#if defined(__linux__)
    #define TG_OS_LINUX 1
#elif defined(__FreeBSD__)
    #define TG_OS_FREEBSD 1
#elif defined(_WIN32)
    #define TG_OS_WINDOWS 1
#else
    #error TinyGate supports Linux, FreeBSD, and Windows.
#endif

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if TG_OS_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
#else
    #include <errno.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <pthread.h>
    #include <signal.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>
    #if TG_OS_LINUX
        #include <sys/epoll.h>
        #include <sys/resource.h>
    #endif
    #if TG_OS_FREEBSD
        #include <sys/event.h>
        #include <sys/resource.h>
    #endif
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "config.h"
#include "http_parser.h"

#if TG_OS_WINDOWS
typedef SOCKET socket_t;
typedef int io_count_t;
#define TG_INVALID_SOCKET INVALID_SOCKET
#define TG_NO_ACCEPTED_SOCKET ((SOCKET)(~(uintptr_t)1))
#else
typedef int socket_t;
typedef ssize_t io_count_t;
#define TG_INVALID_SOCKET (-1)
#define TG_NO_ACCEPTED_SOCKET (-2)
#endif

typedef struct {
    socket_t client_socket;
    bool is_tls;
} Task;

#if TG_OS_WINDOWS
typedef HANDLE thread_handle_t;
typedef CRITICAL_SECTION queue_mutex_t;
typedef CONDITION_VARIABLE queue_cond_t;
#else
typedef pthread_t thread_handle_t;
typedef pthread_mutex_t queue_mutex_t;
typedef pthread_cond_t queue_cond_t;
#endif

typedef struct {
    Task* items;
    int capacity;
    int head;
    int tail;
    int count;
    queue_mutex_t mutex;
    queue_cond_t not_empty;
    queue_cond_t not_full;
} TaskQueue;

typedef struct TlsContextEntry {
    const ProxyRule* rule;
    SSL_CTX* ctx;
    struct TlsContextEntry* next;
} TlsContextEntry;

typedef struct {
    bool enabled;
    int listen_ssl_port;
    SSL_CTX* default_ctx;
    TlsContextEntry* entries;
} TlsState;

typedef struct BackendEntry {
    const ProxyRule* rule;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    struct BackendEntry* next;
} BackendEntry;

typedef struct {
    BackendEntry* entries;
} BackendCache;

typedef struct {
    char* storage;
    char* io_buffer;
    char* host_buffer;
    char* target_buffer;
    char* redirect_buffer;
    size_t io_buffer_size;
    size_t host_buffer_size;
    size_t target_buffer_size;
    size_t redirect_buffer_size;
} WorkerBuffers;

typedef struct {
    const Config* config;
    const TlsState* tls_state;
    const BackendCache* backend_cache;
    TaskQueue* task_queue;
} WorkerContext;

typedef struct {
    socket_t listen_http;
    socket_t listen_https;
#if TG_OS_LINUX
    int epoll_fd;
#elif TG_OS_FREEBSD
    int kqueue_fd;
#elif TG_OS_WINDOWS
    WSAPOLLFD poll_fds[2];
    ULONG poll_count;
#endif
} AcceptLoop;

static const char RESPONSE_BAD_REQUEST[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
static const char RESPONSE_BAD_GATEWAY[] = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

static int clamp_int(int value, int min_value, int max_value);
static int detect_worker_threads(void);
static void apply_fd_limit(int max_connections);
static bool socket_runtime_init(void);
static void socket_runtime_cleanup(void);

static bool queue_init(TaskQueue* queue, int capacity);
static void queue_push(TaskQueue* queue, Task task);
static Task queue_pop(TaskQueue* queue);

static bool worker_buffers_init(WorkerBuffers* buffers, const Config* config);
static void worker_buffers_cleanup(WorkerBuffers* buffers);

static bool accept_loop_init(AcceptLoop* accept_loop, socket_t listen_http, socket_t listen_https);
static bool accept_loop_wait(AcceptLoop* accept_loop, bool* out_http_ready, bool* out_https_ready);
static void accept_loop_cleanup(AcceptLoop* accept_loop);

static void process_connection(Task task, const Config* config, const TlsState* tls_state, const BackendCache* backend_cache, WorkerBuffers* buffers);
static void relay_data(socket_t client_socket, SSL* client_ssl, bool client_is_tls, socket_t server_socket, char* io_buffer, size_t io_buffer_size);
static bool send_redirect_to_https(
    socket_t socket_fd,
    SSL* ssl,
    bool is_tls,
    const char* host,
    const char* target,
    int ssl_port,
    char* response_buffer,
    size_t response_buffer_size
);

static bool send_all(socket_t socket_fd, const char* data, size_t length);
static bool client_send_all(socket_t socket_fd, SSL* ssl, bool is_tls, const char* data, size_t length);
static io_count_t client_recv(socket_t socket_fd, SSL* ssl, bool is_tls, char* buffer, size_t length);

static bool set_nonblocking(socket_t socket_fd);
static bool tune_socket(socket_t socket_fd, bool is_listener);
static int socket_send(socket_t socket_fd, const char* data, size_t length);
static socket_t create_listen_socket(const char* listen_ip, int listen_port, int backlog);
static socket_t accept_client_socket(socket_t listen_socket);
static void close_socket_if_valid(socket_t socket_fd);
static void close_client(socket_t socket_fd, SSL* ssl, bool is_tls);

static bool rule_has_tls_identity(const ProxyRule* rule);
static bool tls_state_init(TlsState* tls_state, const Config* config);
static void tls_state_cleanup(TlsState* tls_state);
static const TlsContextEntry* find_tls_entry(const TlsState* tls_state, const char* host);
static bool tls_state_has_host(const TlsState* tls_state, const char* host);

static bool backend_cache_init(BackendCache* cache, const Config* config);
static void backend_cache_cleanup(BackendCache* cache);
static const BackendEntry* backend_cache_find(const BackendCache* cache, const ProxyRule* rule);

static int net_last_error(void);
static bool net_error_is_would_block(int error_code);
static bool net_error_is_interrupted(int error_code);
static int length_to_int(size_t length);

#if TG_OS_WINDOWS
static DWORD WINAPI worker_thread_start(void* raw_context);
#else
static void* worker_thread_start(void* raw_context);
#endif
static int tls_sni_callback(SSL* ssl, int* alert, void* arg);

static int clamp_int(int value, int min_value, int max_value) {
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

static int detect_worker_threads(void) {
    // Use CPU core count as default worker count.
#if TG_OS_WINDOWS
    DWORD cores = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (cores > 0 && cores <= (DWORD)INT_MAX) {
        return (int)cores;
    }
#else
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0 && cores <= INT_MAX) {
        return (int)cores;
    }
#endif
    return 2;
}

static void apply_fd_limit(int max_connections) {
#if TG_OS_WINDOWS
    (void)max_connections;
#else
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return;
    }

    rlim_t desired = (rlim_t)(max_connections + 128);
    if (desired > limit.rlim_max) {
        desired = limit.rlim_max;
    }
    if (desired <= limit.rlim_cur) {
        return;
    }

    limit.rlim_cur = desired;
    (void)setrlimit(RLIMIT_NOFILE, &limit);
#endif
}

static bool socket_runtime_init(void) {
#if TG_OS_WINDOWS
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
}

static void socket_runtime_cleanup(void) {
#if TG_OS_WINDOWS
    WSACleanup();
#endif
}

static bool queue_init(TaskQueue* queue, int capacity) {
    // Ring queue used by accept thread and worker threads.
    memset(queue, 0, sizeof(*queue));

    queue->items = calloc((size_t)capacity, sizeof(*queue->items));
    if (!queue->items) {
        return false;
    }

    queue->capacity = capacity;

#if TG_OS_WINDOWS
    InitializeCriticalSection(&queue->mutex);
    InitializeConditionVariable(&queue->not_empty);
    InitializeConditionVariable(&queue->not_full);
    return true;
#else
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        free(queue->items);
        return false;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        return false;
    }

    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        return false;
    }

    return true;
#endif
}

static void queue_push(TaskQueue* queue, Task task) {
#if TG_OS_WINDOWS
    EnterCriticalSection(&queue->mutex);
    while (queue->count == queue->capacity) {
        SleepConditionVariableCS(&queue->not_full, &queue->mutex, INFINITE);
    }

    queue->items[queue->tail] = task;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    WakeConditionVariable(&queue->not_empty);
    LeaveCriticalSection(&queue->mutex);
#else
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    queue->items[queue->tail] = task;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
#endif
}

static Task queue_pop(TaskQueue* queue) {
#if TG_OS_WINDOWS
    EnterCriticalSection(&queue->mutex);
    while (queue->count == 0) {
        SleepConditionVariableCS(&queue->not_empty, &queue->mutex, INFINITE);
    }

    Task task = queue->items[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    WakeConditionVariable(&queue->not_full);
    LeaveCriticalSection(&queue->mutex);
    return task;
#else
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    Task task = queue->items[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return task;
#endif
}

static bool worker_buffers_init(WorkerBuffers* buffers, const Config* config) {
    // Allocate one shared block per worker to avoid per-request allocs.
    memset(buffers, 0, sizeof(*buffers));

    buffers->io_buffer_size = (size_t)config->io_buffer_size;
    buffers->host_buffer_size = (size_t)config->host_buffer_size;
    buffers->target_buffer_size = (size_t)config->target_buffer_size;
    buffers->redirect_buffer_size = (size_t)config->redirect_buffer_size;

    size_t total_size = buffers->io_buffer_size +
                        buffers->host_buffer_size +
                        buffers->target_buffer_size +
                        buffers->redirect_buffer_size;

    buffers->storage = malloc(total_size);
    if (!buffers->storage) {
        return false;
    }

    char* cursor = buffers->storage;
    buffers->io_buffer = cursor;
    cursor += buffers->io_buffer_size;
    buffers->host_buffer = cursor;
    cursor += buffers->host_buffer_size;
    buffers->target_buffer = cursor;
    cursor += buffers->target_buffer_size;
    buffers->redirect_buffer = cursor;
    return true;
}

static void worker_buffers_cleanup(WorkerBuffers* buffers) {
    if (!buffers) {
        return;
    }

    free(buffers->storage);
    memset(buffers, 0, sizeof(*buffers));
}

static bool accept_loop_init(AcceptLoop* accept_loop, socket_t listen_http, socket_t listen_https) {
    // Pick the native event API for this OS.
    memset(accept_loop, 0, sizeof(*accept_loop));
    accept_loop->listen_http = listen_http;
    accept_loop->listen_https = listen_https;

#if TG_OS_LINUX
    accept_loop->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (accept_loop->epoll_fd < 0) {
        perror("epoll_create1");
        return false;
    }

    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.u32 = 1;
    if (epoll_ctl(accept_loop->epoll_fd, EPOLL_CTL_ADD, listen_http, &event) != 0) {
        perror("epoll_ctl listen_http");
        close(accept_loop->epoll_fd);
        return false;
    }

    if (listen_https != TG_INVALID_SOCKET) {
        event.events = EPOLLIN;
        event.data.u32 = 2;
        if (epoll_ctl(accept_loop->epoll_fd, EPOLL_CTL_ADD, listen_https, &event) != 0) {
            perror("epoll_ctl listen_https");
            close(accept_loop->epoll_fd);
            return false;
        }
    }

    return true;
#elif TG_OS_FREEBSD
    accept_loop->kqueue_fd = kqueue();
    if (accept_loop->kqueue_fd < 0) {
        perror("kqueue");
        return false;
    }

    struct kevent changes[2];
    int change_count = 0;

    EV_SET(&changes[change_count++], listen_http, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void*)(uintptr_t)1);
    if (listen_https != TG_INVALID_SOCKET) {
        EV_SET(&changes[change_count++], listen_https, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void*)(uintptr_t)2);
    }

    if (kevent(accept_loop->kqueue_fd, changes, change_count, NULL, 0, NULL) < 0) {
        perror("kevent register");
        close(accept_loop->kqueue_fd);
        return false;
    }

    return true;
#else
    accept_loop->poll_count = 0;

    accept_loop->poll_fds[accept_loop->poll_count].fd = listen_http;
    accept_loop->poll_fds[accept_loop->poll_count].events = POLLRDNORM;
    accept_loop->poll_fds[accept_loop->poll_count].revents = 0;
    accept_loop->poll_count++;

    if (listen_https != TG_INVALID_SOCKET) {
        accept_loop->poll_fds[accept_loop->poll_count].fd = listen_https;
        accept_loop->poll_fds[accept_loop->poll_count].events = POLLRDNORM;
        accept_loop->poll_fds[accept_loop->poll_count].revents = 0;
        accept_loop->poll_count++;
    }

    return true;
#endif
}

static bool accept_loop_wait(AcceptLoop* accept_loop, bool* out_http_ready, bool* out_https_ready) {
    // Wait until any listener has new clients.
    *out_http_ready = false;
    *out_https_ready = false;

#if TG_OS_LINUX
    struct epoll_event events[4];
    int ready = epoll_wait(accept_loop->epoll_fd, events, 4, -1);
    if (ready < 0) {
        if (net_error_is_interrupted(net_last_error())) {
            return true;
        }
        perror("epoll_wait");
        return false;
    }

    for (int i = 0; i < ready; i++) {
        if (events[i].data.u32 == 1) {
            *out_http_ready = true;
        } else if (events[i].data.u32 == 2) {
            *out_https_ready = true;
        }
    }

    return true;
#elif TG_OS_FREEBSD
    struct kevent events[4];
    int ready = kevent(accept_loop->kqueue_fd, NULL, 0, events, 4, NULL);
    if (ready < 0) {
        if (net_error_is_interrupted(net_last_error())) {
            return true;
        }
        perror("kevent wait");
        return false;
    }

    for (int i = 0; i < ready; i++) {
        uintptr_t marker = (uintptr_t)events[i].udata;
        if (marker == 1) {
            *out_http_ready = true;
        } else if (marker == 2) {
            *out_https_ready = true;
        }
    }

    return true;
#else
    int ready = WSAPoll(accept_loop->poll_fds, accept_loop->poll_count, -1);
    if (ready == SOCKET_ERROR) {
        int error_code = net_last_error();
        if (net_error_is_interrupted(error_code)) {
            return true;
        }
        fprintf(stderr, "WSAPoll failed: %d\n", error_code);
        return false;
    }

    for (ULONG i = 0; i < accept_loop->poll_count; i++) {
        short revents = accept_loop->poll_fds[i].revents;
        if ((revents & POLLRDNORM) == 0 && (revents & POLLIN) == 0) {
            continue;
        }

        if (accept_loop->poll_fds[i].fd == accept_loop->listen_http) {
            *out_http_ready = true;
        }
        if (accept_loop->poll_fds[i].fd == accept_loop->listen_https) {
            *out_https_ready = true;
        }
    }

    return true;
#endif
}

static void accept_loop_cleanup(AcceptLoop* accept_loop) {
#if TG_OS_LINUX
    close(accept_loop->epoll_fd);
#elif TG_OS_FREEBSD
    close(accept_loop->kqueue_fd);
#else
    (void)accept_loop;
#endif
}

#if TG_OS_WINDOWS
static DWORD WINAPI worker_thread_start(void* raw_context)
#else
static void* worker_thread_start(void* raw_context)
#endif
{
    // Each worker keeps its own buffers and handles queued sockets.
    const WorkerContext* context = (const WorkerContext*)raw_context;

    WorkerBuffers buffers;
    if (!worker_buffers_init(&buffers, context->config)) {
#if TG_OS_WINDOWS
        return 1;
#else
        return NULL;
#endif
    }

    while (1) {
        Task task = queue_pop(context->task_queue);
        process_connection(task, context->config, context->tls_state, context->backend_cache, &buffers);
    }

    worker_buffers_cleanup(&buffers);
#if TG_OS_WINDOWS
    return 0;
#else
    return NULL;
#endif
}

static int tls_sni_callback(SSL* ssl, int* alert, void* arg) {
    (void)alert;

    const TlsState* tls_state = (const TlsState*)arg;
    const char* server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!tls_state || !server_name) {
        return SSL_TLSEXT_ERR_OK;
    }

    const TlsContextEntry* entry = find_tls_entry(tls_state, server_name);
    if (entry && entry->ctx) {
        SSL_set_SSL_CTX(ssl, entry->ctx);
    }

    return SSL_TLSEXT_ERR_OK;
}

int main(int argc, char* argv[]) {
#if !TG_OS_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif

    // Startup flow: load config, init state, then start listeners.
    if (!socket_runtime_init()) {
        fprintf(stderr, "Failed to initialize socket runtime.\n");
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_config.ini>\n", argv[0]);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    Config* config = load_config(argv[1]);
    if (!config) {
        fprintf(stderr, "Failed to load configuration.\n");
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    config->max_events = clamp_int(config->max_events, 2, 32768);
    config->max_connections = clamp_int(config->max_connections, 256, 200000);
    config->io_buffer_size = clamp_int(config->io_buffer_size, 1024, 1048576);
    config->host_buffer_size = clamp_int(config->host_buffer_size, 64, 4096);
    config->target_buffer_size = clamp_int(config->target_buffer_size, 128, 32768);
    config->redirect_buffer_size = clamp_int(config->redirect_buffer_size, 512, 65536);

    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (rule->force_ssl && config->listen_ssl_port <= 0) {
            fprintf(stderr, "force_ssl requires listen_ssl_port > 0 for domain %s\n", rule->entry_domain);
            free_config(config);
            socket_runtime_cleanup();
            return EXIT_FAILURE;
        }
        if (rule->force_ssl && !rule_has_tls_identity(rule)) {
            fprintf(stderr, "force_ssl requires tls_cert_file and tls_key_file for domain %s\n", rule->entry_domain);
            free_config(config);
            socket_runtime_cleanup();
            return EXIT_FAILURE;
        }
    }

    int queue_capacity = clamp_int(config->max_connections / 2, 128, 16384);
    apply_fd_limit(config->max_connections);

    TlsState tls_state;
    if (!tls_state_init(&tls_state, config)) {
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    BackendCache backend_cache;
    if (!backend_cache_init(&backend_cache, config)) {
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    socket_t listen_http = create_listen_socket(config->listen_ip, config->listen_port, config->max_connections);
    if (listen_http == TG_INVALID_SOCKET) {
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    socket_t listen_https = TG_INVALID_SOCKET;
    if (tls_state.enabled) {
        if (config->listen_ssl_port == config->listen_port) {
            fprintf(stderr, "listen_port and listen_ssl_port must be different\n");
            close_socket_if_valid(listen_http);
            backend_cache_cleanup(&backend_cache);
            tls_state_cleanup(&tls_state);
            free_config(config);
            socket_runtime_cleanup();
            return EXIT_FAILURE;
        }

        listen_https = create_listen_socket(config->listen_ip, config->listen_ssl_port, config->max_connections);
        if (listen_https == TG_INVALID_SOCKET) {
            close_socket_if_valid(listen_http);
            backend_cache_cleanup(&backend_cache);
            tls_state_cleanup(&tls_state);
            free_config(config);
            socket_runtime_cleanup();
            return EXIT_FAILURE;
        }
    }

    TaskQueue task_queue;
    if (!queue_init(&task_queue, queue_capacity)) {
        fprintf(stderr, "Failed to initialize task queue.\n");
        close_socket_if_valid(listen_http);
        close_socket_if_valid(listen_https);
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    WorkerContext worker_context = {
        .config = config,
        .tls_state = &tls_state,
        .backend_cache = &backend_cache,
        .task_queue = &task_queue,
    };

    int worker_threads = clamp_int(detect_worker_threads(), 1, 256);
    thread_handle_t* workers = calloc((size_t)worker_threads, sizeof(*workers));
    if (!workers) {
        fprintf(stderr, "Failed to allocate worker list.\n");
        close_socket_if_valid(listen_http);
        close_socket_if_valid(listen_https);
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    int started_threads = 0;
    for (int i = 0; i < worker_threads; i++) {
#if TG_OS_WINDOWS
        HANDLE handle = CreateThread(NULL, 0, worker_thread_start, &worker_context, 0, NULL);
        if (!handle) {
            fprintf(stderr, "Failed to create worker thread.\n");
            break;
        }
        workers[i] = handle;
#else
        if (pthread_create(&workers[i], NULL, worker_thread_start, &worker_context) != 0) {
            fprintf(stderr, "Failed to create worker thread.\n");
            break;
        }
#endif
        started_threads++;
    }

    if (started_threads != worker_threads) {
#if TG_OS_WINDOWS
        for (int i = 0; i < started_threads; i++) {
            CloseHandle(workers[i]);
        }
#endif
        free(workers);
        close_socket_if_valid(listen_http);
        close_socket_if_valid(listen_https);
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    AcceptLoop accept_loop;
    if (!accept_loop_init(&accept_loop, listen_http, listen_https)) {
#if TG_OS_WINDOWS
        for (int i = 0; i < started_threads; i++) {
            CloseHandle(workers[i]);
        }
#endif
        free(workers);
        close_socket_if_valid(listen_http);
        close_socket_if_valid(listen_https);
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        socket_runtime_cleanup();
        return EXIT_FAILURE;
    }

    while (1) {
        // Main thread only accepts sockets and pushes tasks to queue.
        bool http_ready = false;
        bool https_ready = false;
        if (!accept_loop_wait(&accept_loop, &http_ready, &https_ready)) {
            break;
        }

        if (http_ready) {
            while (1) {
                socket_t client_socket = accept_client_socket(listen_http);
                if (client_socket == TG_NO_ACCEPTED_SOCKET) {
                    break;
                }
                if (client_socket == TG_INVALID_SOCKET) {
                    break;
                }

                Task task = {
                    .client_socket = client_socket,
                    .is_tls = false,
                };
                queue_push(&task_queue, task);
            }
        }

        if (https_ready && listen_https != TG_INVALID_SOCKET) {
            while (1) {
                socket_t client_socket = accept_client_socket(listen_https);
                if (client_socket == TG_NO_ACCEPTED_SOCKET) {
                    break;
                }
                if (client_socket == TG_INVALID_SOCKET) {
                    break;
                }

                Task task = {
                    .client_socket = client_socket,
                    .is_tls = true,
                };
                queue_push(&task_queue, task);
            }
        }
    }

    accept_loop_cleanup(&accept_loop);
    close_socket_if_valid(listen_http);
    close_socket_if_valid(listen_https);
    backend_cache_cleanup(&backend_cache);
    tls_state_cleanup(&tls_state);
    free_config(config);

#if TG_OS_WINDOWS
    for (int i = 0; i < started_threads; i++) {
        CloseHandle(workers[i]);
    }
#endif
    free(workers);
    socket_runtime_cleanup();

    return EXIT_FAILURE;
}

static void process_connection(Task task, const Config* config, const TlsState* tls_state, const BackendCache* backend_cache, WorkerBuffers* buffers) {
    // Handle one client from first read to proxy relay.
    socket_t client_socket = task.client_socket;
    SSL* client_ssl = NULL;

    if (task.is_tls) {
        if (!tls_state || !tls_state->enabled || !tls_state->default_ctx) {
            close_socket_if_valid(client_socket);
            return;
        }

        client_ssl = SSL_new(tls_state->default_ctx);
        if (!client_ssl) {
            close_socket_if_valid(client_socket);
            return;
        }

        if (SSL_set_fd(client_ssl, (int)client_socket) != 1 || SSL_accept(client_ssl) <= 0) {
            SSL_free(client_ssl);
            close_socket_if_valid(client_socket);
            return;
        }
    }

    if (buffers->io_buffer_size < 2) {
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    io_count_t bytes_read = client_recv(client_socket, client_ssl, task.is_tls, buffers->io_buffer, buffers->io_buffer_size - 1);
    if (bytes_read <= 0) {
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }
    buffers->io_buffer[(size_t)bytes_read] = '\0';

    if (!parse_host_header(buffers->io_buffer, buffers->host_buffer, buffers->host_buffer_size)) {
        (void)client_send_all(client_socket, client_ssl, task.is_tls, RESPONSE_BAD_REQUEST, sizeof(RESPONSE_BAD_REQUEST) - 1);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    const ProxyRule* rule = find_rule(config, buffers->host_buffer);
    if (!rule) {
        (void)client_send_all(client_socket, client_ssl, task.is_tls, RESPONSE_BAD_GATEWAY, sizeof(RESPONSE_BAD_GATEWAY) - 1);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    if (!task.is_tls && rule->force_ssl) {
        // Redirect plain HTTP to HTTPS when rule requests it.
        if (!parse_request_target(buffers->io_buffer, buffers->target_buffer, buffers->target_buffer_size)) {
            if (buffers->target_buffer_size >= 2) {
                memcpy(buffers->target_buffer, "/", 2);
            }
        }

        bool can_redirect = tls_state && tls_state->enabled && tls_state_has_host(tls_state, buffers->host_buffer);
        if (can_redirect) {
            (void)send_redirect_to_https(
                client_socket,
                client_ssl,
                false,
                buffers->host_buffer,
                buffers->target_buffer,
                tls_state->listen_ssl_port,
                buffers->redirect_buffer,
                buffers->redirect_buffer_size
            );
        } else {
            (void)client_send_all(client_socket, client_ssl, false, RESPONSE_BAD_GATEWAY, sizeof(RESPONSE_BAD_GATEWAY) - 1);
        }

        close_client(client_socket, client_ssl, false);
        return;
    }

    const BackendEntry* backend = backend_cache_find(backend_cache, rule);
    if (!backend) {
        (void)client_send_all(client_socket, client_ssl, task.is_tls, RESPONSE_BAD_GATEWAY, sizeof(RESPONSE_BAD_GATEWAY) - 1);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    socket_t server_socket = socket(backend->ai_family, backend->ai_socktype, backend->ai_protocol);
    if (server_socket == TG_INVALID_SOCKET) {
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    (void)tune_socket(server_socket, false);

    if (connect(server_socket, (const struct sockaddr*)&backend->addr, backend->addr_len) != 0) {
        close_socket_if_valid(server_socket);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    if (!send_all(server_socket, buffers->io_buffer, (size_t)bytes_read)) {
        close_socket_if_valid(server_socket);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    relay_data(client_socket, client_ssl, task.is_tls, server_socket, buffers->io_buffer, buffers->io_buffer_size);

    close_socket_if_valid(server_socket);
    close_client(client_socket, client_ssl, task.is_tls);
}

static void relay_data(socket_t client_socket, SSL* client_ssl, bool client_is_tls, socket_t server_socket, char* io_buffer, size_t io_buffer_size) {
    // Bidirectional relay loop until timeout or close.
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(server_socket, &read_fds);

        struct timeval timeout = {
            .tv_sec = 60,
            .tv_usec = 0,
        };

#if TG_OS_WINDOWS
        int activity = select(0, &read_fds, NULL, NULL, &timeout);
#else
        socket_t max_fd = (client_socket > server_socket) ? client_socket : server_socket;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
#endif
        if (activity <= 0) {
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            io_count_t count = client_recv(client_socket, client_ssl, client_is_tls, io_buffer, io_buffer_size);
            if (count <= 0) {
                break;
            }
            if (!send_all(server_socket, io_buffer, (size_t)count)) {
                break;
            }
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            io_count_t count = recv(server_socket, io_buffer, length_to_int(io_buffer_size), 0);
            if (count <= 0) {
                break;
            }
            if (!client_send_all(client_socket, client_ssl, client_is_tls, io_buffer, (size_t)count)) {
                break;
            }
        }
    }
}

static bool send_redirect_to_https(
    socket_t socket_fd,
    SSL* ssl,
    bool is_tls,
    const char* host,
    const char* target,
    int ssl_port,
    char* response_buffer,
    size_t response_buffer_size
) {
    if (!host || !target || !response_buffer || response_buffer_size == 0) {
        return false;
    }

    const char* prefix = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://";
    const char* suffix = "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

    size_t prefix_len = strlen(prefix);
    size_t host_len = strlen(host);
    size_t target_len = strlen(target);
    size_t suffix_len = strlen(suffix);

    char port_text[16] = {0};
    size_t port_len = 0;

    if (ssl_port != 443) {
        int written = snprintf(port_text, sizeof(port_text), ":%d", ssl_port);
        if (written <= 0 || (size_t)written >= sizeof(port_text)) {
            return false;
        }
        port_len = (size_t)written;
    }

    size_t total_len = prefix_len + host_len + port_len + target_len + suffix_len;
    if (total_len >= response_buffer_size) {
        return false;
    }

    char* out = response_buffer;
    memcpy(out, prefix, prefix_len);
    out += prefix_len;

    memmove(out, host, host_len);
    out += host_len;

    if (port_len > 0) {
        memcpy(out, port_text, port_len);
        out += port_len;
    }

    memmove(out, target, target_len);
    out += target_len;

    memcpy(out, suffix, suffix_len);
    out += suffix_len;

    return client_send_all(socket_fd, ssl, is_tls, response_buffer, (size_t)(out - response_buffer));
}

static bool send_all(socket_t socket_fd, const char* data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        int sent = socket_send(socket_fd, data + sent_total, length - sent_total);
        if (sent < 0) {
            if (net_error_is_interrupted(net_last_error())) {
                continue;
            }
            return false;
        }
        if (sent == 0) {
            return false;
        }
        sent_total += (size_t)sent;
    }
    return true;
}

static bool client_send_all(socket_t socket_fd, SSL* ssl, bool is_tls, const char* data, size_t length) {
    if (is_tls) {
        size_t sent_total = 0;
        while (sent_total < length) {
            int sent = SSL_write(ssl, data + sent_total, length_to_int(length - sent_total));
            if (sent <= 0) {
                return false;
            }
            sent_total += (size_t)sent;
        }
        return true;
    }

    return send_all(socket_fd, data, length);
}

static io_count_t client_recv(socket_t socket_fd, SSL* ssl, bool is_tls, char* buffer, size_t length) {
    if (is_tls) {
        return SSL_read(ssl, buffer, length_to_int(length));
    }

    return recv(socket_fd, buffer, length_to_int(length), 0);
}

static bool set_nonblocking(socket_t socket_fd) {
#if TG_OS_WINDOWS
    u_long mode = 1;
    return ioctlsocket(socket_fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return false;
    }

    return true;
#endif
}

static bool tune_socket(socket_t socket_fd, bool is_listener) {
#if TG_OS_WINDOWS
    BOOL enabled = TRUE;

    if (is_listener) {
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&enabled, sizeof(enabled)) != 0) {
            return false;
        }
    }

    (void)setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&enabled, sizeof(enabled));
    return true;
#else
    int enabled = 1;

    if (is_listener) {
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
            return false;
        }
#ifdef SO_REUSEPORT
        (void)setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));
#endif
#ifdef TCP_FASTOPEN
        int fastopen_queue = 256;
        (void)setsockopt(socket_fd, IPPROTO_TCP, TCP_FASTOPEN, &fastopen_queue, sizeof(fastopen_queue));
#endif
    }

#ifdef TCP_NODELAY
    (void)setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
#endif

    return true;
#endif
}

static int socket_send(socket_t socket_fd, const char* data, size_t length) {
#if TG_OS_WINDOWS
    return send(socket_fd, data, length_to_int(length), 0);
#else
#ifdef MSG_NOSIGNAL
    return (int)send(socket_fd, data, length, MSG_NOSIGNAL);
#else
    return (int)send(socket_fd, data, length, 0);
#endif
#endif
}

static socket_t create_listen_socket(const char* listen_ip, int listen_port, int backlog) {
    // Resolve and bind first address that works.
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", listen_port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = NULL;
    const char* bind_host = (listen_ip && listen_ip[0] != '\0') ? listen_ip : NULL;
    int gai_result = getaddrinfo(bind_host, port_text, &hints, &result);
    if (gai_result != 0 || !result) {
#if TG_OS_WINDOWS
        fprintf(stderr, "getaddrinfo failed for listen socket: %d\n", gai_result);
#else
        fprintf(stderr, "getaddrinfo failed for listen socket: %s\n", gai_strerror(gai_result));
#endif
        return TG_INVALID_SOCKET;
    }

    int actual_backlog = clamp_int(backlog, 64, SOMAXCONN);
    socket_t listen_fd = TG_INVALID_SOCKET;

    for (struct addrinfo* current = result; current != NULL; current = current->ai_next) {
        listen_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (listen_fd == TG_INVALID_SOCKET) {
            continue;
        }

        if (!tune_socket(listen_fd, true)) {
            close_socket_if_valid(listen_fd);
            listen_fd = TG_INVALID_SOCKET;
            continue;
        }

        if (!set_nonblocking(listen_fd)) {
            close_socket_if_valid(listen_fd);
            listen_fd = TG_INVALID_SOCKET;
            continue;
        }

        if (bind(listen_fd, current->ai_addr, (socklen_t)current->ai_addrlen) != 0) {
            close_socket_if_valid(listen_fd);
            listen_fd = TG_INVALID_SOCKET;
            continue;
        }

        if (listen(listen_fd, actual_backlog) != 0) {
            close_socket_if_valid(listen_fd);
            listen_fd = TG_INVALID_SOCKET;
            continue;
        }

        break;
    }

    freeaddrinfo(result);

    if (listen_fd == TG_INVALID_SOCKET) {
        fprintf(stderr, "Failed to bind listen socket for %s:%d\n", bind_host ? bind_host : "0.0.0.0", listen_port);
    }

    return listen_fd;
}

static socket_t accept_client_socket(socket_t listen_socket) {
    socket_t client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket == TG_INVALID_SOCKET) {
        int error_code = net_last_error();
        if (net_error_is_would_block(error_code) || net_error_is_interrupted(error_code)) {
            return TG_NO_ACCEPTED_SOCKET;
        }
        return TG_INVALID_SOCKET;
    }

    (void)tune_socket(client_socket, false);
    return client_socket;
}

static void close_socket_if_valid(socket_t socket_fd) {
    if (socket_fd == TG_INVALID_SOCKET) {
        return;
    }

#if TG_OS_WINDOWS
    closesocket(socket_fd);
#else
    close(socket_fd);
#endif
}

static void close_client(socket_t socket_fd, SSL* ssl, bool is_tls) {
    if (is_tls && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close_socket_if_valid(socket_fd);
}

static bool rule_has_tls_identity(const ProxyRule* rule) {
    return rule && rule->tls_cert_file && rule->tls_key_file && rule->tls_cert_file[0] != '\0' && rule->tls_key_file[0] != '\0';
}

static bool tls_state_init(TlsState* tls_state, const Config* config) {
    // Build SSL contexts once at startup.
    memset(tls_state, 0, sizeof(*tls_state));

    if (config->listen_ssl_port <= 0) {
        tls_state->enabled = false;
        return true;
    }

    if (OPENSSL_init_ssl(0, NULL) != 1) {
        fprintf(stderr, "Failed to initialize OpenSSL.\n");
        return false;
    }

    tls_state->enabled = true;
    tls_state->listen_ssl_port = config->listen_ssl_port;

    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (!rule_has_tls_identity(rule)) {
            continue;
        }

        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            fprintf(stderr, "Failed to create SSL context for domain %s\n", rule->entry_domain);
            tls_state_cleanup(tls_state);
            return false;
        }

        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

        if (SSL_CTX_use_certificate_file(ctx, rule->tls_cert_file, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load certificate for domain %s: %s\n", rule->entry_domain, rule->tls_cert_file);
            SSL_CTX_free(ctx);
            tls_state_cleanup(tls_state);
            return false;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, rule->tls_key_file, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "Failed to load private key for domain %s: %s\n", rule->entry_domain, rule->tls_key_file);
            SSL_CTX_free(ctx);
            tls_state_cleanup(tls_state);
            return false;
        }

        if (SSL_CTX_check_private_key(ctx) != 1) {
            fprintf(stderr, "Certificate and key mismatch for domain %s\n", rule->entry_domain);
            SSL_CTX_free(ctx);
            tls_state_cleanup(tls_state);
            return false;
        }

        TlsContextEntry* entry = calloc(1, sizeof(*entry));
        if (!entry) {
            SSL_CTX_free(ctx);
            tls_state_cleanup(tls_state);
            return false;
        }

        entry->rule = rule;
        entry->ctx = ctx;
        entry->next = tls_state->entries;
        tls_state->entries = entry;

        if (!tls_state->default_ctx) {
            tls_state->default_ctx = ctx;
        }
    }

    if (!tls_state->default_ctx) {
        fprintf(stderr, "SSL listener is enabled but no domain has tls_cert_file and tls_key_file configured.\n");
        tls_state_cleanup(tls_state);
        return false;
    }

    for (TlsContextEntry* entry = tls_state->entries; entry != NULL; entry = entry->next) {
        SSL_CTX_set_tlsext_servername_callback(entry->ctx, tls_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(entry->ctx, tls_state);
    }

    return true;
}

static void tls_state_cleanup(TlsState* tls_state) {
    TlsContextEntry* current = tls_state->entries;
    while (current) {
        TlsContextEntry* next = current->next;
        if (current->ctx) {
            SSL_CTX_free(current->ctx);
        }
        free(current);
        current = next;
    }

    tls_state->entries = NULL;
    tls_state->default_ctx = NULL;
    tls_state->enabled = false;
    tls_state->listen_ssl_port = 0;
}

static bool equal_ignore_case(const char* left, const char* right) {
    while (*left && *right) {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return false;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
}

static const TlsContextEntry* find_tls_entry(const TlsState* tls_state, const char* host) {
    if (!tls_state || !host) {
        return NULL;
    }

    for (const TlsContextEntry* entry = tls_state->entries; entry != NULL; entry = entry->next) {
        if (!entry->rule || !entry->rule->entry_domain) {
            continue;
        }
        if (equal_ignore_case(entry->rule->entry_domain, host)) {
            return entry;
        }
    }

    return NULL;
}

static bool tls_state_has_host(const TlsState* tls_state, const char* host) {
    return find_tls_entry(tls_state, host) != NULL;
}

static bool backend_cache_init(BackendCache* cache, const Config* config) {
    // Resolve backend endpoints once to keep request path fast.
    cache->entries = NULL;

    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (!rule->backend_host || rule->backend_host[0] == '\0' || rule->backend_port <= 0 || rule->backend_port > 65535) {
            fprintf(stderr, "Invalid or missing endpoint for domain %s\n", rule->entry_domain);
            backend_cache_cleanup(cache);
            return false;
        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char port_text[16];
        snprintf(port_text, sizeof(port_text), "%d", rule->backend_port);

        struct addrinfo* result = NULL;
        int gai_result = getaddrinfo(rule->backend_host, port_text, &hints, &result);
        if (gai_result != 0 || !result) {
            fprintf(stderr, "Failed to resolve backend %s:%d for domain %s\n", rule->backend_host, rule->backend_port, rule->entry_domain);
            backend_cache_cleanup(cache);
            return false;
        }

        BackendEntry* entry = calloc(1, sizeof(*entry));
        if (!entry) {
            freeaddrinfo(result);
            backend_cache_cleanup(cache);
            return false;
        }

        if ((size_t)result->ai_addrlen > sizeof(entry->addr)) {
            free(entry);
            freeaddrinfo(result);
            backend_cache_cleanup(cache);
            return false;
        }

        entry->rule = rule;
        entry->addr_len = (socklen_t)result->ai_addrlen;
        entry->ai_family = result->ai_family;
        entry->ai_socktype = result->ai_socktype;
        entry->ai_protocol = result->ai_protocol;
        memcpy(&entry->addr, result->ai_addr, (size_t)result->ai_addrlen);
        entry->next = cache->entries;
        cache->entries = entry;

        freeaddrinfo(result);
    }

    if (config->rules && !cache->entries) {
        fprintf(stderr, "No backend endpoints were cached at startup.\n");
        return false;
    }

    return true;
}

static void backend_cache_cleanup(BackendCache* cache) {
    BackendEntry* current = cache->entries;
    while (current) {
        BackendEntry* next = current->next;
        free(current);
        current = next;
    }
    cache->entries = NULL;
}

static const BackendEntry* backend_cache_find(const BackendCache* cache, const ProxyRule* rule) {
    if (!cache || !rule) {
        return NULL;
    }

    for (const BackendEntry* entry = cache->entries; entry != NULL; entry = entry->next) {
        if (entry->rule == rule) {
            return entry;
        }
    }

    return NULL;
}

static int net_last_error(void) {
#if TG_OS_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif
}

static bool net_error_is_would_block(int error_code) {
#if TG_OS_WINDOWS
    return error_code == WSAEWOULDBLOCK;
#else
    return error_code == EAGAIN || error_code == EWOULDBLOCK;
#endif
}

static bool net_error_is_interrupted(int error_code) {
#if TG_OS_WINDOWS
    return error_code == WSAEINTR;
#else
    return error_code == EINTR;
#endif
}

static int length_to_int(size_t length) {
    if (length > (size_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)length;
}

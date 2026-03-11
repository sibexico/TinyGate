#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>


//HERE BE DRAGONS!!! In name of all the gods, never touch this crossplatform defines...
#if !defined(TG_FORCE_PTHREAD)
    #define TG_FORCE_PTHREAD 0
#endif

#if defined(__has_include) 
    #if __has_include(<threads.h>) && !defined(__STDC_NO_THREADS__) && !TG_FORCE_PTHREAD && !(defined(__FreeBSD__) && defined(__GNUC__) && !defined(__clang__))
        #include <threads.h>
        #define TG_HAS_C23_THREADS 1
    #else
        #include <pthread.h>
        #define TG_HAS_C23_THREADS 0
    #endif
#else
    #include <pthread.h>
    #define TG_HAS_C23_THREADS 0
#endif

#if defined(__has_include)
    #if __has_include(<openssl/ssl.h>) && __has_include(<openssl/err.h>)
        #include <openssl/ssl.h>
        #include <openssl/err.h>
        #define TG_HAS_OPENSSL 1
    #else
        #define TG_HAS_OPENSSL 0
    #endif
#else
    #define TG_HAS_OPENSSL 0
#endif

#include "config.h"

#if !TG_HAS_OPENSSL
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
#endif

#if !TG_HAS_C23_THREADS
typedef pthread_t thrd_t;
typedef pthread_mutex_t mtx_t;
typedef pthread_cond_t cnd_t;

typedef struct {
    int (*func)(void*);
    void* arg;
} ThreadStart;

enum { thrd_success = 0 };

static void* pthread_start(void* raw_arg) {
    ThreadStart* start = (ThreadStart*)raw_arg;
    int result = start->func(start->arg);
    free(start);
    return (void*)(intptr_t)result;
}

static int thrd_create(thrd_t* thread, int (*func)(void*), void* arg) {
    ThreadStart* start = malloc(sizeof(*start));
    if (!start) {
        return -1;
    }
    start->func = func;
    start->arg = arg;
    int status = pthread_create(thread, NULL, pthread_start, start);
    if (status != 0) {
        free(start);
    }
    return status;
}

static int thrd_join(thrd_t thread, int* result) {
    void* join_result = NULL;
    int status = pthread_join(thread, &join_result);
    if (status == 0 && result) {
        *result = (int)(intptr_t)join_result;
    }
    return status;
}

static int mtx_init(mtx_t* mutex, int type) {
    (void)type;
    return pthread_mutex_init(mutex, NULL);
}

static int mtx_lock(mtx_t* mutex) {
    return pthread_mutex_lock(mutex);
}

static int mtx_unlock(mtx_t* mutex) {
    return pthread_mutex_unlock(mutex);
}

static int cnd_init(cnd_t* cond) {
    return pthread_cond_init(cond, NULL);
}

static int cnd_wait(cnd_t* cond, mtx_t* mutex) {
    return pthread_cond_wait(cond, mutex);
}

static int cnd_signal(cnd_t* cond) {
    return pthread_cond_signal(cond);
}

enum { mtx_plain = 0 };
#endif

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    typedef int io_count_t;
    #define close_socket(s) closesocket(s)
#else
    #include <unistd.h>
    #include <sys/select.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    typedef int socket_t;
    typedef ssize_t io_count_t;
    #define close_socket(s) close(s)
    #define INVALID_SOCKET -1
#endif

#define BUFFER_SIZE 16384
#define TASK_QUEUE_SIZE 256
#define HOST_BUFFER_SIZE 256
#define TARGET_BUFFER_SIZE 2048
#define REDIRECT_BUFFER_SIZE 3072

static const char RESPONSE_BAD_REQUEST[] = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
static const char RESPONSE_BAD_GATEWAY[] = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

typedef struct {
    socket_t client_socket;
    bool is_tls;
} Task;

typedef struct {
    Task queue[TASK_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    mtx_t mutex;
    cnd_t not_empty;
    cnd_t not_full;
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
    const Config* config;
    const TlsState* tls_state;
    const BackendCache* backend_cache;
} WorkerContext;

void queue_init(TaskQueue* q);
void queue_push(TaskQueue* q, Task task);
Task queue_pop(TaskQueue* q);
int worker_thread(void* arg);
void process_connection(Task task, const Config* config, const TlsState* tls_state, const BackendCache* backend_cache);
void relay_data(socket_t client_socket, SSL* client_ssl, bool client_is_tls, socket_t server_socket);
bool try_parse_host(const char* buffer, char* out_host, size_t out_size);
bool try_parse_request_target(const char* buffer, char* out_target, size_t out_size);
bool send_all(socket_t socket, const char* data, size_t length);
bool client_send_all(socket_t socket, SSL* ssl, bool is_tls, const char* data, size_t length);
io_count_t client_recv(socket_t socket, SSL* ssl, bool is_tls, char* buffer, size_t length);
socket_t create_listen_socket(const char* listen_ip, int listen_port);
void close_client(socket_t socket, SSL* ssl, bool is_tls);
bool send_redirect_to_https(socket_t socket, SSL* ssl, bool is_tls, const char* host, const char* target, int ssl_port);
bool rule_has_tls_identity(const ProxyRule* rule);
bool tls_state_init(TlsState* tls_state, const Config* config);
void tls_state_cleanup(TlsState* tls_state);
const TlsContextEntry* find_tls_entry(const TlsState* tls_state, const char* host);
bool tls_state_has_host(const TlsState* tls_state, const char* host);
bool backend_cache_init(BackendCache* cache, const Config* config);
void backend_cache_cleanup(BackendCache* cache);
const BackendEntry* backend_cache_find(const BackendCache* cache, const ProxyRule* rule);
bool tune_socket(socket_t socket, bool is_listener);
socket_t accept_client_socket(socket_t listen_socket);
int socket_send(socket_t socket, const char* data, size_t length);

TaskQueue task_queue;

#if TG_HAS_OPENSSL
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
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return EXIT_FAILURE;
    }
#endif

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_config.ini>\n", argv[0]);
        return EXIT_FAILURE;
    }

    Config* config = load_config(argv[1]);
    if (!config) {
        fprintf(stderr, "Failed to load configuration.\n");
        return EXIT_FAILURE;
    }

    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (rule->force_ssl && config->listen_ssl_port <= 0) {
            fprintf(stderr, "force_ssl requires listen_ssl_port > 0 for domain %s\n", rule->entry_domain);
            free_config(config);
            return EXIT_FAILURE;
        }
        if (rule->force_ssl && !rule_has_tls_identity(rule)) {
            fprintf(stderr, "force_ssl requires tls_cert_file and tls_key_file for domain %s\n", rule->entry_domain);
            free_config(config);
            return EXIT_FAILURE;
        }
    }

    TlsState tls_state;
    if (!tls_state_init(&tls_state, config)) {
        free_config(config);
        return EXIT_FAILURE;
    }

    BackendCache backend_cache;
    if (!backend_cache_init(&backend_cache, config)) {
        tls_state_cleanup(&tls_state);
        free_config(config);
        return EXIT_FAILURE;
    }

    socket_t listen_fd = create_listen_socket(config->listen_ip, config->listen_port);
    if (listen_fd == INVALID_SOCKET) {
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        return EXIT_FAILURE;
    }

    socket_t listen_ssl_fd = INVALID_SOCKET;
    if (tls_state.enabled) {
        if (config->listen_ssl_port == config->listen_port) {
            fprintf(stderr, "listen_port and listen_ssl_port must be different\n");
            close_socket(listen_fd);
            backend_cache_cleanup(&backend_cache);
            tls_state_cleanup(&tls_state);
            free_config(config);
            return EXIT_FAILURE;
        }

        listen_ssl_fd = create_listen_socket(config->listen_ip, config->listen_ssl_port);
        if (listen_ssl_fd == INVALID_SOCKET) {
            close_socket(listen_fd);
            backend_cache_cleanup(&backend_cache);
            tls_state_cleanup(&tls_state);
            free_config(config);
            return EXIT_FAILURE;
        }
    }

    queue_init(&task_queue);
    WorkerContext worker_context = {
        .config = config,
        .tls_state = &tls_state,
        .backend_cache = &backend_cache,
    };

    thrd_t* threads = malloc(sizeof(*threads) * (size_t)config->worker_threads);
    if (!threads) {
        fprintf(stderr, "Failed to allocate worker thread list.\n");
        close_socket(listen_fd);
        if (listen_ssl_fd != INVALID_SOCKET) {
            close_socket(listen_ssl_fd);
        }
        backend_cache_cleanup(&backend_cache);
        tls_state_cleanup(&tls_state);
        free_config(config);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < config->worker_threads; i++) {
        if (thrd_create(&threads[i], worker_thread, &worker_context) != thrd_success) {
            fprintf(stderr, "Failed to create worker thread.\n");
            free(threads);
            close_socket(listen_fd);
            if (listen_ssl_fd != INVALID_SOCKET) {
                close_socket(listen_ssl_fd);
            }
            backend_cache_cleanup(&backend_cache);
            tls_state_cleanup(&tls_state);
            free_config(config);
            return EXIT_FAILURE;
        }
    }

    while (1) {
        if (!tls_state.enabled) {
            socket_t client_socket = accept_client_socket(listen_fd);
            if (client_socket == INVALID_SOCKET) {
                perror("accept() failed");
                continue;
            }

            Task task = {
                .client_socket = client_socket,
                .is_tls = false,
            };
            queue_push(&task_queue, task);
            continue;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_fd, &read_fds);
        FD_SET(listen_ssl_fd, &read_fds);

        socket_t max_fd = (listen_fd > listen_ssl_fd) ? listen_fd : listen_ssl_fd;
        int activity = select((int)(max_fd + 1), &read_fds, NULL, NULL, NULL);
        if (activity < 0) {
            perror("select() failed");
            continue;
        }

        if (FD_ISSET(listen_fd, &read_fds)) {
            socket_t client_socket = accept_client_socket(listen_fd);
            if (client_socket != INVALID_SOCKET) {
                Task task = {
                    .client_socket = client_socket,
                    .is_tls = false,
                };
                queue_push(&task_queue, task);
            }
        }

        if (FD_ISSET(listen_ssl_fd, &read_fds)) {
            socket_t client_socket = accept_client_socket(listen_ssl_fd);
            if (client_socket != INVALID_SOCKET) {
                Task task = {
                    .client_socket = client_socket,
                    .is_tls = true,
                };
                queue_push(&task_queue, task);
            }
        }
    }

    for (int i = 0; i < config->worker_threads; i++) {
        thrd_join(threads[i], NULL);
    }

    free(threads);
    close_socket(listen_fd);
    if (listen_ssl_fd != INVALID_SOCKET) {
        close_socket(listen_ssl_fd);
    }
    backend_cache_cleanup(&backend_cache);
    tls_state_cleanup(&tls_state);
    free_config(config);

#ifdef _WIN32
    WSACleanup();
#endif

    return EXIT_SUCCESS;
}

void queue_init(TaskQueue* q) {
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    mtx_init(&q->mutex, mtx_plain);
    cnd_init(&q->not_empty);
    cnd_init(&q->not_full);
}

void queue_push(TaskQueue* q, Task task) {
    mtx_lock(&q->mutex);
    while (q->count == TASK_QUEUE_SIZE) {
        cnd_wait(&q->not_full, &q->mutex);
    }
    q->queue[q->tail] = task;
    q->tail = (q->tail + 1) & (TASK_QUEUE_SIZE - 1);
    q->count++;
    cnd_signal(&q->not_empty);
    mtx_unlock(&q->mutex);
}

Task queue_pop(TaskQueue* q) {
    mtx_lock(&q->mutex);
    while (q->count == 0) {
        cnd_wait(&q->not_empty, &q->mutex);
    }
    Task task = q->queue[q->head];
    q->head = (q->head + 1) & (TASK_QUEUE_SIZE - 1);
    q->count--;
    cnd_signal(&q->not_full);
    mtx_unlock(&q->mutex);
    return task;
}

int worker_thread(void* arg) {
    const WorkerContext* context = (const WorkerContext*)arg;
    while (1) {
        Task task = queue_pop(&task_queue);
        process_connection(task, context->config, context->tls_state, context->backend_cache);
    }
    return 0;
}

void process_connection(Task task, const Config* config, const TlsState* tls_state, const BackendCache* backend_cache) {
    socket_t client_socket = task.client_socket;
    SSL* client_ssl = NULL;

    if (task.is_tls) {
#if TG_HAS_OPENSSL
        if (!tls_state || !tls_state->enabled || !tls_state->default_ctx) {
            close_socket(client_socket);
            return;
        }

        client_ssl = SSL_new(tls_state->default_ctx);
        if (!client_ssl) {
            close_socket(client_socket);
            return;
        }

        if (SSL_set_fd(client_ssl, (int)client_socket) != 1 || SSL_accept(client_ssl) <= 0) {
            SSL_free(client_ssl);
            close_socket(client_socket);
            return;
        }
#else
        close_socket(client_socket);
        return;
#endif
    }

    char buffer[BUFFER_SIZE];
    io_count_t bytes_read = client_recv(client_socket, client_ssl, task.is_tls, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }
    buffer[bytes_read] = '\0';

    char host[HOST_BUFFER_SIZE];
    if (!try_parse_host(buffer, host, sizeof(host))) {
        (void)client_send_all(client_socket, client_ssl, task.is_tls, RESPONSE_BAD_REQUEST, sizeof(RESPONSE_BAD_REQUEST) - 1);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    const ProxyRule* rule = find_rule(config, host);
    if (!rule) {
        (void)client_send_all(client_socket, client_ssl, task.is_tls, RESPONSE_BAD_GATEWAY, sizeof(RESPONSE_BAD_GATEWAY) - 1);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    if (!task.is_tls && rule->force_ssl) {
        char target[TARGET_BUFFER_SIZE];
        if (!try_parse_request_target(buffer, target, sizeof(target))) {
            memcpy(target, "/", 2);
        }

        bool can_redirect = tls_state && tls_state->enabled && tls_state_has_host(tls_state, host);
        if (can_redirect) {
            (void)send_redirect_to_https(client_socket, client_ssl, false, host, target, tls_state->listen_ssl_port);
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
    if (server_socket == INVALID_SOCKET) {
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    (void)tune_socket(server_socket, false);

    if (connect(server_socket, (const struct sockaddr*)&backend->addr, backend->addr_len) < 0) {
        close_socket(server_socket);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    if (!send_all(server_socket, buffer, (size_t)bytes_read)) {
        close_socket(server_socket);
        close_client(client_socket, client_ssl, task.is_tls);
        return;
    }

    relay_data(client_socket, client_ssl, task.is_tls, server_socket);

    close_socket(server_socket);
    close_client(client_socket, client_ssl, task.is_tls);
}

void relay_data(socket_t client_socket, SSL* client_ssl, bool client_is_tls, socket_t server_socket) {
    char buffer[BUFFER_SIZE];
    fd_set read_fds;
    socket_t max_fd = (client_socket > server_socket) ? client_socket : server_socket;

    struct timeval timeout;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(server_socket, &read_fds);

        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        int activity = select((int)(max_fd + 1), &read_fds, NULL, NULL, &timeout);
        if (activity <= 0) {
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            io_count_t count = client_recv(client_socket, client_ssl, client_is_tls, buffer, sizeof(buffer));
            if (count <= 0) {
                break;
            }
            if (!send_all(server_socket, buffer, (size_t)count)) {
                break;
            }
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            io_count_t count = recv(server_socket, buffer, (int)sizeof(buffer), 0);
            if (count <= 0) {
                break;
            }
            if (!client_send_all(client_socket, client_ssl, client_is_tls, buffer, (size_t)count)) {
                break;
            }
        }
    }
}

bool try_parse_host(const char* buffer, char* out_host, size_t out_size) {
    const char* line = buffer;

    while (*line != '\0') {
        const char* line_end = strstr(line, "\r\n");
        if (!line_end) {
            return false;
        }

        if (line_end == line) {
            return false;
        }

        size_t line_len = (size_t)(line_end - line);
        if (line_len >= 5 &&
            ((line[0] | 32) == 'h') &&
            ((line[1] | 32) == 'o') &&
            ((line[2] | 32) == 's') &&
            ((line[3] | 32) == 't') &&
            line[4] == ':') {
            const char* host_start = line + 5;
            while (host_start < line_end && (*host_start == ' ' || *host_start == '\t')) {
                host_start++;
            }

            size_t host_len = (size_t)(line_end - host_start);
            while (host_len > 0 && (host_start[host_len - 1] == ' ' || host_start[host_len - 1] == '\t')) {
                host_len--;
            }

            if (host_len == 0 || host_len >= out_size) {
                return false;
            }

            for (size_t i = 0; i < host_len; i++) {
                out_host[i] = (char)tolower((unsigned char)host_start[i]);
            }
            out_host[host_len] = '\0';

            if (out_host[0] == '[') {
                char* closing_bracket = strchr(out_host, ']');
                if (!closing_bracket) {
                    return false;
                }

                size_t bracket_len = (size_t)(closing_bracket - (out_host + 1));
                memmove(out_host, out_host + 1, bracket_len);
                out_host[bracket_len] = '\0';
            } else {
                char* port_colon = strchr(out_host, ':');
                if (port_colon) {
                    *port_colon = '\0';
                }
            }

            return out_host[0] != '\0';
        }

        line = line_end + 2;
    }

    return false;
}

bool try_parse_request_target(const char* buffer, char* out_target, size_t out_size) {
    const char* line_end = strstr(buffer, "\r\n");
    if (!line_end) {
        if (out_size < 2) {
            return false;
        }
        memcpy(out_target, "/", 2);
        return true;
    }

    const char* first_space = strchr(buffer, ' ');
    if (!first_space || first_space >= line_end) {
        if (out_size < 2) {
            return false;
        }
        memcpy(out_target, "/", 2);
        return true;
    }

    const char* second_space = strchr(first_space + 1, ' ');
    if (!second_space || second_space >= line_end || second_space <= first_space + 1) {
        if (out_size < 2) {
            return false;
        }
        memcpy(out_target, "/", 2);
        return true;
    }

    size_t raw_len = (size_t)(second_space - (first_space + 1));
    if (raw_len == 0) {
        if (out_size < 2) {
            return false;
        }
        memcpy(out_target, "/", 2);
        return true;
    }

    if (raw_len + 1 > out_size) {
        return false;
    }

    memcpy(out_target, first_space + 1, raw_len);
    out_target[raw_len] = '\0';

    const char* scheme = strstr(out_target, "://");
    if (scheme && (scheme == out_target + 4 || scheme == out_target + 5)) {
        const char* authority_start = scheme + 3;
        const char* path_start = strchr(authority_start, '/');
        if (!path_start) {
            if (out_size < 2) {
                return false;
            }
            memcpy(out_target, "/", 2);
            return true;
        }

        size_t normalized_len = strlen(path_start);
        if (normalized_len + 1 > out_size) {
            return false;
        }
        memmove(out_target, path_start, normalized_len + 1);
        return true;
    }

    if (out_target[0] != '/') {
        if (out_size < 2) {
            return false;
        }
        memcpy(out_target, "/", 2);
        return true;
    }

    return true;
}

bool send_all(socket_t socket, const char* data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        int sent = socket_send(socket, data + sent_total, length - sent_total);
        if (sent <= 0) {
            return false;
        }
        sent_total += (size_t)sent;
    }
    return true;
}

bool client_send_all(socket_t socket, SSL* ssl, bool is_tls, const char* data, size_t length) {
#if TG_HAS_OPENSSL
    if (is_tls) {
        size_t sent_total = 0;
        while (sent_total < length) {
            int sent = SSL_write(ssl, data + sent_total, (int)(length - sent_total));
            if (sent <= 0) {
                return false;
            }
            sent_total += (size_t)sent;
        }
        return true;
    }
#else
    (void)ssl;
    if (is_tls) {
        return false;
    }
#endif

    return send_all(socket, data, length);
}

io_count_t client_recv(socket_t socket, SSL* ssl, bool is_tls, char* buffer, size_t length) {
#if TG_HAS_OPENSSL
    if (is_tls) {
        return SSL_read(ssl, buffer, (int)length);
    }
#else
    (void)ssl;
    if (is_tls) {
        return -1;
    }
#endif

    return recv(socket, buffer, (int)length, 0);
}

socket_t create_listen_socket(const char* listen_ip, int listen_port) {
    socket_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == INVALID_SOCKET) {
        perror("socket() failed");
        return INVALID_SOCKET;
    }

    (void)tune_socket(listen_fd, true);

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)listen_port);
    if (inet_pton(AF_INET, listen_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid listen_ip: %s\n", listen_ip);
        close_socket(listen_fd);
        return INVALID_SOCKET;
    }

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close_socket(listen_fd);
        return INVALID_SOCKET;
    }

    if (listen(listen_fd, SOMAXCONN) < 0) {
        perror("listen() failed");
        close_socket(listen_fd);
        return INVALID_SOCKET;
    }

    return listen_fd;
}

void close_client(socket_t socket, SSL* ssl, bool is_tls) {
#if TG_HAS_OPENSSL
    if (is_tls && ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
#else
    (void)ssl;
    (void)is_tls;
#endif
    close_socket(socket);
}

bool send_redirect_to_https(socket_t socket, SSL* ssl, bool is_tls, const char* host, const char* target, int ssl_port) {
    char response[REDIRECT_BUFFER_SIZE];
    int written = 0;

    if (ssl_port == 443) {
        written = snprintf(
            response,
            sizeof(response),
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            host,
            target
        );
    } else {
        written = snprintf(
            response,
            sizeof(response),
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s:%d%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            host,
            ssl_port,
            target
        );
    }

    if (written <= 0 || (size_t)written >= sizeof(response)) {
        return false;
    }

    return client_send_all(socket, ssl, is_tls, response, (size_t)written);
}

bool rule_has_tls_identity(const ProxyRule* rule) {
    return rule && rule->tls_cert_file && rule->tls_key_file && rule->tls_cert_file[0] != '\0' && rule->tls_key_file[0] != '\0';
}

bool tls_state_init(TlsState* tls_state, const Config* config) {
    memset(tls_state, 0, sizeof(*tls_state));

    if (config->listen_ssl_port <= 0) {
        tls_state->enabled = false;
        return true;
    }

    tls_state->enabled = true;
    tls_state->listen_ssl_port = config->listen_ssl_port;

#if !TG_HAS_OPENSSL
    fprintf(stderr, "SSL support requires OpenSSL headers and libraries.\n");
    return false;
#else
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        fprintf(stderr, "Failed to initialize OpenSSL.\n");
        return false;
    }

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

        TlsContextEntry* entry = malloc(sizeof(*entry));
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
#endif
}

void tls_state_cleanup(TlsState* tls_state) {
#if TG_HAS_OPENSSL
    TlsContextEntry* current = tls_state->entries;
    while (current) {
        TlsContextEntry* next = current->next;
        if (current->ctx) {
            SSL_CTX_free(current->ctx);
        }
        free(current);
        current = next;
    }
#endif

    tls_state->entries = NULL;
    tls_state->default_ctx = NULL;
    tls_state->enabled = false;
    tls_state->listen_ssl_port = 0;
}

const TlsContextEntry* find_tls_entry(const TlsState* tls_state, const char* host) {
    if (!tls_state || !host) {
        return NULL;
    }

    char host_lower[HOST_BUFFER_SIZE];
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len >= sizeof(host_lower)) {
        return NULL;
    }

    for (size_t i = 0; i < host_len; i++) {
        host_lower[i] = (char)tolower((unsigned char)host[i]);
    }
    host_lower[host_len] = '\0';

    for (const TlsContextEntry* entry = tls_state->entries; entry != NULL; entry = entry->next) {
        if (entry->rule && entry->rule->entry_domain_lower && strcmp(entry->rule->entry_domain_lower, host_lower) == 0) {
            return entry;
        }
    }

    return NULL;
}

bool tls_state_has_host(const TlsState* tls_state, const char* host) {
    return find_tls_entry(tls_state, host) != NULL;
}

bool backend_cache_init(BackendCache* cache, const Config* config) {
    cache->entries = NULL;

    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (!rule->backend_host || rule->backend_host[0] == '\0' || rule->backend_port <= 0 || rule->backend_port > 65535) {
            fprintf(stderr, "Invalid or missing endpoint for domain %s\n", rule->entry_domain);
            backend_cache_cleanup(cache);
            return false;
        }

        struct addrinfo hints = {0};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", rule->backend_port);

        struct addrinfo* result = NULL;
        if (getaddrinfo(rule->backend_host, port_str, &hints, &result) != 0 || result == NULL) {
            fprintf(stderr, "Failed to resolve backend %s:%d for domain %s\n", rule->backend_host, rule->backend_port, rule->entry_domain);
            backend_cache_cleanup(cache);
            return false;
        }

        BackendEntry* entry = malloc(sizeof(*entry));
        if (!entry) {
            freeaddrinfo(result);
            backend_cache_cleanup(cache);
            return false;
        }

        if ((size_t)result->ai_addrlen > sizeof(entry->addr)) {
            free(entry);
            freeaddrinfo(result);
            fprintf(stderr, "Resolved backend address too large for domain %s\n", rule->entry_domain);
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

void backend_cache_cleanup(BackendCache* cache) {
    BackendEntry* current = cache->entries;
    while (current) {
        BackendEntry* next = current->next;
        free(current);
        current = next;
    }
    cache->entries = NULL;
}

const BackendEntry* backend_cache_find(const BackendCache* cache, const ProxyRule* rule) {
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

bool tune_socket(socket_t socket, bool is_listener) {
    int enabled = 1;
    bool success = true;

    if (is_listener) {
        if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&enabled, sizeof(enabled)) != 0) {
            success = false;
        }
#if defined(SO_REUSEPORT)
        (void)setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, (const char*)&enabled, sizeof(enabled));
#endif
#if defined(__FreeBSD__) && defined(SO_REUSEPORT_LB)
        // FreeBSD load-balancing.
        (void)setsockopt(socket, SOL_SOCKET, SO_REUSEPORT_LB, (const char*)&enabled, sizeof(enabled));
#endif
#if defined(TCP_FASTOPEN)
    int fastopen_queue = 256;
    (void)setsockopt(socket, IPPROTO_TCP, TCP_FASTOPEN, (const char*)&fastopen_queue, sizeof(fastopen_queue));
#endif
    }

#if defined(SO_NOSIGPIPE)
    // FreeBSD SO_NOSIGPIPE.
    (void)setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&enabled, sizeof(enabled));
#endif
#if defined(TCP_NODELAY)
    (void)setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&enabled, sizeof(enabled));
#endif

    return success;
}

socket_t accept_client_socket(socket_t listen_socket) {
    socket_t client_socket = INVALID_SOCKET;

#if defined(__FreeBSD__) && defined(SOCK_CLOEXEC)
    client_socket = accept4(listen_socket, NULL, NULL, SOCK_CLOEXEC);
    if (client_socket != INVALID_SOCKET) {
        (void)tune_socket(client_socket, false);
        return client_socket;
    }

    if (errno != ENOSYS && errno != EINVAL) {
        return INVALID_SOCKET;
    }
#endif

    client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket != INVALID_SOCKET) {
        (void)tune_socket(client_socket, false);
    }
    return client_socket;
}

int socket_send(socket_t socket, const char* data, size_t length) {
#if defined(_WIN32)
    return send(socket, data, (int)length, 0);
#else
#if defined(MSG_NOSIGNAL)
    return (int)send(socket, data, length, MSG_NOSIGNAL);
#else
    return (int)send(socket, data, length, 0);
#endif
#endif
}

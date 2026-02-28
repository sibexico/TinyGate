#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#if defined(__has_include)
    #if __has_include(<threads.h>)
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

#include "config.h"

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
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    typedef int socket_t;
    typedef ssize_t io_count_t;
    #define close_socket(s) close(s)
    #define INVALID_SOCKET -1
#endif

#define BUFFER_SIZE 4096
#define TASK_QUEUE_SIZE 256

typedef struct {
    socket_t queue[TASK_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    mtx_t mutex;
    cnd_t not_empty;
    cnd_t not_full;
} TaskQueue;


void queue_init(TaskQueue* q);
void queue_push(TaskQueue* q, socket_t socket);
socket_t queue_pop(TaskQueue* q);
void process_connection(socket_t client_socket, const Config* config);
int worker_thread(void* arg);
void relay_data(socket_t client_socket, socket_t server_socket);
char* get_host_from_request(const char* buffer);
const char* cross_platform_strcasestr(const char* haystack, const char* needle);
bool send_all(socket_t socket, const char* data, size_t length);


TaskQueue task_queue;


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

    queue_init(&task_queue);
    thrd_t* threads = malloc(sizeof(*threads) * (size_t)config->worker_threads);
    if (!threads) {
        fprintf(stderr, "Failed to allocate worker thread list.\n");
        free_config(config);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < config->worker_threads; i++) {
        if (thrd_create(&threads[i], worker_thread, (void*)config) != thrd_success) {
            fprintf(stderr, "Failed to create worker thread.\n");
            free(threads);
            free_config(config);
            return EXIT_FAILURE;
        }
    }

    socket_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == INVALID_SOCKET) {
        perror("socket() failed");
        free_config(config);
        return EXIT_FAILURE;
    }

    int optval = 1;
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->listen_port);
    if (inet_pton(AF_INET, config->listen_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid listen_ip: %s\n", config->listen_ip);
        close_socket(listen_fd);
        free(threads);
        free_config(config);
        return EXIT_FAILURE;
    }

    if (bind(listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close_socket(listen_fd);
        free_config(config);
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, 10) < 0) {
        perror("listen() failed");
        close_socket(listen_fd);
        free_config(config);
        return EXIT_FAILURE;
    }

    while (1) {
        socket_t client_socket = accept(listen_fd, NULL, NULL);
        if (client_socket == INVALID_SOCKET) {
            perror("accept() failed");
            continue;
        }
        queue_push(&task_queue, client_socket);
    }

    for (int i = 0; i < config->worker_threads; i++) {
        thrd_join(threads[i], NULL);
    }
    free(threads);
    close_socket(listen_fd);
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

void queue_push(TaskQueue* q, socket_t socket) {
    mtx_lock(&q->mutex);
    while (q->count == TASK_QUEUE_SIZE) {
        cnd_wait(&q->not_full, &q->mutex);
    }
    q->queue[q->tail] = socket;
    q->tail = (q->tail + 1) % TASK_QUEUE_SIZE;
    q->count++;
    cnd_signal(&q->not_empty);
    mtx_unlock(&q->mutex);
}

socket_t queue_pop(TaskQueue* q) {
    mtx_lock(&q->mutex);
    while (q->count == 0) {
        cnd_wait(&q->not_empty, &q->mutex);
    }
    socket_t socket = q->queue[q->head];
    q->head = (q->head + 1) % TASK_QUEUE_SIZE;
    q->count--;
    cnd_signal(&q->not_full);
    mtx_unlock(&q->mutex);
    return socket;
}

int worker_thread(void* arg) {
    const Config* config = (const Config*)arg;
    while (1) {
        socket_t client_socket = queue_pop(&task_queue);
        process_connection(client_socket, config);
    }
    return 0;
}

void process_connection(socket_t client_socket, const Config* config) {
    char buffer[BUFFER_SIZE];
    io_count_t bytes_read = recv(client_socket, buffer, (int)(sizeof(buffer) - 1), 0);

    if (bytes_read <= 0) {
        close_socket(client_socket);
        return;
    }
    buffer[bytes_read] = '\0';

    char* host = get_host_from_request(buffer);
    if (!host) {
        const char* bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        (void)send_all(client_socket, bad_request, strlen(bad_request));
        close_socket(client_socket);
        return;
    }

    const ProxyRule* rule = find_rule(config, host);
    free(host);

    if (!rule) {
        const char* not_found = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        (void)send_all(client_socket, not_found, strlen(not_found));
        close_socket(client_socket);
        return;
    }
    
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", rule->endpoint_port);

    if (getaddrinfo(rule->endpoint_host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        close_socket(client_socket);
        return;
    }

    socket_t server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_socket == INVALID_SOCKET) {
        perror("endpoint socket() failed");
        freeaddrinfo(res);
        close_socket(client_socket);
        return;
    }

    if (connect(server_socket, res->ai_addr, res->ai_addrlen) < 0) {
        perror("endpoint connect() failed");
        freeaddrinfo(res);
        close_socket(server_socket);
        close_socket(client_socket);
        return;
    }
    freeaddrinfo(res);

    if (!send_all(server_socket, buffer, (size_t)bytes_read)) {
        perror("send to endpoint failed");
        close_socket(server_socket);
        close_socket(client_socket);
        return;
    }

    relay_data(client_socket, server_socket);

    close_socket(client_socket);
    close_socket(server_socket);
}

void relay_data(socket_t client_socket, socket_t server_socket) {
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

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity <= 0) { 
            if (activity < 0) {
                perror("select() error");
            }
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            io_count_t count = recv(client_socket, buffer, (int)sizeof(buffer), 0);
            if (count <= 0) break;
            if (!send_all(server_socket, buffer, (size_t)count)) break;
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            io_count_t count = recv(server_socket, buffer, (int)sizeof(buffer), 0);
            if (count <= 0) break;
            if (!send_all(client_socket, buffer, (size_t)count)) break;
        }
    }
}

char* get_host_from_request(const char* buffer) {
    const char* host_hdr = "Host: ";
    const char* host_start = cross_platform_strcasestr(buffer, host_hdr);

    if (!host_start) {
        return NULL;
    }
    
    host_start += strlen(host_hdr);
    const char* host_end = strstr(host_start, "\r\n");
    if (!host_end) {
        return NULL;
    }

    while (*host_start == ' ' || *host_start == '\t') {
        ++host_start;
    }

    size_t host_len = (size_t)(host_end - host_start);
    while (host_len > 0 && (host_start[host_len - 1] == ' ' || host_start[host_len - 1] == '\t')) {
        --host_len;
    }

    char* host = malloc(host_len + 1);
    if (!host) {
        return NULL;
    }

    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    char* port_colon = strchr(host, ':');
    if (port_colon) {
        *port_colon = '\0';
    }

    return host;
}

const char* cross_platform_strcasestr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    for (; *haystack; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char* h;
            const char* n;
            for (h = haystack, n = needle; *h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n); ++h, ++n) {}
            if (!*n) {
                return haystack;
            }
        }
    }
    return NULL;
}

bool send_all(socket_t socket, const char* data, size_t length) {
    size_t sent_total = 0;
    while (sent_total < length) {
        int sent = send(socket, data + sent_total, (int)(length - sent_total), 0);
        if (sent <= 0) {
            return false;
        }
        sent_total += (size_t)sent;
    }
    return true;
}

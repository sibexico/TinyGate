#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include "config.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define close_socket(s) closesocket(s)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    typedef int socket_t;
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
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
} TaskQueue;


void queue_init(TaskQueue* q);
void queue_push(TaskQueue* q, socket_t socket);
socket_t queue_pop(TaskQueue* q);
void process_connection(socket_t client_socket, const Config* config);
void* worker_thread(void* arg);
void relay_data(socket_t client_socket, socket_t server_socket);
char* get_host_from_request(const char* buffer);
char* cross_platform_strcasestr(const char* haystack, const char* needle);


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
    pthread_t* threads = malloc(sizeof(pthread_t) * config->worker_threads);
    for (int i = 0; i < config->worker_threads; i++) {
        if (pthread_create(&threads[i], nullptr, worker_thread, (void*)config) != 0) {
            perror("Failed to create worker thread");
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
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->listen_port);
    inet_pton(AF_INET, config->listen_ip, &server_addr.sin_addr);

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
        socket_t client_socket = accept(listen_fd, nullptr, nullptr);
        if (client_socket == INVALID_SOCKET) {
            perror("accept() failed");
            continue;
        }
        queue_push(&task_queue, client_socket);
    }

    for (int i = 0; i < config->worker_threads; i++) {
        pthread_join(threads[i], nullptr);
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
    pthread_mutex_init(&q->mutex, nullptr);
    pthread_cond_init(&q->not_empty, nullptr);
}

void queue_push(TaskQueue* q, socket_t socket) {
    pthread_mutex_lock(&q->mutex);
    q->queue[q->tail] = socket;
    q->tail = (q->tail + 1) % TASK_QUEUE_SIZE;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

socket_t queue_pop(TaskQueue* q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    socket_t socket = q->queue[q->head];
    q->head = (q->head + 1) % TASK_QUEUE_SIZE;
    q->count--;
    pthread_mutex_unlock(&q->mutex);
    return socket;
}

void* worker_thread(void* arg) {
    const Config* config = (const Config*)arg;
    while (1) {
        socket_t client_socket = queue_pop(&task_queue);
        process_connection(client_socket, config);
    }
    return nullptr;
}

void process_connection(socket_t client_socket, const Config* config) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

    if (bytes_read <= 0) {
        close_socket(client_socket);
        return;
    }
    buffer[bytes_read] = '\0';

    char* host = get_host_from_request(buffer);
    if (!host) {
        const char* bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_socket, bad_request, strlen(bad_request), 0);
        close_socket(client_socket);
        return;
    }

    const ProxyRule* rule = find_rule(config, host);
    free(host);

    if (!rule) {
        const char* not_found = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(client_socket, not_found, strlen(not_found), 0);
        close_socket(client_socket);
        return;
    }
    
    struct addrinfo hints = {0}, *res = nullptr;
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

    if (send(server_socket, buffer, bytes_read, 0) < 0) {
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
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_socket, &read_fds);
        FD_SET(server_socket, &read_fds);

        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (activity <= 0) { 
            if (activity < 0) {
                perror("select() error");
            }
            break;
        }

        if (FD_ISSET(client_socket, &read_fds)) {
            ssize_t count = recv(client_socket, buffer, sizeof(buffer), 0);
            if (count <= 0) break;
            if (send(server_socket, buffer, count, 0) <= 0) break;
        }

        if (FD_ISSET(server_socket, &read_fds)) {
            ssize_t count = recv(server_socket, buffer, sizeof(buffer), 0);
            if (count <= 0) break;
            if (send(client_socket, buffer, count, 0) <= 0) break;
        }
    }
}

char* get_host_from_request(const char* buffer) {
    const char* host_hdr = "Host: ";
    const char* host_start = cross_platform_strcasestr(buffer, host_hdr);

    if (!host_start) {
        return nullptr;
    }
    
    host_start += strlen(host_hdr);
    const char* host_end = strstr(host_start, "\r\n");
    if (!host_end) {
        return nullptr;
    }

    size_t host_len = host_end - host_start;
    char* host = malloc(host_len + 1);
    if (!host) {
        return nullptr;
    }

    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    char* port_colon = strchr(host, ':');
    if (port_colon) {
        *port_colon = '\0';
    }

    return host;
}

char* cross_platform_strcasestr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char* h, * n;
            for (h = haystack, n = needle; *h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n); ++h, ++n) {}
            if (!*n) {
                return (char*)haystack;
            }
        }
    }
    return nullptr;
}

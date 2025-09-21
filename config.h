#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct ProxyRule {
    char* entry_domain;
    char* endpoint_host;
    int endpoint_port;
    struct ProxyRule* next;
} ProxyRule;

typedef struct Config {
    char* listen_ip;
    int listen_port;
    int worker_threads;
    ProxyRule* rules;
} Config;

[[nodiscard]] Config* load_config(const char* filename);
void free_config(Config* config);
const ProxyRule* find_rule(const Config* config, const char* host);

#endif
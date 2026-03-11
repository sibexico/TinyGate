#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#if !defined(__INTELLISENSE__)
    #if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 202000L)
        #error TinyGate requires C23 mode.
    #endif
#endif

typedef struct ProxyRule {
    char* entry_domain;
    char* entry_domain_lower;
    char* backend_host;
    int backend_port;
    char* tls_cert_file;
    char* tls_key_file;
    bool force_ssl;
    struct ProxyRule* next;
} ProxyRule;

typedef struct Config {
    char* listen_ip;
    int listen_port;
    int listen_ssl_port;
    int worker_threads;
    ProxyRule* rules;
} Config;

[[nodiscard]] Config* load_config(const char* filename);
void free_config(Config* config);
const ProxyRule* find_rule(const Config* config, const char* host);

#endif
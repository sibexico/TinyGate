#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

#define LINE_BUFFER_SIZE 256

static bool parse_endpoint_value(const char* text, char** out_host, int* out_port);
static int detect_worker_threads(void);
static char* duplicate_string_lower(const char* source);

static char* duplicate_string(const char* source) {
    size_t length = strlen(source);
    char* copy = malloc(length + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, source, length + 1);
    return copy;
}

static char* duplicate_string_lower(const char* source) {
    size_t length = strlen(source);
    char* copy = malloc(length + 1);
    if (!copy) {
        return NULL;
    }

    for (size_t i = 0; i < length; i++) {
        copy[i] = (char)tolower((unsigned char)source[i]);
    }
    copy[length] = '\0';
    return copy;
}

static bool parse_int_value(const char* text, int* out_value) {
    char* end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < INT_MIN || value > INT_MAX) {
        return false;
    }
    *out_value = (int)value;
    return true;
}

static bool parse_bool_value(const char* text, bool* out_value) {
    if (strcmp(text, "1") == 0) {
        *out_value = true;
        return true;
    }

    if (strcmp(text, "0") == 0) {
        *out_value = false;
        return true;
    }

    char normalized[16] = {0};
    size_t length = strlen(text);
    if (length >= sizeof(normalized)) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        normalized[i] = (char)tolower((unsigned char)text[i]);
    }

    if (strcmp(normalized, "true") == 0 || strcmp(normalized, "yes") == 0 || strcmp(normalized, "on") == 0) {
        *out_value = true;
        return true;
    }

    if (strcmp(normalized, "false") == 0 || strcmp(normalized, "no") == 0 || strcmp(normalized, "off") == 0) {
        *out_value = false;
        return true;
    }

    return false;
}

static char* trim_whitespace(char* str) {
    char* end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
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

static int detect_worker_threads(void) {
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors > 0 && info.dwNumberOfProcessors <= INT_MAX) {
        return (int)info.dwNumberOfProcessors;
    }
#elif defined(_SC_NPROCESSORS_ONLN)
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0 && cores <= INT_MAX) {
        return (int)cores;
    }
#endif

    return 2;
}

Config* load_config(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Could not open config file");
        return NULL;
    }

    Config* config = calloc(1, sizeof(Config));
    if (!config) {
        perror("Failed to allocate memory for config");
        fclose(file);
        return NULL;
    }

    config->listen_ip = duplicate_string("127.0.0.1");
    config->listen_port = 80;
    config->listen_ssl_port = 443;
    config->worker_threads = detect_worker_threads();
    if (!config->listen_ip) {
        perror("Failed to allocate memory for listen_ip");
        fclose(file);
        free(config);
        return NULL;
    }

    char line[LINE_BUFFER_SIZE];
    ProxyRule* current_rule = NULL;

    while (fgets(line, sizeof(line), file)) {
        char* trimmed_line = trim_whitespace(line);
        if (trimmed_line[0] == '#' || trimmed_line[0] == ';' || trimmed_line[0] == '\0') {
            continue;
        }

        if (trimmed_line[0] == '[') {
            char* section_end = strchr(trimmed_line, ']');
            if (section_end) {
                *section_end = '\0';
                char* section_name = trimmed_line + 1;
                current_rule = (strcmp(section_name, "proxy_settings") == 0) ? NULL : calloc(1, sizeof(ProxyRule));
                if (current_rule) {
                    current_rule->entry_domain = duplicate_string(section_name);
                    current_rule->entry_domain_lower = duplicate_string_lower(section_name);
                    if (!current_rule->entry_domain || !current_rule->entry_domain_lower) {
                        free(current_rule->entry_domain);
                        free(current_rule->entry_domain_lower);
                        free(current_rule);
                        current_rule = NULL;
                        continue;
                    }
                    current_rule->next = config->rules;
                    config->rules = current_rule;
                }
            }
        } else {
            char* equals = strchr(trimmed_line, '=');
            if (equals) {
                *equals = '\0';
                char* key = trim_whitespace(trimmed_line);
                char* value = trim_whitespace(equals + 1);

                if (current_rule) {
                    if (strcmp(key, "endpoint") == 0) {
                        char* parsed_host = NULL;
                        int parsed_port = 0;
                        if (parse_endpoint_value(value, &parsed_host, &parsed_port)) {
                            free(current_rule->backend_host);
                            current_rule->backend_host = parsed_host;
                            current_rule->backend_port = parsed_port;
                        } else {
                            fprintf(stderr, "Invalid endpoint '%s' for domain %s. Use host:port\n", value, current_rule->entry_domain);
                        }
                    } else if (strcmp(key, "tls_cert_file") == 0) {
                        char* next_cert_file = duplicate_string(value);
                        if (next_cert_file) {
                            free(current_rule->tls_cert_file);
                            current_rule->tls_cert_file = next_cert_file;
                        }
                    } else if (strcmp(key, "tls_key_file") == 0) {
                        char* next_key_file = duplicate_string(value);
                        if (next_key_file) {
                            free(current_rule->tls_key_file);
                            current_rule->tls_key_file = next_key_file;
                        }
                    } else if (strcmp(key, "force_ssl") == 0) {
                        bool parsed_force_ssl = false;
                        if (parse_bool_value(value, &parsed_force_ssl)) {
                            current_rule->force_ssl = parsed_force_ssl;
                        }
                    }
                } else {
                    if (strcmp(key, "listen_ip") == 0) {
                        char* next_ip = duplicate_string(value);
                        if (next_ip) {
                            free(config->listen_ip);
                            config->listen_ip = next_ip;
                        }
                    } else if (strcmp(key, "listen_port") == 0) {
                        int parsed_port = 0;
                        if (parse_int_value(value, &parsed_port) && parsed_port > 0 && parsed_port <= 65535) {
                            config->listen_port = parsed_port;
                        }
                    } else if (strcmp(key, "listen_ssl_port") == 0) {
                        int parsed_ssl_port = 0;
                        if (parse_int_value(value, &parsed_ssl_port) && parsed_ssl_port >= 0 && parsed_ssl_port <= 65535) {
                            config->listen_ssl_port = parsed_ssl_port;
                        }
                    } else if (strcmp(key, "worker_threads") == 0) {
                        int parsed_threads = 0;
                        if (parse_int_value(value, &parsed_threads) && parsed_threads > 0) {
                            config->worker_threads = parsed_threads;
                        }
                    }
                }
            }
        }
    }

    fclose(file);
    return config;
}

void free_config(Config* config) {
    if (!config) return;
    free(config->listen_ip);
    ProxyRule* current = config->rules;
    while (current) {
        ProxyRule* next = current->next;
        free(current->entry_domain);
        free(current->entry_domain_lower);
        free(current->backend_host);
        free(current->tls_cert_file);
        free(current->tls_key_file);
        free(current);
        current = next;
    }
    free(config);
}

const ProxyRule* find_rule(const Config* config, const char* host) {
    if (!config || !host) return NULL;
    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (rule->entry_domain_lower && strcmp(rule->entry_domain_lower, host) == 0) {
            return rule;
        }
        if (rule->entry_domain && equal_ignore_case(rule->entry_domain, host)) {
            return rule;
        }
    }
    return NULL;
}

static bool parse_endpoint_value(const char* text, char** out_host, int* out_port) {
    if (!text || !out_host || !out_port || text[0] == '\0') {
        return false;
    }

    const char* host_start = text;
    size_t host_length = 0;
    const char* port_text = NULL;

    if (text[0] == '[') {
        const char* closing_bracket = strchr(text, ']');
        if (!closing_bracket || closing_bracket[1] != ':') {
            return false;
        }

        host_start = text + 1;
        host_length = (size_t)(closing_bracket - host_start);
        port_text = closing_bracket + 2;
    } else {
        const char* separator = strrchr(text, ':');
        if (!separator) {
            return false;
        }

        host_length = (size_t)(separator - text);
        port_text = separator + 1;
    }

    if (host_length == 0 || !port_text || port_text[0] == '\0') {
        return false;
    }

    int parsed_port = 0;
    if (!parse_int_value(port_text, &parsed_port) || parsed_port <= 0 || parsed_port > 65535) {
        return false;
    }

    char* host_copy = malloc(host_length + 1);
    if (!host_copy) {
        return false;
    }

    memcpy(host_copy, host_start, host_length);
    host_copy[host_length] = '\0';

    *out_host = host_copy;
    *out_port = parsed_port;
    return true;
}

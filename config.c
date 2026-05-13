#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define LINE_BUFFER_SIZE 512

static char* duplicate_string(const char* source);
static char* duplicate_string_lower(const char* source);
static char* trim_whitespace(char* value);
static int parse_int_value(const char* text, int* out_value);
static int parse_bool_value(const char* text, bool* out_value);
static int parse_endpoint_value(const char* text, char** out_host, int* out_port);
static int equal_ignore_case(const char* left, const char* right);

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

static char* trim_whitespace(char* value) {
    while (isspace((unsigned char)*value)) {
        value++;
    }

    if (*value == '\0') {
        return value;
    }

    char* end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';
    return value;
}

static int parse_int_value(const char* text, int* out_value) {
    char* end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < INT_MIN || value > INT_MAX) {
        return 0;
    }

    *out_value = (int)value;
    return 1;
}

static int parse_bool_value(const char* text, bool* out_value) {
    if (strcmp(text, "1") == 0) {
        *out_value = true;
        return 1;
    }

    if (strcmp(text, "0") == 0) {
        *out_value = false;
        return 1;
    }

    char normalized[16] = {0};
    size_t length = strlen(text);
    if (length >= sizeof(normalized)) {
        return 0;
    }

    for (size_t i = 0; i < length; i++) {
        normalized[i] = (char)tolower((unsigned char)text[i]);
    }

    if (strcmp(normalized, "true") == 0 || strcmp(normalized, "yes") == 0 || strcmp(normalized, "on") == 0) {
        *out_value = true;
        return 1;
    }

    if (strcmp(normalized, "false") == 0 || strcmp(normalized, "no") == 0 || strcmp(normalized, "off") == 0) {
        *out_value = false;
        return 1;
    }

    return 0;
}

static int parse_endpoint_value(const char* text, char** out_host, int* out_port) {
    if (!text || !out_host || !out_port || text[0] == '\0') {
        return 0;
    }

    const char* host_start = text;
    size_t host_length = 0;
    const char* port_text = NULL;

    if (text[0] == '[') {
        const char* closing_bracket = strchr(text, ']');
        if (!closing_bracket || closing_bracket[1] != ':') {
            return 0;
        }
        host_start = text + 1;
        host_length = (size_t)(closing_bracket - host_start);
        port_text = closing_bracket + 2;
    } else {
        const char* separator = strrchr(text, ':');
        if (!separator) {
            return 0;
        }
        host_length = (size_t)(separator - text);
        port_text = separator + 1;
    }

    if (host_length == 0 || !port_text || port_text[0] == '\0') {
        return 0;
    }

    int parsed_port = 0;
    if (!parse_int_value(port_text, &parsed_port) || parsed_port <= 0 || parsed_port > 65535) {
        return 0;
    }

    char* host_copy = malloc(host_length + 1);
    if (!host_copy) {
        return 0;
    }

    memcpy(host_copy, host_start, host_length);
    host_copy[host_length] = '\0';

    *out_host = host_copy;
    *out_port = parsed_port;
    return 1;
}

static int equal_ignore_case(const char* left, const char* right) {
    while (*left && *right) {
        if (tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
            return 0;
        }
        left++;
        right++;
    }
    return *left == '\0' && *right == '\0';
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

    config->listen_ip = duplicate_string("0.0.0.0");
    config->listen_port = 80;
    config->listen_ssl_port = 443;
    config->max_events = 1024;
    config->max_connections = 8192;
    config->io_buffer_size = 16384;
    config->host_buffer_size = 256;
    config->target_buffer_size = 2048;
    config->redirect_buffer_size = 3072;

    if (!config->listen_ip) {
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
            if (!section_end) {
                continue;
            }

            *section_end = '\0';
            char* section_name = trim_whitespace(trimmed_line + 1);
            if (strcmp(section_name, "proxy_settings") == 0) {
                current_rule = NULL;
                continue;
            }

            ProxyRule* rule = calloc(1, sizeof(*rule));
            if (!rule) {
                continue;
            }

            rule->entry_domain = duplicate_string(section_name);
            rule->entry_domain_lower = duplicate_string_lower(section_name);
            if (!rule->entry_domain || !rule->entry_domain_lower) {
                free(rule->entry_domain);
                free(rule->entry_domain_lower);
                free(rule);
                continue;
            }

            rule->next = config->rules;
            config->rules = rule;
            current_rule = rule;
            continue;
        }

        char* equals = strchr(trimmed_line, '=');
        if (!equals) {
            continue;
        }

        *equals = '\0';
        char* key = trim_whitespace(trimmed_line);
        char* value = trim_whitespace(equals + 1);

        if (!current_rule) {
            if (strcmp(key, "listen_ip") == 0) {
                char* next_ip = duplicate_string(value);
                if (next_ip) {
                    free(config->listen_ip);
                    config->listen_ip = next_ip;
                }
            } else if (strcmp(key, "listen_port") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0 && parsed <= 65535) {
                    config->listen_port = parsed;
                }
            } else if (strcmp(key, "listen_ssl_port") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed >= 0 && parsed <= 65535) {
                    config->listen_ssl_port = parsed;
                }
            } else if (strcmp(key, "max_events") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->max_events = parsed;
                }
            } else if (strcmp(key, "max_connections") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->max_connections = parsed;
                }
            } else if (strcmp(key, "io_buffer_size") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->io_buffer_size = parsed;
                }
            } else if (strcmp(key, "host_buffer_size") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->host_buffer_size = parsed;
                }
            } else if (strcmp(key, "target_buffer_size") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->target_buffer_size = parsed;
                }
            } else if (strcmp(key, "redirect_buffer_size") == 0) {
                int parsed = 0;
                if (parse_int_value(value, &parsed) && parsed > 0) {
                    config->redirect_buffer_size = parsed;
                }
            }
            continue;
        }

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
            char* next_cert = duplicate_string(value);
            if (next_cert) {
                free(current_rule->tls_cert_file);
                current_rule->tls_cert_file = next_cert;
            }
        } else if (strcmp(key, "tls_key_file") == 0) {
            char* next_key = duplicate_string(value);
            if (next_key) {
                free(current_rule->tls_key_file);
                current_rule->tls_key_file = next_key;
            }
        } else if (strcmp(key, "force_ssl") == 0) {
            bool parsed_force_ssl = false;
            if (parse_bool_value(value, &parsed_force_ssl)) {
                current_rule->force_ssl = parsed_force_ssl;
            }
        }
    }

    fclose(file);
    return config;
}

void free_config(Config* config) {
    if (!config) {
        return;
    }

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
    if (!config || !host) {
        return NULL;
    }

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
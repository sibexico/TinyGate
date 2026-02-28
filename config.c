#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define LINE_BUFFER_SIZE 256

static char* duplicate_string(const char* source) {
    size_t length = strlen(source);
    char* copy = malloc(length + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, source, length + 1);
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

static char* trim_whitespace(char* str) {
    char* end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
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
    config->worker_threads = 2;
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
                    if (!current_rule->entry_domain) {
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
                    if (strcmp(key, "endpoint_host") == 0) {
                        char* next_host = duplicate_string(value);
                        if (next_host) {
                            free(current_rule->endpoint_host);
                            current_rule->endpoint_host = next_host;
                        }
                    } else if (strcmp(key, "endpoint_port") == 0) {
                        int parsed_port = 0;
                        if (parse_int_value(value, &parsed_port) && parsed_port > 0 && parsed_port <= 65535) {
                            current_rule->endpoint_port = parsed_port;
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
        free(current->endpoint_host);
        free(current);
        current = next;
    }
    free(config);
}

const ProxyRule* find_rule(const Config* config, const char* host) {
    if (!config || !host) return NULL;
    for (const ProxyRule* rule = config->rules; rule != NULL; rule = rule->next) {
        if (strcmp(rule->entry_domain, host) == 0) {
            return rule;
        }
    }
    return NULL;
}
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LINE_BUFFER_SIZE 256

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
        return nullptr;
    }

    Config* config = calloc(1, sizeof(Config));
    if (!config) {
        perror("Failed to allocate memory for config");
        fclose(file);
        return nullptr;
    }
    // Set default values
    config->listen_ip = strdup("127.0.0.1");
    config->listen_port = 80;
    config->worker_threads = 2;

    char line[LINE_BUFFER_SIZE];
    ProxyRule* current_rule = nullptr;

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
                current_rule = (strcmp(section_name, "proxy_settings") == 0) ? nullptr : calloc(1, sizeof(ProxyRule));
                if (current_rule) {
                    current_rule->entry_domain = strdup(section_name);
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
                    if (strcmp(key, "endpoint_host") == 0) current_rule->endpoint_host = strdup(value);
                    else if (strcmp(key, "endpoint_port") == 0) current_rule->endpoint_port = atoi(value);
                } else {
                    if (strcmp(key, "listen_ip") == 0) {
                        free(config->listen_ip);
                        config->listen_ip = strdup(value);
                    } else if (strcmp(key, "listen_port") == 0) {
                        config->listen_port = atoi(value);
                    } else if (strcmp(key, "worker_threads") == 0) {
                        config->worker_threads = atoi(value);
                    }
                }
            }
        }
    }

    fclose(file);
    return config;
}

// free_config and find_rule are unchanged.
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
    if (!config || !host) return nullptr;
    for (const ProxyRule* rule = config->rules; rule != nullptr; rule = rule->next) {
        if (strcmp(rule->entry_domain, host) == 0) {
            return rule;
        }
    }
    return nullptr;
}
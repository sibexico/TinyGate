#include "http_parser.h"

#include <ctype.h>
#include <string.h>

static bool set_default_target(char* out_target, size_t out_size) {
    if (out_size < 2) {
        return false;
    }
    memcpy(out_target, "/", 2);
    return true;
}

bool parse_host_header(const char* request, char* out_host, size_t out_size) {
    if (!request || !out_host || out_size == 0) {
        return false;
    }

    const char* line = request;

    while (*line != '\0') {
        const char* line_end = strstr(line, "\r\n");
        if (!line_end || line_end == line) {
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

bool parse_request_target(const char* request, char* out_target, size_t out_size) {
    if (!request || !out_target || out_size == 0) {
        return false;
    }

    const char* line_end = strstr(request, "\r\n");
    if (!line_end) {
        return set_default_target(out_target, out_size);
    }

    const char* first_space = strchr(request, ' ');
    if (!first_space || first_space >= line_end) {
        return set_default_target(out_target, out_size);
    }

    const char* second_space = strchr(first_space + 1, ' ');
    if (!second_space || second_space >= line_end || second_space <= first_space + 1) {
        return set_default_target(out_target, out_size);
    }

    size_t raw_len = (size_t)(second_space - (first_space + 1));
    if (raw_len == 0) {
        return set_default_target(out_target, out_size);
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
            return set_default_target(out_target, out_size);
        }

        size_t normalized_len = strlen(path_start);
        if (normalized_len + 1 > out_size) {
            return false;
        }

        memmove(out_target, path_start, normalized_len + 1);
        return true;
    }

    if (out_target[0] != '/') {
        return set_default_target(out_target, out_size);
    }

    return true;
}

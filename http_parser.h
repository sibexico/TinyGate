#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdbool.h>
#include <stddef.h>

bool parse_host_header(const char* request, char* out_host, size_t out_size);
bool parse_request_target(const char* request, char* out_target, size_t out_size);

#endif
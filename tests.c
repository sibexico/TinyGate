#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "http_parser.h"

static void write_text_file(const char* path, const char* content) {
    FILE* file = fopen(path, "wb");
    assert(file != NULL);

    size_t length = strlen(content);
    size_t written = fwrite(content, 1, length, file);
    assert(written == length);

    fclose(file);
}

static void test_parse_host_header(void) {
    char host[256];

    const char* request_one =
        "GET / HTTP/1.1\r\n"
        "Host: Example.com:8080\r\n"
        "Connection: close\r\n"
        "\r\n";

    bool ok = parse_host_header(request_one, host, sizeof(host));
    assert(ok);
    assert(strcmp(host, "example.com") == 0);

    const char* request_two =
        "GET / HTTP/1.1\r\n"
        "hOsT: [2001:db8::1]:443\r\n"
        "\r\n";

    ok = parse_host_header(request_two, host, sizeof(host));
    assert(ok);
    assert(strcmp(host, "2001:db8::1") == 0);
}

static void test_parse_request_target(void) {
    char target[1024];

    const char* absolute_request =
        "GET http://example.com/path?q=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    bool ok = parse_request_target(absolute_request, target, sizeof(target));
    assert(ok);
    assert(strcmp(target, "/path?q=1") == 0);

    const char* origin_request =
        "GET /local/path HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    ok = parse_request_target(origin_request, target, sizeof(target));
    assert(ok);
    assert(strcmp(target, "/local/path") == 0);
}

static void test_config_loading(void) {
    const char* config_path = "tinygate_test_config.ini";

    const char* config_text =
        "[proxy_settings]\n"
        "listen_ip = 127.0.0.1\n"
        "listen_port = 8080\n"
        "listen_ssl_port = 8443\n"
        "max_events = 512\n"
        "max_connections = 2048\n"
        "io_buffer_size = 32768\n"
        "host_buffer_size = 512\n"
        "target_buffer_size = 4096\n"
        "redirect_buffer_size = 8192\n"
        "\n"
        "[Example.COM]\n"
        "endpoint = 127.0.0.1:9000\n"
        "force_ssl = true\n";

    write_text_file(config_path, config_text);

    Config* config = load_config(config_path);
    assert(config != NULL);

    assert(strcmp(config->listen_ip, "127.0.0.1") == 0);
    assert(config->listen_port == 8080);
    assert(config->listen_ssl_port == 8443);
    assert(config->max_events == 512);
    assert(config->max_connections == 2048);
    assert(config->io_buffer_size == 32768);
    assert(config->host_buffer_size == 512);
    assert(config->target_buffer_size == 4096);
    assert(config->redirect_buffer_size == 8192);

    const ProxyRule* rule = find_rule(config, "example.com");
    assert(rule != NULL);
    assert(rule->backend_host != NULL);
    assert(strcmp(rule->backend_host, "127.0.0.1") == 0);
    assert(rule->backend_port == 9000);
    assert(rule->force_ssl);

    free_config(config);
    remove(config_path);
}

int main(void) {
    test_parse_host_header();
    test_parse_request_target();
    test_config_loading();

    puts("All tests passed.");
    return 0;
}

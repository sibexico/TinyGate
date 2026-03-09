A lightweight cross-platform reverse proxy that routes incoming HTTP/HTTPS requests to backend servers.

TinyGate supports TLS certificates, SNI-based certificate selection, and optional per-domain HTTP to HTTPS redirection.

## Configuration
**`[proxy_settings]`**
* `listen_ip`: IP for listening (`0.0.0.0` for all interfaces).
* `listen_port`: Port for listening.
* `listen_ssl_port`: Port for listening HTTPS. Set `0` to disable HTTPS listener.
* `worker_threads`: The number of worker threads in the thread pool.

* `[your.domain.com]`: Targeted host.
* `endpoint_host`: The hostname of the backend server.
* `endpoint_port`: The port of the backend server.
* `tls_cert_file`: Path to PEM certificate.
* `tls_key_file`: Path to PEM private key.
* `force_ssl`: HTTP requests for this domain are forced to HTTPS.

### Example `proxy.ini`

```ini
[proxy_settings]
listen_ip = 0.0.0.0
listen_port = 80
listen_ssl_port = 443
worker_threads = 2

[localhost]
endpoint_host = 127.0.0.1
endpoint_port = 8080
tls_cert_file = 
tls_key_file = 
force_ssl = false

[example.com]
endpoint_host = 127.0.0.1
endpoint_port = 8081
tls_cert_file = certs/example.com.crt
tls_key_file = certs/example.com.key
force_ssl = true
```

## Compilation

### Linux
```Bash
gcc -std=c23 -Wall -Wextra -pedantic main.c config.c -o tinygate -pthread -lssl -lcrypto
```

### Windows
```Bash
gcc -std=c23 -Wall -Wextra -pedantic main.c config.c -o tinygate.exe -pthread -lws2_32 -lssl -lcrypto
```
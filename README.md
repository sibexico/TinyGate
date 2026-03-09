A lightweight cross-platform reverse proxy that routes incoming HTTP/HTTPS requests to backend servers.

TinyGate supports TLS certificates, SNI-based certificate selection, and optional per-domain HTTP to HTTPS redirection.

## Configuration
**`[proxy_settings]`**
* `listen_ip`: IP for listening (`0.0.0.0` for all interfaces).
* `listen_port`: Port for listening.
* `listen_ssl_port`: Port for listening HTTPS. Set `0` to disable HTTPS.
* `worker_threads`: The number of worker threads in the thread pool.

* `[your.domain.com]`: Targeted host.
* `endpoint`: Backend target in `host:port` format (example: `127.0.0.1:8080`).
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
endpoint = 127.0.0.1:8080
tls_cert_file = 
tls_key_file = 
force_ssl = false

[example.com]
endpoint = 127.0.0.1:8081
tls_cert_file = certs/example.com.crt
tls_key_file = certs/example.com.key
force_ssl = true
```


## ACME (Certbot / Let's Encrypt)

### 1. Issue a certificate
Replace with your real domain and email:

```bash
certbot certonly --standalone -d example.com -m you@example.com --agree-tos --non-interactive
```

`--standalone` needs port `80`, stop TinyGate for this first time if TinyGate is already bound to port `80`.

### 2. Use Certbot files with TinyGate

```ini
[example.com]
endpoint = 127.0.0.1:8081
tls_cert_file = /etc/letsencrypt/live/example.com/fullchain.pem
tls_key_file = /etc/letsencrypt/live/example.com/privkey.pem
force_ssl = true
```

### 3. Renew automatically and restart TinyGate only on change

TinyGate loads certificates at startup, so restart after successful renewal.

```bash
certbot renew --deploy-hook "systemctl restart tinygate"
```

If you run TinyGate in other way (Windows service, Docker, manual process), replace the restart command with your own equivalent.


## Compilation

### Linux
```Bash
gcc -std=c23 -Wall -Wextra -pedantic main.c config.c -o tinygate -pthread -lssl -lcrypto
```

### Windows
```Bash
gcc -std=c23 -Wall -Wextra -pedantic main.c config.c -o tinygate.exe -pthread -lws2_32 -lssl -lcrypto
```
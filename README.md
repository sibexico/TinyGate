A lighweight and crosspalform reverse proxy server for standalone web-instances orchestration on single server. It forwarding http reqursts to different backend servers based on the request's `Host` header (domain name).
It's crossplatform (Windows/Linux), uses thread pool and have very simple configuration.

The project was developed in 2020-2021 during COVID-19 pandemic. Code was refactored and adapted to C23 in 2025. 

## Configuration
**`[proxy_settings]`**
* `listen_ip`: IP for listening (`0.0.0.0` for all interfaces).
* `listen_port`: Port for listening.
* `worker_threads`: The number of worker threads in the thread pool.

* `[your.domain.com]`: Targeted host.
* `endpoint_host`: The hostname of the backend server.
* `endpoint_port`: The port of the backend server.

### Example `proxy.ini`

```ini
[proxy_settings]
listen_ip = 0.0.0.0
listen_port = 80
worker_threads = 2

[localhost]
endpoint_host = 127.0.0.1
endpoint_port = 8080

[example.com]
endpoint_host = 127.0.0.1
endpoint_port = 8081
```

## Compilation

### Linux
```Bash
gcc -std=c23 -Wall -Wextra -pthread main.c config.c -o tinygate
```

### Windows
```Bash
gcc -std=c23 -Wall -Wextra -pthread main.c config.c -o tinygate.exe -lws2_32
```
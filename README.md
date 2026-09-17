# SOCKS5 over HTTP Tunnel

A small self-hosted bridge that exposes a **local SOCKS5 listener** and carries each TCP connection through a normal HTTP/HTTPS web endpoint before connecting to the destination from the server side.

The project is designed for accessing systems you own or are authorized to administer when a normal VPN or direct inbound TCP service is not practical.

## How it works

```text
Application / Browser / SSH / Database client
                    |
                    | SOCKS5 CONNECT
                    v
          127.0.0.1:1080
        socks5-bridge binary
                    |
                    | HTTPS POST
                    | optional HTTP/SOCKS5 upstream proxy
                    v
          public web endpoint
       PHP / ASP.NET / JSP
                    |
                    | TCP
                    v
          private/remote target
```

The client speaks SOCKS5 locally, while the server endpoint receives a compact binary envelope over HTTP and opens the actual TCP connection to the requested target.

## Features

- Native single-file Go client for Windows, Linux, and macOS.
- SOCKS5 `CONNECT` with IPv4 targets and hostnames that resolve to IPv4.
- Multiple concurrent SOCKS sessions from one bridge process.
- HTTPS-first client behavior.
- Token authentication between the bridge and server endpoint.
- Binary payload transport without Base64 encoding.
- Server-side CIDR and TCP port policy controls.
- Idle timeout, maximum tunnel lifetime, pending-data limits, and tunnel-count limits.
- Optional upstream proxy between the native bridge and the public endpoint:
  - HTTP proxy
  - HTTP proxy with Basic authentication
  - SOCKS5 / SOCKS5h
  - SOCKS5 username/password authentication
- Server implementations for PHP, ASP.NET, and JSP.

Not currently supported: SOCKS5 `BIND`, `UDP ASSOCIATE`, or IPv6 destination targets.

## Repository layout

```text
client/
  main.go                 Native Go SOCKS5 bridge
  main_test.go            Go unit/integration tests
  socks5-bridge.php       Legacy/debug PHP client

server/
  tunnel.php              PHP endpoint
  tunnel.ashx             ASP.NET 4.x endpoint
  tunnel.aspx             ASP.NET 4.x endpoint
  tunnel.jsp              Tomcat/JSP endpoint
  tunnel.asp              Classic ASP compatibility stub

tests/
  e2e.sh                  PHP end-to-end test harness
  echo_server.php         TCP echo target used by tests
  http_policy_probe.php   Endpoint policy checks
  socks_probe.php         SOCKS5 end-to-end probe

dist/
  prebuilt client binaries, when present
```

## Server endpoint support

All functional server implementations use the same bridge protocol and the same actions: `open`, `run`, `send`, and `close`.

| Endpoint | Runtime | Status | State model |
|---|---|---|---|
| `server/tunnel.php` | PHP 8.x | Full | Shared filesystem state, suitable for multiple PHP workers |
| `server/tunnel.ashx` | IIS + ASP.NET 4.x | Full | Shared filesystem state |
| `server/tunnel.aspx` | IIS + ASP.NET 4.x | Full | Shared filesystem state |
| `server/tunnel.jsp` | Tomcat/JSP | Full | In-memory state inside one JVM |
| `server/tunnel.asp` | Classic ASP/VBScript | Stub only | Returns `501 Not Implemented` |

Classic ASP/VBScript does not provide a standard raw TCP socket API comparable to .NET sockets or Java NIO. Use `tunnel.ashx` or `tunnel.aspx` on IIS instead.

## Quick start

### 1. Deploy a server endpoint

Choose one functional endpoint that matches your web stack:

```text
PHP:       server/tunnel.php
ASP.NET:   server/tunnel.ashx
ASP.NET:   server/tunnel.aspx
Tomcat:    server/tunnel.jsp
```

Place it in the corresponding web application and expose it through HTTPS, for example:

```text
https://home.example.com/tunnel.php
```

Before deployment, review the configuration at the top of the selected server file. At minimum:

- use a strong unique token;
- restrict destination CIDRs to networks you actually need;
- restrict destination ports where practical;
- keep HTTPS required;
- only trust `X-Forwarded-Proto` when it is supplied by a trusted reverse proxy that cannot be bypassed.

> **Important before publishing this repository:** never commit a production token. If a real token has ever been committed or pushed, rotate it rather than only deleting it from the latest revision.

### 2. Run the native bridge

Windows:

```powershell
.\socks5-bridge-windows-amd64.exe `
  --endpoint=https://home.example.com/tunnel.php `
  --token="YOUR_SECRET_TOKEN" `
  --listen=127.0.0.1:1080
```

Linux:

```bash
./socks5-bridge-linux-amd64 \
  --endpoint=https://home.example.com/tunnel.php \
  --token="YOUR_SECRET_TOKEN" \
  --listen=127.0.0.1:1080
```

The token may also be supplied through `SOCKS_TUNNEL_TOKEN`:

```bash
export SOCKS_TUNNEL_TOKEN='YOUR_SECRET_TOKEN'
./socks5-bridge-linux-amd64 \
  --endpoint=https://home.example.com/tunnel.php
```

### 3. Point your application at the local SOCKS5 listener

```text
SOCKS5 host: 127.0.0.1
SOCKS5 port: 1080
Authentication: none
```

Example with `curl`:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://192.168.1.10/
```

## Native client options

Run:

```text
socks5-bridge --help
```

Important options:

| Option | Purpose |
|---|---|
| `--endpoint` | Public server endpoint URL; required |
| `--token` | Bridge token; may also come from `SOCKS_TUNNEL_TOKEN` |
| `--listen` | Local SOCKS5 listener, default `127.0.0.1:1080` |
| `--proxy` | Optional HTTP/SOCKS5 proxy used to reach the server endpoint |
| `--http-timeout` | Connect/header timeout in seconds, default `15`, range `1-120` |
| `--allow-remote-listen` | Explicitly permit a non-loopback SOCKS listener |
| `--allow-http` | Permit an `http://` endpoint for local testing |
| `--insecure` | Disable TLS certificate verification for HTTPS testing |

The bridge deliberately ignores system `HTTP_PROXY` / `HTTPS_PROXY` environment variables. Use `--proxy` when an upstream proxy is required.

## Upstream proxy support

The optional upstream proxy applies only to the connection from the native bridge to the public web endpoint.

```text
App -> local SOCKS5 -> bridge -> upstream proxy -> web endpoint -> TCP target
```

HTTP proxy:

```text
--proxy=http://127.0.0.1:8080
```

HTTP proxy with credentials:

```text
--proxy=http://user:password@proxy.example.com:8080
```

SOCKS5:

```text
--proxy=socks5://127.0.0.1:1081
```

SOCKS5 with credentials:

```text
--proxy=socks5://user:password@proxy.example.com:1080
```

`socks5h://` is also accepted. Hostnames are sent to the SOCKS proxy for resolution.

When the endpoint uses HTTPS through an HTTP proxy, the Go HTTP transport uses HTTP `CONNECT` automatically.

## Listening on the LAN

For safety, the bridge refuses to bind a non-loopback address unless the opt-in flag is supplied.

To listen on all interfaces:

```bash
./socks5-bridge-linux-amd64 \
  --endpoint=https://home.example.com/tunnel.php \
  --token="YOUR_SECRET_TOKEN" \
  --listen=0.0.0.0:1080 \
  --allow-remote-listen
```

The local SOCKS5 listener currently uses **NO-AUTH**. If you bind it to `0.0.0.0`, restrict access with the host firewall and do not expose that port directly to the Internet.

## Server deployment notes

### PHP

`tunnel.php` stores tunnel metadata and upstream queues in a temporary state directory so requests handled by different PHP workers can cooperate.

For Nginx + PHP-FPM, disable buffering for the tunnel endpoint and allow the long-running `run` response:

```nginx
location = /tunnel.php {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root/tunnel.php;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;

    fastcgi_buffering off;
    fastcgi_request_buffering off;
    fastcgi_read_timeout 3700s;
    gzip off;
}
```

The PHP-FPM socket path varies by distribution and PHP version.

If TLS terminates directly at Nginx and PHP needs HTTPS detection, pass the HTTPS state to FastCGI according to your deployment. If TLS terminates at a trusted reverse proxy, only enable forwarded-protocol trust when the backend cannot be reached directly with a forged header.

### IIS / ASP.NET

`tunnel.ashx` and `tunnel.aspx` are self-contained ASP.NET 4.x implementations. Deploy one of them inside an ASP.NET application and edit the configuration constants at the top of the file.

The `run` request stays open for the lifetime of the TCP tunnel. Configure an execution timeout longer than the tunnel lifetime, for example:

```xml
<configuration>
  <system.web>
    <httpRuntime executionTimeout="3700" />
  </system.web>
</configuration>
```

If IIS terminates TLS directly, keep forwarded-protocol trust disabled. Enable it only behind a trusted reverse proxy that controls the forwarded protocol header.

### Tomcat / JSP

Copy `server/tunnel.jsp` into a Tomcat web application and edit the configuration constants at the top of the file.

The JSP implementation keeps tunnel state in static in-memory structures. Therefore:

- all requests belonging to one tunnel must reach the same web application JVM;
- application restart/redeploy closes active tunnels;
- multi-node/load-balanced deployments require session affinity or a different shared-state design.

## Build the native client

The Go client uses only the standard library and can be cross-compiled into a standalone executable.

```bash
mkdir -p dist

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/socks5-bridge-windows-amd64.exe ./client

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/socks5-bridge-linux-amd64 ./client

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/socks5-bridge-linux-arm64 ./client

CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/socks5-bridge-macos-arm64 ./client
```

The recipient of these binaries does not need Go, PHP, or another runtime installed locally.

## Protocol overview

Every bridge request is a `POST` to the exact endpoint URL. Protocol parameters are not placed in the query string.

Request body format:

```text
uint32_be metadata_length | metadata JSON | optional raw payload
```

Metadata carries fields such as:

```text
token, action, id, seq, host, port
```

Only the `send` action appends raw TCP payload after the JSON metadata.

The four main actions are:

1. **`open`** — validates authentication, destination policy, DNS/IP, and creates tunnel state.
2. **`run`** — opens the destination TCP socket and keeps a streaming HTTP response alive. Downstream TCP bytes are framed as `uint32_be length + payload`.
3. **`send`** — uploads ordered upstream TCP chunks using a monotonically increasing sequence number.
4. **`close`** — requests tunnel shutdown.

Zero-length downstream frames are heartbeats and contain no application data.

## Security

This project creates a path from a web endpoint to TCP destinations reachable by that server. Treat it as security-sensitive infrastructure.

Before exposing an endpoint publicly:

- use a long, unique token and never commit the production value to Git;
- use HTTPS with a valid certificate;
- keep CIDR and port allowlists as narrow as possible;
- avoid `0.0.0.0/0` and `1-65535` unless you explicitly intend to permit every reachable IPv4 destination and TCP port;
- keep loopback, link-local, multicast, metadata-service, and other sensitive networks blocked unless they are explicitly required;
- enable forwarded-protocol trust only behind a trusted, non-bypassable reverse proxy;
- do not use `--insecure` outside controlled testing;
- keep the local SOCKS listener on loopback unless remote LAN access is required;
- if listening on the LAN, restrict port `1080` with a firewall because the local SOCKS listener has no authentication;
- remember that command-line proxy credentials may be visible to local process inspection tools.

The token is stored inside the HTTP request body rather than the URL, which avoids putting it in normal URL access logs. This does **not** replace TLS and does not protect the token from systems that explicitly log request bodies.

## Testing

Run the Go test suite:

```bash
go test ./client
```

Run the PHP end-to-end harness with the legacy PHP client:

```bash
sh tests/e2e.sh
```

Run the same end-to-end test with a native bridge binary:

```bash
SOCKS_BRIDGE_BIN="$PWD/dist/socks5-bridge-linux-amd64" sh tests/e2e.sh
```

The E2E harness starts a local TCP echo server, a multi-worker PHP HTTP server, the SOCKS bridge, performs policy checks, and transfers binary payloads through concurrent SOCKS sessions.

Expected result:

```text
POLICY_OK
E2E_OK bytes=131072
E2E_OK bytes=65536
E2E_PASS
```

To exercise the native client's upstream proxy path, the test harness also accepts `SOCKS_BRIDGE_PROXY` when `SOCKS_BRIDGE_BIN` is set.

## Operational limitations

- Active tunnels hold a long-running HTTP request open.
- PHP deployments consume one web worker / PHP-FPM child for each active `run` request.
- Reverse proxies, CDNs, WAFs, and hosting providers may enforce request/response timeouts or buffering that break long-lived streaming.
- The JSP server keeps state in one JVM and is not cluster-safe without affinity/shared state.
- Classic ASP is not a functional server implementation in this repository.
- The local bridge supports SOCKS5 CONNECT only; no UDP or BIND.
- IPv6 destination targets are not currently supported by the local SOCKS bridge.

For high-throughput, high-availability, or large multi-user deployments, a dedicated VPN or purpose-built tunnel daemon is usually a better fit than a long-lived web-request transport.

## Responsible use

Use this project only with networks and systems that you own or have explicit permission to access. Do not deploy it as an unauthenticated public proxy.

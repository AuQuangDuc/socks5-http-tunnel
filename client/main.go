package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

const (
	metadataLimit   = 8192
	maxFrameSize    = 1048576
	maxResponseBody = 65536
)

type config struct {
	endpoint          string
	token             string
	listen            string
	proxyURL          *url.URL
	httpTimeout       time.Duration
	allowHTTP         bool
	allowRemoteListen bool
	insecure          bool
}

type tunnelClient struct {
	config config
	http   *http.Client
}

type openResponse struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
}

type target struct {
	host string
	port int
}

type pumpResult struct {
	reason string
	err    error
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "[fatal]", err)
		os.Exit(2)
	}

	client := newTunnelClient(cfg)
	defer client.closeIdleConnections()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := runBridge(ctx, client); err != nil {
		fmt.Fprintln(os.Stderr, "[fatal]", err)
		os.Exit(1)
	}
}

func parseConfig(args []string) (config, error) {
	var cfg config
	var timeoutSeconds int
	var proxyText string

	fs := flag.NewFlagSet("socks5-bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.endpoint, "endpoint", "", "HTTPS URL of tunnel.php")
	fs.StringVar(&cfg.token, "token", os.Getenv("SOCKS_TUNNEL_TOKEN"), "tunnel token (or SOCKS_TUNNEL_TOKEN)")
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:1080", "local SOCKS5 listen address")
	fs.StringVar(&proxyText, "proxy", "", "upstream proxy URL: http:// or socks5://")
	fs.IntVar(&timeoutSeconds, "http-timeout", 15, "HTTP connect/header timeout in seconds")
	fs.BoolVar(&cfg.allowHTTP, "allow-http", false, "permit an http:// endpoint for local testing")
	fs.BoolVar(&cfg.allowRemoteListen, "allow-remote-listen", false, "permit SOCKS listener outside loopback")
	fs.BoolVar(&cfg.insecure, "insecure", false, "disable TLS certificate verification")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s --endpoint=https://home.example.com/tunnel.php --token=SECRET [options]\n\n", fs.Name())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "\nThe local SOCKS5 listener supports CONNECT with NO-AUTH.")
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if cfg.endpoint == "" {
		return cfg, errors.New("--endpoint is required")
	}
	if cfg.token == "" {
		return cfg, errors.New("--token or SOCKS_TUNNEL_TOKEN is required")
	}
	if timeoutSeconds < 1 || timeoutSeconds > 120 {
		return cfg, errors.New("--http-timeout must be between 1 and 120 seconds")
	}
	cfg.httpTimeout = time.Duration(timeoutSeconds) * time.Second

	u, err := url.Parse(cfg.endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return cfg, errors.New("invalid endpoint URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && cfg.allowHTTP) {
		return cfg, errors.New("endpoint must use HTTPS (use --allow-http only for local testing)")
	}
	if cfg.insecure && scheme != "https" {
		return cfg, errors.New("--insecure only applies to HTTPS")
	}
	if proxyText != "" {
		proxyURL, err := parseProxyURL(proxyText)
		if err != nil {
			return cfg, err
		}
		cfg.proxyURL = proxyURL
	}

	host, portText, err := net.SplitHostPort(cfg.listen)
	if err != nil || host == "" {
		return cfg, errors.New("--listen must use IPv4/hostname:port syntax")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return cfg, errors.New("invalid listen port")
	}
	if strings.Contains(host, ":") {
		return cfg, errors.New("--listen currently supports IPv4/hostname addresses only")
	}
	if !cfg.allowRemoteListen && host != "127.0.0.1" && !strings.EqualFold(host, "localhost") {
		return cfg, errors.New("refusing non-loopback SOCKS listener without --allow-remote-listen")
	}

	return cfg, nil
}

func newTunnelClient(cfg config) *tunnelClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = cfg.httpTimeout
	transport.TLSHandshakeTimeout = cfg.httpTimeout
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.insecure} //nolint:gosec -- explicit --insecure opt-in
	if cfg.proxyURL != nil {
		switch strings.ToLower(cfg.proxyURL.Scheme) {
		case "http":
			transport.Proxy = http.ProxyURL(cfg.proxyURL)
		case "socks5", "socks5h":
			transport.DialContext = newSOCKS5DialContext(cfg.proxyURL, cfg.httpTimeout)
		}
	}

	return &tunnelClient{
		config: cfg,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func parseProxyURL(raw string) (*url.URL, error) {
	proxyURL, err := url.Parse(raw)
	if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
		return nil, errors.New("invalid --proxy URL")
	}
	if proxyURL.Fragment != "" || proxyURL.RawQuery != "" || (proxyURL.Path != "" && proxyURL.Path != "/") {
		return nil, errors.New("--proxy URL must not contain path, query, or fragment")
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	case "socks5", "socks5h":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "1080")
		}
		if proxyURL.User != nil {
			username := proxyURL.User.Username()
			password, hasPassword := proxyURL.User.Password()
			if !hasPassword || len(username) < 1 || len(username) > 255 || len(password) < 1 || len(password) > 255 {
				return nil, errors.New("SOCKS5 proxy credentials require username/password of 1-255 bytes each")
			}
		}
	default:
		return nil, errors.New("--proxy supports only http://, socks5://, or socks5h://")
	}

	return proxyURL, nil
}

func newSOCKS5DialContext(proxyURL *url.URL, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	proxyAddress := proxyURL.Host
	username := ""
	password := ""
	useAuth := proxyURL.User != nil
	if useAuth {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}

	return func(ctx context.Context, _ string, address string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("connect SOCKS5 proxy %s: %w", proxyAddress, err)
		}

		deadline := time.Now().Add(timeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetDeadline(deadline)
		if err := socks5ProxyConnect(conn, address, username, password, useAuth); err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
}

func socks5ProxyConnect(conn net.Conn, address, username, password string, useAuth bool) error {
	methods := []byte{0x00}
	if useAuth {
		methods = []byte{0x02}
	}
	if err := writeAll(conn, append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("SOCKS5 greeting: %w", err)
	}

	var methodReply [2]byte
	if _, err := io.ReadFull(conn, methodReply[:]); err != nil {
		return fmt.Errorf("SOCKS5 greeting response: %w", err)
	}
	if methodReply[0] != 0x05 {
		return errors.New("SOCKS5 proxy returned invalid version")
	}
	if methodReply[1] == 0xff {
		return errors.New("SOCKS5 proxy rejected authentication methods")
	}
	if useAuth {
		if methodReply[1] != 0x02 {
			return fmt.Errorf("SOCKS5 proxy selected unexpected auth method 0x%02x", methodReply[1])
		}
		authRequest := make([]byte, 0, 3+len(username)+len(password))
		authRequest = append(authRequest, 0x01, byte(len(username)))
		authRequest = append(authRequest, username...)
		authRequest = append(authRequest, byte(len(password)))
		authRequest = append(authRequest, password...)
		if err := writeAll(conn, authRequest); err != nil {
			return fmt.Errorf("SOCKS5 proxy authentication: %w", err)
		}
		var authReply [2]byte
		if _, err := io.ReadFull(conn, authReply[:]); err != nil {
			return fmt.Errorf("SOCKS5 proxy authentication response: %w", err)
		}
		if authReply[0] != 0x01 || authReply[1] != 0x00 {
			return errors.New("SOCKS5 proxy authentication failed")
		}
	} else if methodReply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 proxy selected unexpected auth method 0x%02x", methodReply[1])
	}

	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 target address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid SOCKS5 target port")
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 0x01)
			request = append(request, ipv4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) < 1 || len(host) > 255 {
			return errors.New("SOCKS5 target hostname must be 1-255 bytes")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT request: %w", err)
	}

	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT response: %w", err)
	}
	if reply[0] != 0x05 {
		return errors.New("SOCKS5 proxy returned invalid CONNECT version")
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 proxy CONNECT failed with code %d", reply[1])
	}

	var addressLength int
	switch reply[3] {
	case 0x01:
		addressLength = 4
	case 0x04:
		addressLength = 16
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return fmt.Errorf("SOCKS5 CONNECT bind address length: %w", err)
		}
		addressLength = int(length[0])
	default:
		return errors.New("SOCKS5 proxy returned invalid bind address type")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT bind address: %w", err)
	}
	return nil
}

func (c *tunnelClient) closeIdleConnections() {
	if transport, ok := c.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func runBridge(ctx context.Context, client *tunnelClient) error {
	listener, err := net.Listen("tcp", client.config.listen)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", client.config.listen, err)
	}
	defer listener.Close()

	log.Printf("[ready] SOCKS5 listening on %s", client.config.listen)
	log.Printf("[ready] tunnel endpoint: %s", client.config.endpoint)
	if client.config.proxyURL != nil {
		log.Printf("[ready] upstream proxy: %s", redactedProxyURL(client.config.proxyURL))
	}
	if client.config.insecure {
		log.Printf("[warning] TLS certificate verification is disabled")
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("accept SOCKS connection: %w", err)
		}

		go handleClient(client, conn)
	}
}

func redactedProxyURL(proxyURL *url.URL) string {
	copyURL := *proxyURL
	if copyURL.User != nil {
		username := copyURL.User.Username()
		if _, hasPassword := copyURL.User.Password(); hasPassword {
			copyURL.User = url.UserPassword(username, "***")
		}
	}
	return copyURL.String()
}

func handleClient(client *tunnelClient, conn net.Conn) {
	peer := conn.RemoteAddr().String()
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	target, err := socksHandshake(conn)
	if err != nil {
		log.Printf("[reject] %s SOCKS handshake: %v", peer, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	id, status, err := client.openTunnel(target)
	if err != nil {
		code := byte(0x01)
		if status == http.StatusForbidden {
			code = 0x02
		}
		_ = socksReply(conn, code)
		log.Printf("[reject] %s -> %s:%d HTTP %d: %v", peer, target.host, target.port, status, err)
		return
	}

	runCtx, cancelRun := context.WithCancel(context.Background())
	runner, err := client.openRunner(runCtx, id)
	if err != nil {
		cancelRun()
		client.bestEffortClose(id)
		_ = socksReply(conn, 0x05)
		log.Printf("[error] %s -> %s:%d target connect failed: %v", peer, target.host, target.port, err)
		return
	}
	defer runner.Close()

	if err := socksReply(conn, 0x00); err != nil {
		cancelRun()
		client.bestEffortClose(id)
		return
	}

	log.Printf("[open] %s -> %s:%d", peer, target.host, target.port)
	results := make(chan pumpResult, 2)
	go func() {
		results <- pumpResult{reason: "local_closed", err: client.pumpUpstream(conn, id)}
	}()
	go func() {
		results <- pumpResult{reason: "remote_closed", err: pumpDownstream(runner, conn)}
	}()

	first := <-results
	cancelRun()
	_ = runner.Close()
	_ = conn.Close()
	client.bestEffortClose(id)

	if first.err != nil && !errors.Is(first.err, io.EOF) && !errors.Is(first.err, net.ErrClosed) && !errors.Is(first.err, context.Canceled) {
		log.Printf("[close] %s -> %s:%d (%s: %v)", peer, target.host, target.port, first.reason, first.err)
		return
	}
	log.Printf("[close] %s -> %s:%d (%s)", peer, target.host, target.port, first.reason)
}

func socksHandshake(conn net.Conn) (target, error) {
	var result target
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return result, err
	}
	if head[0] != 0x05 || head[1] == 0 {
		return result, errors.New("invalid SOCKS5 greeting")
	}

	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return result, err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{0x05, 0xff})
		return result, errors.New("client did not offer NO-AUTH")
	}
	if err := writeAll(conn, []byte{0x05, 0x00}); err != nil {
		return result, err
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return result, err
	}
	if request[0] != 0x05 {
		return result, errors.New("invalid SOCKS5 request version")
	}
	if request[1] != 0x01 {
		_ = socksReply(conn, 0x07)
		return result, errors.New("only CONNECT is supported")
	}

	switch request[3] {
	case 0x01:
		var raw [4]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return result, err
		}
		result.host = net.IP(raw[:]).String()
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return result, err
		}
		if length[0] == 0 {
			_ = socksReply(conn, 0x08)
			return result, errors.New("empty domain name")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return result, err
		}
		result.host = string(raw)
	case 0x04:
		_ = socksReply(conn, 0x08)
		return result, errors.New("IPv6 targets are not supported")
	default:
		_ = socksReply(conn, 0x08)
		return result, errors.New("unsupported address type")
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return result, err
	}
	result.port = int(binary.BigEndian.Uint16(portBytes[:]))
	if result.port == 0 {
		_ = socksReply(conn, 0x01)
		return result, errors.New("invalid target port")
	}

	return result, nil
}

func socksReply(conn net.Conn, code byte) error {
	return writeAll(conn, []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *tunnelClient) openTunnel(target target) (string, int, error) {
	status, body, err := c.request(map[string]any{
		"action": "open",
		"host":   target.host,
		"port":   target.port,
	}, nil)
	if err != nil {
		return "", status, err
	}
	if status != http.StatusCreated {
		return "", status, fmt.Errorf("open returned HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}

	var opened openResponse
	if err := json.Unmarshal(body, &opened); err != nil {
		return "", status, fmt.Errorf("invalid open response: %w", err)
	}
	if len(opened.ID) != 32 {
		return "", status, errors.New("invalid tunnel id in open response")
	}
	for _, ch := range opened.ID {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return "", status, errors.New("invalid tunnel id in open response")
		}
	}
	return opened.ID, status, nil
}

func (c *tunnelClient) openRunner(ctx context.Context, id string) (io.ReadCloser, error) {
	response, err := c.do(ctx, map[string]any{"action": "run", "id": id}, nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, maxResponseBody))
		return nil, fmt.Errorf("run returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return response.Body, nil
}

func (c *tunnelClient) pumpUpstream(conn net.Conn, id string) error {
	buffer := make([]byte, 65536)
	var sequence uint64
	for {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			status, _, err := c.request(map[string]any{
				"action": "send",
				"id":     id,
				"seq":    strconv.FormatUint(sequence, 10),
			}, buffer[:n])
			if err != nil {
				return err
			}
			if status != http.StatusNoContent {
				return fmt.Errorf("send returned HTTP %d", status)
			}
			sequence++
		}
		if readErr != nil {
			return readErr
		}
	}
}

func pumpDownstream(runner io.Reader, conn net.Conn) error {
	var lengthBytes [4]byte
	for {
		if _, err := io.ReadFull(runner, lengthBytes[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(lengthBytes[:])
		if length > maxFrameSize {
			return fmt.Errorf("remote frame too large: %d", length)
		}
		if length == 0 {
			continue
		}

		payload := make([]byte, int(length))
		if _, err := io.ReadFull(runner, payload); err != nil {
			return err
		}
		if err := writeAll(conn, payload); err != nil {
			return err
		}
	}
}

func (c *tunnelClient) request(metadata map[string]any, payload []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.httpTimeout)
	defer cancel()

	response, err := c.do(ctx, metadata, payload)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return response.StatusCode, nil, err
	}
	if len(body) > maxResponseBody {
		return response.StatusCode, nil, errors.New("tunnel response body is too large")
	}
	return response.StatusCode, body, nil
}

func (c *tunnelClient) do(ctx context.Context, metadata map[string]any, payload []byte) (*http.Response, error) {
	body, err := encodeEnvelope(c.config.token, metadata, payload)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0")

	return c.http.Do(request)
}

func encodeEnvelope(token string, metadata map[string]any, payload []byte) ([]byte, error) {
	copyMetadata := make(map[string]any, len(metadata)+1)
	for key, value := range metadata {
		copyMetadata[key] = value
	}
	copyMetadata["token"] = token

	jsonMetadata, err := json.Marshal(copyMetadata)
	if err != nil {
		return nil, err
	}
	if len(jsonMetadata) > metadataLimit {
		return nil, errors.New("tunnel request metadata is too large")
	}

	body := make([]byte, 4+len(jsonMetadata)+len(payload))
	binary.BigEndian.PutUint32(body[:4], uint32(len(jsonMetadata)))
	copy(body[4:], jsonMetadata)
	copy(body[4+len(jsonMetadata):], payload)
	return body, nil
}

func (c *tunnelClient) bestEffortClose(id string) {
	status, _, err := c.request(map[string]any{"action": "close", "id": id}, nil)
	if err != nil || (status != http.StatusNoContent && status != http.StatusNotFound) {
		return
	}
}

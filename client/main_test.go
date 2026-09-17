package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestEncodeEnvelope(t *testing.T) {
	payload := []byte{0x00, 0x01, 0xfe, 0xff}
	body, err := encodeEnvelope("secret", map[string]any{
		"action": "send",
		"id":     "0123456789abcdef0123456789abcdef",
		"seq":    "7",
	}, payload)
	if err != nil {
		t.Fatalf("encodeEnvelope() error = %v", err)
	}
	if len(body) < 4 {
		t.Fatal("encoded body is shorter than metadata length prefix")
	}

	metadataLength := int(binary.BigEndian.Uint32(body[:4]))
	if metadataLength <= 0 || len(body) < 4+metadataLength {
		t.Fatalf("invalid encoded metadata length %d for body size %d", metadataLength, len(body))
	}

	var metadata map[string]any
	if err := json.Unmarshal(body[4:4+metadataLength], &metadata); err != nil {
		t.Fatalf("metadata JSON decode error = %v", err)
	}
	if metadata["token"] != "secret" || metadata["action"] != "send" || metadata["seq"] != "7" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	if got := body[4+metadataLength:]; string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %v want %v", got, payload)
	}
}

func TestParseConfigDefaultsToLoopback(t *testing.T) {
	cfg, err := parseConfig([]string{
		"--endpoint=https://home.example.com/tunnel.php",
		"--token=test-token",
	})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if cfg.listen != "127.0.0.1:1080" {
		t.Fatalf("listen = %q, want loopback default", cfg.listen)
	}
}

func TestParseConfigRejectsRemoteListenByDefault(t *testing.T) {
	_, err := parseConfig([]string{
		"--endpoint=https://home.example.com/tunnel.php",
		"--token=test-token",
		"--listen=0.0.0.0:1080",
	})
	if err == nil {
		t.Fatal("parseConfig() accepted a non-loopback listener without --allow-remote-listen")
	}
}

func TestParseConfigAcceptsProxyURLs(t *testing.T) {
	tests := []struct {
		proxy string
		host  string
	}{
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"http://proxy.example", "proxy.example:80"},
		{"socks5://127.0.0.1:1080", "127.0.0.1:1080"},
		{"socks5h://user:pass@proxy.example", "proxy.example:1080"},
	}

	for _, test := range tests {
		cfg, err := parseConfig([]string{
			"--endpoint=https://home.example.com/tunnel.php",
			"--token=test-token",
			"--proxy=" + test.proxy,
		})
		if err != nil {
			t.Fatalf("parseConfig(%q) error = %v", test.proxy, err)
		}
		if cfg.proxyURL == nil || cfg.proxyURL.Host != test.host {
			t.Fatalf("parseConfig(%q) proxy host = %v, want %q", test.proxy, cfg.proxyURL, test.host)
		}
	}
}

func TestParseConfigRejectsUnsupportedProxy(t *testing.T) {
	_, err := parseConfig([]string{
		"--endpoint=https://home.example.com/tunnel.php",
		"--token=test-token",
		"--proxy=ftp://127.0.0.1:2121",
	})
	if err == nil {
		t.Fatal("parseConfig() accepted unsupported proxy scheme")
	}
}

func TestHTTPProxyConnectsToHTTPSEndpoint(t *testing.T) {
	endpointHit := make(chan struct{}, 1)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		endpointHit <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()

	proxyHit := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		proxyHit <- struct{}{}

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			upstream.Close()
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		defer clientConn.Close()
		defer upstream.Close()
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		done := make(chan struct{}, 1)
		go func() {
			_, _ = io.Copy(upstream, clientConn)
			if tcpConn, ok := upstream.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			}
			done <- struct{}{}
		}()
		_, _ = io.Copy(clientConn, upstream)
		<-done
	}))
	defer proxy.Close()

	proxyURL, err := parseProxyURL(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := newTunnelClient(config{
		endpoint:    endpoint.URL,
		token:       "test-token",
		proxyURL:    proxyURL,
		httpTimeout: 2 * time.Second,
		insecure:    true,
	})
	defer client.closeIdleConnections()

	status, _, err := client.request(map[string]any{"action": "close", "id": "0123456789abcdef0123456789abcdef"}, nil)
	if err != nil {
		t.Fatalf("request through HTTP proxy error = %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("request through HTTP proxy status = %d", status)
	}
	select {
	case <-proxyHit:
	default:
		t.Fatal("HTTP proxy did not receive endpoint request")
	}
	select {
	case <-endpointHit:
	default:
		t.Fatal("endpoint did not receive request forwarded by HTTP proxy")
	}
}

func TestSOCKS5ProxyDialWithAuthentication(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()

	proxyErr := make(chan error, 1)
	go func() {
		conn, acceptErr := proxyListener.Accept()
		if acceptErr != nil {
			proxyErr <- acceptErr
			return
		}
		proxyErr <- serveTestSOCKS5Proxy(conn, targetListener.Addr().String(), "endpoint.test", "proxy-user", "proxy-pass")
	}()

	proxyURL, err := url.Parse("socks5://proxy-user:proxy-pass@" + proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dial := newSOCKS5DialContext(proxyURL, 2*time.Second)
	_, port, _ := net.SplitHostPort(targetListener.Addr().String())
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("endpoint.test", port))
	if err != nil {
		t.Fatalf("SOCKS5 dial error = %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "ping" {
		t.Fatalf("SOCKS5 tunneled reply = %q", reply)
	}
	_ = conn.Close()

	if err := <-proxyErr; err != nil {
		t.Fatalf("test SOCKS5 proxy error = %v", err)
	}
}

func serveTestSOCKS5Proxy(conn net.Conn, targetAddress, expectedHost, expectedUser, expectedPassword string) error {
	defer conn.Close()

	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if greeting[0] != 0x05 || len(methods) != 1 || methods[0] != 0x02 {
		return io.ErrUnexpectedEOF
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return err
	}

	var authHead [2]byte
	if _, err := io.ReadFull(conn, authHead[:]); err != nil {
		return err
	}
	username := make([]byte, int(authHead[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return err
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if authHead[0] != 0x01 || string(username) != expectedUser || string(password) != expectedPassword {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return io.ErrUnexpectedEOF
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return err
	}
	if request[0] != 0x05 || request[1] != 0x01 || request[3] != 0x03 {
		return io.ErrUnexpectedEOF
	}
	var hostLength [1]byte
	if _, err := io.ReadFull(conn, hostLength[:]); err != nil {
		return err
	}
	host := make([]byte, int(hostLength[0]))
	if _, err := io.ReadFull(conn, host); err != nil {
		return err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return err
	}
	if string(host) != expectedHost {
		return io.ErrUnexpectedEOF
	}
	_, targetPortText, _ := net.SplitHostPort(targetAddress)
	targetPort, _ := strconv.Atoi(targetPortText)
	if int(binary.BigEndian.Uint16(portBytes[:])) != targetPort {
		return io.ErrUnexpectedEOF
	}

	upstream, err := net.Dial("tcp", targetAddress)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(conn, upstream)
	<-done
	return nil
}

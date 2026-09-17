#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
STATE_DIR="/tmp/php-socks-tunnel-e2e-$$"
SERVER_ROOT="/tmp/php-socks-server-root-e2e-$$"
SERVER_LOG="/tmp/php-socks-server-e2e-$$.log"
BRIDGE_LOG="/tmp/php-socks-bridge-e2e-$$.log"
ECHO_LOG="/tmp/php-socks-echo-e2e-$$.log"

cleanup() {
    for pid in "${BRIDGE_PID:-}" "${HTTP_PID:-}" "${ECHO_PID:-}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${BRIDGE_PID:-}" "${HTTP_PID:-}" "${ECHO_PID:-}"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$STATE_DIR" "$SERVER_ROOT" "$SERVER_LOG" "$BRIDGE_LOG" "$ECHO_LOG" "${PROBE1:-}" "${PROBE2:-}"
}
trap cleanup EXIT INT TERM

export PHP_CLI_SERVER_WORKERS='4'

mkdir -p "$SERVER_ROOT"
php "$ROOT/tests/make_test_server.php" "$ROOT/server/tunnel.php" "$SERVER_ROOT/tunnel.php" "$STATE_DIR"

php "$ROOT/tests/echo_server.php" 127.0.0.1:19090 >"$ECHO_LOG" 2>&1 &
ECHO_PID=$!

php -S 127.0.0.1:18080 -t "$SERVER_ROOT" >"$SERVER_LOG" 2>&1 &
HTTP_PID=$!

sleep 1

if [ -n "${SOCKS_BRIDGE_BIN:-}" ]; then
	set -- \
		--endpoint=http://127.0.0.1:18080/tunnel.php \
		--token="e2e-test-token" \
		--listen=127.0.0.1:11080 \
		--allow-http
	if [ -n "${SOCKS_BRIDGE_PROXY:-}" ]; then
		set -- "$@" "--proxy=$SOCKS_BRIDGE_PROXY"
	fi
	"$SOCKS_BRIDGE_BIN" "$@" >"$BRIDGE_LOG" 2>&1 &
else
    php "$ROOT/client/socks5-bridge.php" \
        --endpoint=http://127.0.0.1:18080/tunnel.php \
        --token="e2e-test-token" \
        --listen=127.0.0.1:11080 \
        --allow-http >"$BRIDGE_LOG" 2>&1 &
fi
BRIDGE_PID=$!

sleep 1

php "$ROOT/tests/http_policy_probe.php" http://127.0.0.1:18080/tunnel.php "e2e-test-token"

PROBE1="/tmp/php-socks-probe1-e2e-$$.log"
PROBE2="/tmp/php-socks-probe2-e2e-$$.log"
php "$ROOT/tests/socks_probe.php" 127.0.0.1:11080 127.0.0.1 19090 131072 >"$PROBE1" 2>&1 &
PROBE1_PID=$!
php "$ROOT/tests/socks_probe.php" 127.0.0.1:11080 127.0.0.1 19090 65536 >"$PROBE2" 2>&1 &
PROBE2_PID=$!

PROBE_FAILED=0
wait "$PROBE1_PID" || PROBE_FAILED=1
wait "$PROBE2_PID" || PROBE_FAILED=1
cat "$PROBE1"
cat "$PROBE2"
rm -f "$PROBE1" "$PROBE2"

if [ "$PROBE_FAILED" -ne 0 ]; then
    echo '--- server log ---' >&2
    cat "$SERVER_LOG" >&2 || true
    echo '--- bridge log ---' >&2
    cat "$BRIDGE_LOG" >&2 || true
    echo '--- echo log ---' >&2
    cat "$ECHO_LOG" >&2 || true
    exit 1
fi

if grep -F 'tunnel.php?' "$SERVER_LOG" >/dev/null 2>&1; then
    echo 'E2E_FAIL protocol parameters leaked into the request URL' >&2
    cat "$SERVER_LOG" >&2 || true
    exit 1
fi

echo 'E2E_PASS'

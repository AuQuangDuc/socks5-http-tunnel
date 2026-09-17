<?php
declare(strict_types=1);

const TUNNEL_METADATA_LIMIT = 8192;

/*
 * Single-endpoint TCP tunnel for Apache/XAMPP.
 *
 * Every request is POSTed to this exact endpoint URL with no protocol query
 * parameters. Body format: uint32_be metadata length + metadata JSON + raw
 * payload (payload is only used by the send action).
 *
 * Authentication token and action parameters are carried in metadata JSON.
 */

$CONFIG = array(
    'token' => 'CHANGE_ME_BEFORE_PUBLIC_USE',
    'require_https' => true,
    'trust_forwarded_proto' => true,
    'state_dir' => sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'php-socks-tunnel',
    'allowed_cidrs' => array('0.0.0.0/0'),
    'denied_cidrs' => array(),
    'allowed_ports' => array(array(1, 65535)),
    'connect_timeout' => 8,
    'idle_timeout' => 300,
    'max_lifetime' => 3600,
    'max_send_bytes' => 262144,
    'max_pending_bytes' => 1048576,
    'max_tunnels' => 32,
    'heartbeat_seconds' => 5,
);

try {
    bootstrap($CONFIG);
    dispatch($CONFIG);
} catch (Throwable $e) {
    error_log('[php-socks-tunnel] ' . $e->getMessage());
    if (!headers_sent()) {
        respondJson(500, array('error' => 'internal_error'));
    }
}

function dispatch(array $config): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: POST');
        respondJson(405, array('error' => 'method_not_allowed'));
    }

    if ($config['require_https'] && !isHttpsRequest($config['trust_forwarded_proto'])) {
        respondJson(400, array('error' => 'https_required'));
    }

    $envelope = readRequestEnvelope($config);
    $request = $envelope['metadata'];
    $payload = $envelope['payload'];
    authenticate($config['token'], $request);

    $action = isset($request['action']) && is_string($request['action']) ? $request['action'] : '';
    switch ($action) {
        case 'open':
            handleOpen($config, $request);
            return;
        case 'run':
            handleRun($config, $request);
            return;
        case 'send':
            handleSend($config, $request, $payload);
            return;
        case 'close':
            handleClose($config, $request);
            return;
        default:
            respondJson(404, array('error' => 'unknown_action'));
    }
}

function bootstrap(array $config): void
{
    if ($config['token'] === '' || $config['token'] === 'CHANGE_ME_BEFORE_PUBLIC_USE') {
        respondJson(503, array('error' => 'tunnel_token_not_configured'));
    }

    ensureDirectory($config['state_dir']);
}

function handleOpen(array $config, array $request): void
{
    cleanupStaleTunnels($config);
    if (countActiveTunnels($config['state_dir']) >= $config['max_tunnels']) {
        respondJson(429, array('error' => 'too_many_tunnels'));
    }

    $host = isset($request['host']) && is_string($request['host']) ? trim($request['host']) : '';
    $portValue = $request['port'] ?? null;
    $port = is_int($portValue) || (is_string($portValue) && ctype_digit($portValue)) ? (int) $portValue : 0;
    if ($host === '' || $port < 1 || $port > 65535) {
        respondJson(400, array('error' => 'invalid_target'));
    }
    if (!isPortAllowed($port, $config['allowed_ports'])) {
        respondJson(403, array('error' => 'target_port_not_allowed'));
    }

    $ip = resolveAllowedIpv4($host, $config['allowed_cidrs'], $config['denied_cidrs']);
    if ($ip === null) {
        respondJson(403, array('error' => 'target_not_allowed'));
    }

    $id = bin2hex(random_bytes(16));
    $dir = tunnelDir($config['state_dir'], $id);
    $buildDir = $config['state_dir'] . DIRECTORY_SEPARATOR . '.creating-' . $id . '-' . bin2hex(random_bytes(4));
    ensureDirectory($buildDir);

    try {
        ensureDirectory($buildDir . DIRECTORY_SEPARATOR . 'up');

        $now = time();
        writeJsonAtomic($buildDir . DIRECTORY_SEPARATOR . 'meta.json', array(
            'id' => $id,
            'host' => $host,
            'ip' => $ip,
            'port' => $port,
            'created_at' => $now,
            'expires_at' => $now + $config['max_lifetime'],
        ));
        writeJsonAtomic($buildDir . DIRECTORY_SEPARATOR . 'state.json', array(
            'state' => 'opened',
            'updated_at' => $now,
        ));

        if (!@rename($buildDir, $dir)) {
            throw new RuntimeException('cannot publish tunnel state');
        }
    } catch (Throwable $e) {
        removeTree($buildDir);
        throw $e;
    }

    respondJson(201, array(
        'id' => $id,
        'expires_at' => $now + $config['max_lifetime'],
    ));
}

function handleRun(array $config, array $request): void
{
    $id = requireTunnelId($request);
    $dir = tunnelDir($config['state_dir'], $id);
    $meta = readTunnelMeta($dir);
    if ($meta === null) {
        respondJson(404, array('error' => 'tunnel_not_found'));
    }
    if ((int) $meta['expires_at'] <= time()) {
        respondJson(410, array('error' => 'tunnel_expired'));
    }

    $lockPath = $dir . DIRECTORY_SEPARATOR . 'runner.lock';
    $lock = @fopen($lockPath, 'c+b');
    if ($lock === false || !@flock($lock, LOCK_EX | LOCK_NB)) {
        if (is_resource($lock)) {
            fclose($lock);
        }
        respondJson(409, array('error' => 'runner_already_active'));
    }

    $address = 'tcp://' . $meta['ip'] . ':' . (int) $meta['port'];
    $errno = 0;
    $errstr = '';
    $target = @stream_socket_client(
        $address,
        $errno,
        $errstr,
        (float) $config['connect_timeout'],
        STREAM_CLIENT_CONNECT
    );
    if ($target === false) {
        writeTunnelState($dir, 'connect_failed');
        @flock($lock, LOCK_UN);
        fclose($lock);
        respondJson(502, array('error' => 'target_connect_failed'));
    }

    try {
        stream_set_blocking($target, false);
        writeTunnelState($dir, 'running');
        prepareStreamingResponse();

        // Force common buffering layers to release the response before payload arrives.
        echo str_repeat(pack('N', 0), 1024);
        flushOutput();

        ignore_user_abort(true);
        @set_time_limit(0);

        $pendingUpstream = '';
        $lastActivity = microtime(true);
        $lastHeartbeat = microtime(true);
        $lastStateWrite = microtime(true);

        while (true) {
            $now = microtime(true);
            if (file_exists($dir . DIRECTORY_SEPARATOR . 'close.flag')) {
                break;
            }
            if ($now >= (float) $meta['expires_at']) {
                break;
            }
            if (($now - $lastActivity) >= (float) $config['idle_timeout']) {
                break;
            }

            if (strlen($pendingUpstream) < $config['max_pending_bytes']) {
                $loaded = loadUpstreamChunks($dir, $config['max_pending_bytes'] - strlen($pendingUpstream));
                if ($loaded !== '') {
                    $pendingUpstream .= $loaded;
                    $lastActivity = $now;
                }
            }

            $read = array($target);
            $write = $pendingUpstream !== '' ? array($target) : array();
            $except = null;
            $selected = @stream_select($read, $write, $except, 0, 100000);
            if ($selected === false) {
                break;
            }

            if (!empty($write) && $pendingUpstream !== '') {
                $written = @fwrite($target, $pendingUpstream);
                if ($written === false) {
                    break;
                }
                if ($written > 0) {
                    $pendingUpstream = (string) substr($pendingUpstream, $written);
                    $lastActivity = microtime(true);
                }
            }

            if (!empty($read)) {
                $data = @fread($target, 65536);
                if ($data === false) {
                    break;
                }
                if ($data === '' && feof($target)) {
                    break;
                }
                if ($data !== '') {
                    sendFrame($data);
                    $lastActivity = microtime(true);
                }
            }

            $now = microtime(true);
            if (($now - $lastHeartbeat) >= (float) $config['heartbeat_seconds']) {
                sendFrame('');
                $lastHeartbeat = $now;
                if (connection_aborted()) {
                    break;
                }
            }

            if (($now - $lastStateWrite) >= 2.0) {
                writeTunnelState($dir, 'running');
                $lastStateWrite = $now;
            }
        }
    } finally {
        if (is_resource($target)) {
            fclose($target);
        }
        @flock($lock, LOCK_UN);
        fclose($lock);
        writeTunnelState($dir, 'closed');
    }
}

function handleSend(array $config, array $request, string $payload): void
{
    $id = requireTunnelId($request);
    $sequence = requireSendSequence($request);
    $dir = tunnelDir($config['state_dir'], $id);
    $meta = readTunnelMeta($dir);
    if ($meta === null) {
        respondJson(404, array('error' => 'tunnel_not_found'));
    }
    if ((int) $meta['expires_at'] <= time()) {
        respondJson(410, array('error' => 'tunnel_expired'));
    }
    if (file_exists($dir . DIRECTORY_SEPARATOR . 'close.flag')) {
        respondJson(409, array('error' => 'tunnel_closing'));
    }
    $state = readTunnelState($dir);
    if ($state !== 'running') {
        respondJson(409, array('error' => 'tunnel_not_running'));
    }

    if ($payload === '') {
        http_response_code(204);
        exit;
    }

    $upDir = $dir . DIRECTORY_SEPARATOR . 'up';
    ensureDirectory($upDir);
    if (queuedBytes($upDir) + strlen($payload) > $config['max_pending_bytes']) {
        respondJson(429, array('error' => 'upstream_queue_full'));
    }
    $name = str_pad($sequence, 20, '0', STR_PAD_LEFT);
    $tmp = $upDir . DIRECTORY_SEPARATOR . $name . '.tmp';
    $final = $upDir . DIRECTORY_SEPARATOR . $name . '.bin';
    if (file_exists($tmp) || file_exists($final)) {
        respondJson(409, array('error' => 'duplicate_sequence'));
    }
    if (@file_put_contents($tmp, $payload, LOCK_EX) !== strlen($payload) || !@rename($tmp, $final)) {
        @unlink($tmp);
        respondJson(500, array('error' => 'queue_write_failed'));
    }

    http_response_code(204);
    header('Cache-Control: no-store');
    exit;
}

function handleClose(array $config, array $request): void
{
    $id = requireTunnelId($request);
    $dir = tunnelDir($config['state_dir'], $id);
    if (readTunnelMeta($dir) === null) {
        respondJson(404, array('error' => 'tunnel_not_found'));
    }
    @touch($dir . DIRECTORY_SEPARATOR . 'close.flag');
    http_response_code(204);
    header('Cache-Control: no-store');
    exit;
}

function loadUpstreamChunks(string $dir, int $budget): string
{
    if ($budget <= 0) {
        return '';
    }

    $files = glob($dir . DIRECTORY_SEPARATOR . 'up' . DIRECTORY_SEPARATOR . '*.bin');
    if ($files === false || empty($files)) {
        return '';
    }
    sort($files, SORT_STRING);

    $buffer = '';
    foreach ($files as $file) {
        if (strlen($buffer) >= $budget) {
            break;
        }

        $work = substr($file, 0, -4) . '.work';
        if (!@rename($file, $work)) {
            continue;
        }
        $data = @file_get_contents($work);
        @unlink($work);
        if ($data === false || $data === '') {
            continue;
        }

        $room = $budget - strlen($buffer);
        if (strlen($data) <= $room) {
            $buffer .= $data;
            continue;
        }

        $buffer .= substr($data, 0, $room);
        $remainder = substr($data, $room);
        $requeue = dirname($file) . DIRECTORY_SEPARATOR . basename($file, '.bin') . '-r.bin';
        @file_put_contents($requeue, $remainder, LOCK_EX);
        break;
    }
    return $buffer;
}

function prepareStreamingResponse(): void
{
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    @ini_set('zlib.output_compression', '0');
    if (function_exists('apache_setenv')) {
        @apache_setenv('no-gzip', '1');
    }
    header('Content-Type: application/octet-stream');
    header('Cache-Control: no-store, no-cache, must-revalidate, no-transform');
    header('Pragma: no-cache');
    header('X-Accel-Buffering: no');
    header('Content-Encoding: identity');
    header('Connection: close');
    http_response_code(200);
    ob_implicit_flush(true);
}

function sendFrame(string $payload): void
{
    echo pack('N', strlen($payload)), $payload;
    flushOutput();
}

function flushOutput(): void
{
    if (function_exists('ob_flush') && ob_get_level() > 0) {
        @ob_flush();
    }
    @flush();
}

function resolveAllowedIpv4(string $host, array $allowedCidrs, array $deniedCidrs): ?string
{
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ips = array($host);
    } else {
        if (!preg_match('/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/', $host)) {
            return null;
        }
        $resolved = @gethostbynamel($host);
        if ($resolved === false || empty($resolved)) {
            return null;
        }
        $ips = array_values(array_unique($resolved));
    }

    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }
        if (ipMatchesAnyCidr($ip, $deniedCidrs)) {
            return null;
        }
        if (!ipMatchesAnyCidr($ip, $allowedCidrs)) {
            return null;
        }
    }

    return (string) $ips[0];
}

function ipMatchesAnyCidr(string $ip, array $cidrs): bool
{
    foreach ($cidrs as $cidr) {
        if (cidrContains($cidr, $ip)) {
            return true;
        }
    }
    return false;
}

function cidrContains(string $cidr, string $ip): bool
{
    $parts = explode('/', trim($cidr), 2);
    if (count($parts) !== 2) {
        return false;
    }
    $network = @inet_pton($parts[0]);
    $address = @inet_pton($ip);
    $prefix = (int) $parts[1];
    if ($network === false || $address === false || strlen($network) !== 4 || strlen($address) !== 4 || $prefix < 0 || $prefix > 32) {
        return false;
    }

    $fullBytes = intdiv($prefix, 8);
    $remainingBits = $prefix % 8;
    if ($fullBytes > 0 && substr($network, 0, $fullBytes) !== substr($address, 0, $fullBytes)) {
        return false;
    }
    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
    return (ord($network[$fullBytes]) & $mask) === (ord($address[$fullBytes]) & $mask);
}

function isPortAllowed(int $port, array $rules): bool
{
    foreach ($rules as $rule) {
        if ($port >= $rule[0] && $port <= $rule[1]) {
            return true;
        }
    }
    return false;
}

function authenticate(string $expected, array $request): void
{
    $provided = isset($request['token']) && is_string($request['token']) ? $request['token'] : '';

    if ($provided === '' || !hash_equals($expected, $provided)) {
        respondJson(401, array('error' => 'unauthorized'));
    }
}

function isHttpsRequest(bool $trustForwardedProto): bool
{
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if ($trustForwardedProto && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $proto = strtolower(trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
        return $proto === 'https';
    }
    return false;
}

function requireTunnelId(array $request): string
{
    $id = isset($request['id']) && is_string($request['id']) ? strtolower($request['id']) : '';
    if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
        respondJson(400, array('error' => 'invalid_tunnel_id'));
    }
    return $id;
}

function requireSendSequence(array $request): string
{
    $value = $request['seq'] ?? null;
    $sequence = is_int($value) || is_string($value) ? (string) $value : '';
    if (!preg_match('/^(?:0|[1-9][0-9]{0,17})$/', $sequence)) {
        respondJson(400, array('error' => 'invalid_sequence'));
    }
    return $sequence;
}

function readTunnelMeta(string $dir): ?array
{
    $path = $dir . DIRECTORY_SEPARATOR . 'meta.json';
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        return null;
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || !isset($data['ip'], $data['port'], $data['expires_at'])) {
        return null;
    }
    return $data;
}

function readTunnelState(string $dir): ?string
{
    $path = $dir . DIRECTORY_SEPARATOR . 'state.json';
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        return null;
    }
    $data = json_decode($raw, true);
    return is_array($data) && isset($data['state']) ? (string) $data['state'] : null;
}

function writeTunnelState(string $dir, string $state): void
{
    if (!is_dir($dir)) {
        return;
    }
    writeJsonAtomic($dir . DIRECTORY_SEPARATOR . 'state.json', array(
        'state' => $state,
        'updated_at' => time(),
    ));
}

function writeJsonAtomic(string $path, array $data): void
{
    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('json_encode failed');
    }
    $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $json, LOCK_EX) === false || !@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('atomic write failed');
    }
}

function readRequestBody(int $limit): string
{
    $declared = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : null;
    if ($declared !== null && $declared > $limit) {
        respondJson(413, array('error' => 'request_too_large'));
    }
    $body = @file_get_contents('php://input', false, null, 0, $limit + 1);
    if ($body === false) {
        respondJson(400, array('error' => 'request_read_failed'));
    }
    if (strlen($body) > $limit) {
        respondJson(413, array('error' => 'request_too_large'));
    }
    return $body;
}

function readRequestEnvelope(array $config): array
{
    $contentType = isset($_SERVER['CONTENT_TYPE']) ? strtolower(trim(explode(';', (string) $_SERVER['CONTENT_TYPE'], 2)[0])) : '';
    if ($contentType !== 'application/octet-stream') {
        respondJson(415, array('error' => 'unsupported_media_type'));
    }

    $raw = readRequestBody(4 + TUNNEL_METADATA_LIMIT + $config['max_send_bytes']);
    if (strlen($raw) < 4) {
        respondJson(400, array('error' => 'invalid_envelope'));
    }

    $lengthData = unpack('Nlength', substr($raw, 0, 4));
    $metadataLength = is_array($lengthData) && isset($lengthData['length']) ? (int) $lengthData['length'] : 0;
    if ($metadataLength < 2 || $metadataLength > TUNNEL_METADATA_LIMIT || strlen($raw) < 4 + $metadataLength) {
        respondJson(400, array('error' => 'invalid_envelope'));
    }

    $metadataJson = substr($raw, 4, $metadataLength);
    $metadata = json_decode($metadataJson, true);
    if (!is_array($metadata)) {
        respondJson(400, array('error' => 'invalid_metadata'));
    }

    $payload = (string) substr($raw, 4 + $metadataLength);
    $action = isset($metadata['action']) && is_string($metadata['action']) ? $metadata['action'] : '';
    if ($action !== 'send' && $payload !== '') {
        respondJson(400, array('error' => 'unexpected_payload'));
    }
    if ($action === 'send' && strlen($payload) > $config['max_send_bytes']) {
        respondJson(413, array('error' => 'request_too_large'));
    }

    return array('metadata' => $metadata, 'payload' => $payload);
}

function cleanupStaleTunnels(array $config): void
{
    $entries = @scandir($config['state_dir']);
    if ($entries === false) {
        return;
    }
    $now = time();
    foreach ($entries as $entry) {
        if (strncmp($entry, '.creating-', 10) === 0) {
            $buildDir = $config['state_dir'] . DIRECTORY_SEPARATOR . $entry;
            $modified = @filemtime($buildDir);
            if ($modified !== false && (int) $modified + 60 < $now) {
                removeTree($buildDir);
            }
            continue;
        }
        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) {
            continue;
        }
        $dir = tunnelDir($config['state_dir'], $entry);
        $meta = readTunnelMeta($dir);
        $state = readTunnelState($dir);
        if ($meta === null || $state === 'closed' || $state === 'connect_failed' || (int) $meta['expires_at'] + 60 < $now) {
            removeTree($dir);
        }
    }
}

function countActiveTunnels(string $root): int
{
    $entries = @scandir($root);
    if ($entries === false) {
        return 0;
    }
    $count = 0;
    $now = time();
    foreach ($entries as $entry) {
        if (!preg_match('/^[a-f0-9]{32}$/', $entry)) {
            continue;
        }
        $dir = tunnelDir($root, $entry);
        $meta = readTunnelMeta($dir);
        $state = readTunnelState($dir);
        if ($meta !== null && (int) $meta['expires_at'] > $now && ($state === 'opened' || $state === 'running')) {
            $count++;
        }
    }
    return $count;
}

function queuedBytes(string $upDir): int
{
    $files = array();
    foreach (array('*.bin', '*.tmp', '*.work') as $pattern) {
        $matched = glob($upDir . DIRECTORY_SEPARATOR . $pattern);
        if ($matched !== false) {
            $files = array_merge($files, $matched);
        }
    }
    $total = 0;
    foreach ($files as $file) {
        $size = @filesize($file);
        if ($size !== false) {
            $total += (int) $size;
        }
    }
    return $total;
}

function removeTree(string $path): void
{
    if (!is_dir($path)) {
        @unlink($path);
        return;
    }
    $items = @scandir($path);
    if ($items !== false) {
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            removeTree($path . DIRECTORY_SEPARATOR . $item);
        }
    }
    @rmdir($path);
}

function tunnelDir(string $root, string $id): string
{
    return rtrim($root, '/\\') . DIRECTORY_SEPARATOR . $id;
}

function ensureDirectory(string $path): void
{
    if (is_dir($path)) {
        return;
    }
    if (!@mkdir($path, 0700, true) && !is_dir($path)) {
        throw new RuntimeException('cannot create state directory');
    }
}

function respondJson(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}


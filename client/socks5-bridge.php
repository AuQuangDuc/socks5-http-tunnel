<?php
declare(strict_types=1);

const TUNNEL_METADATA_LIMIT = 8192;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This bridge must run with PHP CLI.\n");
    exit(2);
}

$options = getopt('', array(
    'endpoint:',
    'token:',
    'listen:',
    'http-timeout:',
    'allow-http',
    'allow-remote-listen',
    'insecure',
    'help',
));

if (isset($options['help'])) {
    printUsage();
    exit(0);
}

$endpoint = isset($options['endpoint']) ? (string) $options['endpoint'] : '';
$token = isset($options['token']) ? (string) $options['token'] : (string) (getenv('SOCKS_TUNNEL_TOKEN') ?: '');
$listen = isset($options['listen']) ? (string) $options['listen'] : '127.0.0.1:1080';
$httpTimeout = isset($options['http-timeout']) ? (int) $options['http-timeout'] : 15;
$allowHttp = isset($options['allow-http']);
$allowRemoteListen = isset($options['allow-remote-listen']);
$insecure = isset($options['insecure']);

try {
    $config = validateConfig($endpoint, $token, $listen, $httpTimeout, $allowHttp, $allowRemoteListen, $insecure);
    runBridge($config);
} catch (Throwable $e) {
    fwrite(STDERR, '[fatal] ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

function runBridge(array $config): void
{
    $errno = 0;
    $errstr = '';
    $server = @stream_socket_server('tcp://' . $config['listen'], $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
    if ($server === false) {
        throw new RuntimeException('Cannot listen on ' . $config['listen'] . ': ' . $errstr);
    }
    stream_set_blocking($server, false);

    fwrite(STDERR, '[ready] SOCKS5 listening on ' . $config['listen'] . PHP_EOL);
    fwrite(STDERR, '[ready] tunnel endpoint: ' . $config['endpoint'] . PHP_EOL);
    if ($config['insecure']) {
        fwrite(STDERR, "[warning] TLS certificate verification is disabled.\n");
    }

    $sessions = array();

    while (true) {
        $read = array($server);
        $write = array();
        $clientMap = array();

        foreach ($sessions as $key => $session) {
            $read[] = $session['client'];
            $clientMap[(int) $session['client']] = $key;
            if ($session['to_client'] !== '') {
                $write[] = $session['client'];
            }
        }

        $except = null;
        $selectMicros = empty($sessions) ? 200000 : 20000;
        $selected = @stream_select($read, $write, $except, 0, $selectMicros);
        if ($selected === false) {
            usleep(20000);
            continue;
        }

        foreach ($write as $writable) {
            $resourceId = (int) $writable;
            if (!isset($clientMap[$resourceId])) {
                continue;
            }
            $key = $clientMap[$resourceId];
            if (!isset($sessions[$key]) || $sessions[$key]['to_client'] === '') {
                continue;
            }
            $written = @fwrite($sessions[$key]['client'], $sessions[$key]['to_client']);
            if ($written === false) {
                closeSession($sessions, $key, $config, 'local_write_failed');
                continue;
            }
            if ($written > 0) {
                $sessions[$key]['to_client'] = (string) substr($sessions[$key]['to_client'], $written);
            }
        }

        foreach ($read as $readable) {
            if ($readable === $server) {
                acceptClient($server, $sessions, $config);
                continue;
            }

            $resourceId = (int) $readable;
            if (isset($clientMap[$resourceId])) {
                $key = $clientMap[$resourceId];
                if (!isset($sessions[$key])) {
                    continue;
                }
                $data = @fread($sessions[$key]['client'], 65536);
                if ($data === false || ($data === '' && feof($sessions[$key]['client']))) {
                    closeSession($sessions, $key, $config, 'local_closed');
                    continue;
                }
                if ($data !== '') {
                    $sequence = $sessions[$key]['send_sequence'];
                    $sessions[$key]['send_sequence']++;
                    $response = tunnelRequest($config, array(
                        'action' => 'send',
                        'id' => $sessions[$key]['id'],
                        'seq' => (string) $sequence,
                    ), $data);
                    if ($response['status'] !== 204) {
                        closeSession($sessions, $key, $config, 'upstream_send_failed');
                    }
                }
                continue;
            }

        }

        // HTTP/HTTPS wrappers may buffer decoded chunked data internally. On some
        // Apache stacks stream_select() only sees the underlying socket and misses
        // those already-buffered bytes, so runners are polled directly in non-blocking mode.
        foreach (array_keys($sessions) as $key) {
            if (!isset($sessions[$key])) {
                continue;
            }
            $data = @fread($sessions[$key]['runner'], 65536);
            if ($data === false || ($data === '' && feof($sessions[$key]['runner']))) {
                closeSession($sessions, $key, $config, 'remote_closed');
                continue;
            }
            if ($data !== '') {
                $sessions[$key]['frame_buffer'] .= $data;
                if (!consumeFrames($sessions[$key])) {
                    closeSession($sessions, $key, $config, 'invalid_remote_frame');
                }
            }
        }
    }
}

function acceptClient($server, array &$sessions, array $config): void
{
    $peer = '';
    $client = @stream_socket_accept($server, 0, $peer);
    if ($client === false) {
        return;
    }

    stream_set_blocking($client, true);
    stream_set_timeout($client, 10);

    $target = socksHandshake($client);
    if ($target === null) {
        fclose($client);
        return;
    }

    $opened = tunnelRequest($config, array(
        'action' => 'open',
        'host' => $target['host'],
        'port' => $target['port'],
    ));
    if ($opened['status'] !== 201) {
        socksReply($client, $opened['status'] === 403 ? 0x02 : 0x01);
        fclose($client);
        logLine('reject', $peer . ' -> ' . $target['host'] . ':' . $target['port'] . ' HTTP ' . $opened['status']);
        return;
    }

    $openData = json_decode($opened['body'], true);
    $id = is_array($openData) && isset($openData['id']) ? (string) $openData['id'] : '';
    if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
        socksReply($client, 0x01);
        fclose($client);
        return;
    }

    $runner = openRunnerStream($config, $id);
    if ($runner === null) {
        bestEffortClose($config, $id);
        socksReply($client, 0x05);
        fclose($client);
        logLine('error', $peer . ' target connect failed');
        return;
    }

    socksReply($client, 0x00);
    stream_set_blocking($client, false);
    stream_set_blocking($runner, false);

    $key = (int) $client;
    $sessions[$key] = array(
        'id' => $id,
        'client' => $client,
        'runner' => $runner,
        'frame_buffer' => '',
        'frame_length' => null,
        'to_client' => '',
        'send_sequence' => 0,
        'peer' => $peer,
        'target' => $target['host'] . ':' . $target['port'],
    );
    logLine('open', $peer . ' -> ' . $sessions[$key]['target']);
}

function socksHandshake($client): ?array
{
    $head = readExact($client, 2);
    if ($head === null || ord($head[0]) !== 0x05) {
        return null;
    }
    $methodCount = ord($head[1]);
    if ($methodCount < 1) {
        return null;
    }
    $methods = readExact($client, $methodCount);
    if ($methods === null || strpos($methods, "\x00") === false) {
        @fwrite($client, "\x05\xff");
        return null;
    }
    if (!writeAll($client, "\x05\x00")) {
        return null;
    }

    $request = readExact($client, 4);
    if ($request === null || ord($request[0]) !== 0x05) {
        return null;
    }
    if (ord($request[1]) !== 0x01) {
        socksReply($client, 0x07);
        return null;
    }

    $atyp = ord($request[3]);
    if ($atyp === 0x01) {
        $rawHost = readExact($client, 4);
        if ($rawHost === null) {
            return null;
        }
        $host = @inet_ntop($rawHost);
        if ($host === false) {
            return null;
        }
    } elseif ($atyp === 0x03) {
        $lengthRaw = readExact($client, 1);
        if ($lengthRaw === null) {
            return null;
        }
        $length = ord($lengthRaw);
        if ($length < 1) {
            socksReply($client, 0x08);
            return null;
        }
        $host = readExact($client, $length);
        if ($host === null) {
            return null;
        }
    } elseif ($atyp === 0x04) {
        socksReply($client, 0x08);
        return null;
    } else {
        socksReply($client, 0x08);
        return null;
    }

    $portRaw = readExact($client, 2);
    if ($portRaw === null) {
        return null;
    }
    $portData = unpack('nport', $portRaw);
    $port = (int) $portData['port'];
    if ($port < 1) {
        socksReply($client, 0x01);
        return null;
    }

    return array('host' => $host, 'port' => $port);
}

function socksReply($client, int $code): void
{
    writeAll($client, "\x05" . chr($code) . "\x00\x01\x00\x00\x00\x00\x00\x00");
}

function consumeFrames(array &$session): bool
{
    while (true) {
        if ($session['frame_length'] === null) {
            if (strlen($session['frame_buffer']) < 4) {
                return true;
            }
            $lengthData = unpack('Nlength', substr($session['frame_buffer'], 0, 4));
            $session['frame_buffer'] = (string) substr($session['frame_buffer'], 4);
            $length = (int) $lengthData['length'];
            if ($length < 0 || $length > 1048576) {
                return false;
            }
            $session['frame_length'] = $length;
        }

        $length = (int) $session['frame_length'];
        if (strlen($session['frame_buffer']) < $length) {
            return true;
        }

        if ($length > 0) {
            $session['to_client'] .= substr($session['frame_buffer'], 0, $length);
            if (strlen($session['to_client']) > 4194304) {
                return false;
            }
        }
        $session['frame_buffer'] = (string) substr($session['frame_buffer'], $length);
        $session['frame_length'] = null;
    }
}

function openRunnerStream(array $config, string $id)
{
    $body = encodeRequestEnvelope($config, array('action' => 'run', 'id' => $id));
    $context = makeHttpContext($config, $body);
    $stream = @fopen($config['endpoint'], 'rb', false, $context);
    if ($stream === false) {
        return null;
    }

    $status = responseStatus($stream);
    if ($status !== 200) {
        fclose($stream);
        return null;
    }
    return $stream;
}

function tunnelRequest(array $config, array $metadata, string $payload = ''): array
{
    $body = encodeRequestEnvelope($config, $metadata, $payload);
    $context = makeHttpContext($config, $body);
    $stream = @fopen($config['endpoint'], 'rb', false, $context);
    if ($stream === false) {
        return array('status' => 0, 'body' => '');
    }
    $status = responseStatus($stream);
    $responseBody = stream_get_contents($stream);
    fclose($stream);
    return array('status' => $status, 'body' => $responseBody === false ? '' : $responseBody);
}

function encodeRequestEnvelope(array $config, array $metadata, string $payload = ''): string
{
    $metadata['token'] = $config['token'];
    $json = json_encode($metadata, JSON_UNESCAPED_SLASHES);
    if ($json === false || strlen($json) > TUNNEL_METADATA_LIMIT) {
        throw new RuntimeException('Tunnel request metadata is too large');
    }
    return pack('N', strlen($json)) . $json . $payload;
}

function makeHttpContext(array $config, string $body)
{
    $headers = array(
        'Content-Type: application/octet-stream',
        'Content-Length: ' . strlen($body),
        'Connection: close',
        'User-Agent: php-socks-http-bridge/1',
    );

    $options = array(
        'http' => array(
            'method' => 'POST',
            'header' => implode("\r\n", $headers) . "\r\n",
            'content' => $body,
            'timeout' => $config['http_timeout'],
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 0,
            'protocol_version' => 1.1,
        ),
    );

    if ($config['scheme'] === 'https') {
        $options['ssl'] = array(
            'verify_peer' => !$config['insecure'],
            'verify_peer_name' => !$config['insecure'],
            'allow_self_signed' => $config['insecure'],
            'SNI_enabled' => true,
            'peer_name' => $config['host'],
        );
    }

    return stream_context_create($options);
}

function responseStatus($stream): int
{
    $meta = stream_get_meta_data($stream);
    $headers = isset($meta['wrapper_data']) && is_array($meta['wrapper_data']) ? $meta['wrapper_data'] : array();
    $status = 0;
    foreach ($headers as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/i', (string) $header, $m)) {
            $status = (int) $m[1];
        }
    }
    return $status;
}

function closeSession(array &$sessions, int $key, array $config, string $reason): void
{
    if (!isset($sessions[$key])) {
        return;
    }
    $session = $sessions[$key];
    unset($sessions[$key]);

    if (is_resource($session['client'])) {
        @fclose($session['client']);
    }
    if (is_resource($session['runner'])) {
        @fclose($session['runner']);
    }
    bestEffortClose($config, $session['id']);
    logLine('close', $session['peer'] . ' -> ' . $session['target'] . ' (' . $reason . ')');
}

function bestEffortClose(array $config, string $id): void
{
    tunnelRequest($config, array('action' => 'close', 'id' => $id));
}

function readExact($stream, int $length): ?string
{
    $buffer = '';
    while (strlen($buffer) < $length) {
        $chunk = @fread($stream, $length - strlen($buffer));
        if ($chunk === false || $chunk === '') {
            return null;
        }
        $buffer .= $chunk;
    }
    return $buffer;
}

function writeAll($stream, string $data): bool
{
    $offset = 0;
    $length = strlen($data);
    while ($offset < $length) {
        $written = @fwrite($stream, substr($data, $offset));
        if ($written === false || $written === 0) {
            return false;
        }
        $offset += $written;
    }
    return true;
}

function validateConfig(
    string $endpoint,
    string $token,
    string $listen,
    int $httpTimeout,
    bool $allowHttp,
    bool $allowRemoteListen,
    bool $insecure
): array {
    if ($endpoint === '') {
        throw new InvalidArgumentException('--endpoint is required');
    }
    if ($token === '') {
        throw new InvalidArgumentException('--token or SOCKS_TUNNEL_TOKEN is required');
    }
    if (!filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
        throw new RuntimeException('allow_url_fopen must be enabled in client PHP');
    }

    $url = parse_url($endpoint);
    if (!is_array($url) || !isset($url['scheme'], $url['host']) || isset($url['user']) || isset($url['pass']) || isset($url['fragment'])) {
        throw new InvalidArgumentException('Invalid endpoint URL');
    }
    $scheme = strtolower((string) $url['scheme']);
    if ($scheme !== 'https' && !($scheme === 'http' && $allowHttp)) {
        throw new InvalidArgumentException('Endpoint must use HTTPS (use --allow-http only for local testing)');
    }
    if ($insecure && $scheme !== 'https') {
        throw new InvalidArgumentException('--insecure only applies to HTTPS');
    }

    if (!preg_match('/^([^:]+):(\d{1,5})$/', $listen, $m)) {
        throw new InvalidArgumentException('--listen must use IPv4/hostname:port syntax');
    }
    $listenHost = $m[1];
    $listenPort = (int) $m[2];
    if ($listenPort < 1 || $listenPort > 65535) {
        throw new InvalidArgumentException('Invalid listen port');
    }
    if (!$allowRemoteListen && $listenHost !== '127.0.0.1' && strtolower($listenHost) !== 'localhost') {
        throw new InvalidArgumentException('Refusing non-loopback SOCKS listener without --allow-remote-listen');
    }
    if ($httpTimeout < 1 || $httpTimeout > 120) {
        throw new InvalidArgumentException('--http-timeout must be between 1 and 120 seconds');
    }

    return array(
        'endpoint' => $endpoint,
        'token' => $token,
        'listen' => $listen,
        'http_timeout' => $httpTimeout,
        'allow_http' => $allowHttp,
        'insecure' => $insecure,
        'scheme' => $scheme,
        'host' => (string) $url['host'],
    );
}

function logLine(string $kind, string $message): void
{
    fwrite(STDERR, '[' . $kind . '] ' . $message . PHP_EOL);
}

function printUsage(): void
{
    echo <<<'TXT'
Usage:
  php socks5-bridge.php --endpoint=https://home.example.com/tunnel.php --token=SECRET [options]

Options:
  --listen=127.0.0.1:1080   Local SOCKS5 listener (default: 127.0.0.1:1080)
  --http-timeout=15         HTTP connect/header timeout in seconds
  --insecure                Disable TLS certificate verification (testing only)
  --allow-http              Permit an http:// endpoint (local testing only)
  --allow-remote-listen     Permit SOCKS listener outside loopback
  --help                    Show this help

The bridge supports SOCKS5 CONNECT with NO-AUTH on the local listener.
The public tunnel endpoint is authenticated by a token carried inside the POST body metadata.
TXT;
    echo PHP_EOL;
}

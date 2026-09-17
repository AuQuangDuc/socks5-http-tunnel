<?php
declare(strict_types=1);

$endpoint = $argv[1] ?? 'http://127.0.0.1:18080/tunnel.php';
$token = $argv[2] ?? 'e2e-test-token';

$unauthorized = postTunnel($endpoint, '', array('action' => 'open', 'host' => '127.0.0.1', 'port' => 19090));
if ($unauthorized['status'] !== 401) {
    fail('expected 401 without token, got ' . $unauthorized['status'] . ' body=' . $unauthorized['body']);
}

$blockedPort = postTunnel($endpoint, $token, array('action' => 'open', 'host' => '127.0.0.1', 'port' => 19091));
if ($blockedPort['status'] !== 403) {
    fail('expected 403 for disallowed port, got ' . $blockedPort['status'] . ' body=' . $blockedPort['body']);
}

fwrite(STDOUT, "POLICY_OK\n");

function postTunnel(string $url, string $token, array $metadata): array
{
    if ($token !== '') {
        $metadata['token'] = $token;
    }
    $json = json_encode($metadata, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        fail('metadata JSON encode failed');
    }
    $body = pack('N', strlen($json)) . $json;
    $headers = "Content-Type: application/octet-stream\r\nContent-Length: " . strlen($body) . "\r\n";
    $context = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => $headers,
            'content' => $body,
            'ignore_errors' => true,
            'follow_location' => 0,
        ),
    ));
    $stream = @fopen($url, 'rb', false, $context);
    if ($stream === false) {
        fail('HTTP request failed');
    }
    $meta = stream_get_meta_data($stream);
    $body = stream_get_contents($stream);
    fclose($stream);
    $status = 0;
    foreach (($meta['wrapper_data'] ?? array()) as $header) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', (string) $header, $m)) {
            $status = (int) $m[1];
        }
    }
    return array('status' => $status, 'body' => $body === false ? '' : $body);
}

function fail(string $message): void
{
    fwrite(STDERR, 'POLICY_FAIL ' . $message . PHP_EOL);
    exit(1);
}

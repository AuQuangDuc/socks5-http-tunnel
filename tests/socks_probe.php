<?php
declare(strict_types=1);

$socks = $argv[1] ?? '127.0.0.1:11080';
$targetHost = $argv[2] ?? '127.0.0.1';
$targetPort = isset($argv[3]) ? (int) $argv[3] : 19090;
$payloadSize = isset($argv[4]) ? (int) $argv[4] : 131072;

$errno = 0;
$errstr = '';
$socket = @stream_socket_client('tcp://' . $socks, $errno, $errstr, 10);
if ($socket === false) {
    fail('cannot connect to SOCKS bridge: ' . $errstr);
}
stream_set_timeout($socket, 15);

writeAll($socket, "\x05\x01\x00");
$method = readExact($socket, 2);
if ($method !== "\x05\x00") {
    fail('SOCKS method negotiation failed');
}

$ip = @inet_pton($targetHost);
if ($ip === false || strlen($ip) !== 4) {
    fail('probe target must be IPv4');
}
writeAll($socket, "\x05\x01\x00\x01" . $ip . pack('n', $targetPort));
$reply = readExact($socket, 10);
if (strlen($reply) !== 10 || ord($reply[1]) !== 0x00) {
    fail('SOCKS CONNECT failed with code ' . (strlen($reply) >= 2 ? ord($reply[1]) : -1));
}

$payload = random_bytes($payloadSize);
writeAll($socket, $payload);
$echo = readExact($socket, strlen($payload));
if (!hash_equals($payload, $echo)) {
    fail('echo payload mismatch');
}

fclose($socket);
fwrite(STDOUT, "E2E_OK bytes=" . strlen($payload) . PHP_EOL);

function readExact($stream, int $length): string
{
    $buffer = '';
    while (strlen($buffer) < $length) {
        $chunk = fread($stream, $length - strlen($buffer));
        if ($chunk === false || $chunk === '') {
            $meta = stream_get_meta_data($stream);
            fail('unexpected EOF/timeout while reading; timed_out=' . (!empty($meta['timed_out']) ? 'yes' : 'no'));
        }
        $buffer .= $chunk;
    }
    return $buffer;
}

function writeAll($stream, string $data): void
{
    $offset = 0;
    while ($offset < strlen($data)) {
        $written = fwrite($stream, substr($data, $offset));
        if ($written === false || $written === 0) {
            fail('write failed');
        }
        $offset += $written;
    }
}

function fail(string $message): void
{
    fwrite(STDERR, 'E2E_FAIL ' . $message . PHP_EOL);
    exit(1);
}

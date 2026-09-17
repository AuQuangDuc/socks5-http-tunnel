<?php
declare(strict_types=1);

$listen = $argv[1] ?? '127.0.0.1:19090';
$errno = 0;
$errstr = '';
$server = @stream_socket_server('tcp://' . $listen, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if ($server === false) {
    fwrite(STDERR, "echo server failed: {$errstr}\n");
    exit(1);
}
stream_set_blocking($server, false);

$clients = array();
while (true) {
    $read = array_merge(array($server), array_values($clients));
    $write = null;
    $except = null;
    if (@stream_select($read, $write, $except, 1) === false) {
        continue;
    }

    foreach ($read as $stream) {
        if ($stream === $server) {
            $client = @stream_socket_accept($server, 0);
            if ($client !== false) {
                stream_set_blocking($client, false);
                $clients[(int) $client] = $client;
            }
            continue;
        }

        $key = (int) $stream;
        $data = @fread($stream, 65536);
        if ($data === false || ($data === '' && feof($stream))) {
            @fclose($stream);
            unset($clients[$key]);
            continue;
        }
        if ($data === '') {
            continue;
        }

        $offset = 0;
        while ($offset < strlen($data)) {
            $written = @fwrite($stream, substr($data, $offset));
            if ($written === false || $written === 0) {
                @fclose($stream);
                unset($clients[$key]);
                break;
            }
            $offset += $written;
        }
    }
}

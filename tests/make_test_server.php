<?php
declare(strict_types=1);

$source = $argv[1] ?? '';
$destination = $argv[2] ?? '';
$stateDir = $argv[3] ?? '';

if ($source === '' || $destination === '' || $stateDir === '') {
    fwrite(STDERR, "usage: php make_test_server.php SOURCE DESTINATION STATE_DIR\n");
    exit(2);
}

$contents = @file_get_contents($source);
if ($contents === false) {
    fwrite(STDERR, "cannot read source tunnel.php\n");
    exit(1);
}

$config = <<<'PHP'
$CONFIG = array(
    'token' => 'e2e-test-token',
    'require_https' => false,
    'trust_forwarded_proto' => false,
    'state_dir' => __STATE_DIR__,
    'allowed_cidrs' => array('127.0.0.0/8'),
    'denied_cidrs' => array(),
    'allowed_ports' => array(array(19090, 19090)),
    'connect_timeout' => 8,
    'idle_timeout' => 30,
    'max_lifetime' => 120,
    'max_send_bytes' => 262144,
    'max_pending_bytes' => 1048576,
    'max_tunnels' => 32,
    'heartbeat_seconds' => 5,
);
PHP;
$config = str_replace('__STATE_DIR__', var_export($stateDir, true), $config);

$updated = preg_replace('/\$CONFIG = array\(\n.*?\n\);/s', $config, $contents, 1, $count);
if ($updated === null || $count !== 1) {
    fwrite(STDERR, "cannot replace test config block\n");
    exit(1);
}

if (@file_put_contents($destination, $updated) === false) {
    fwrite(STDERR, "cannot write test tunnel.php\n");
    exit(1);
}

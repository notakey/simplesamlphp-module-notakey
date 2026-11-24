<?php

declare(strict_types=1);

use SimpleSAML\Auth;
use SimpleSAML\Logger;
use SimpleSAML\Module\notakey\SspNtkBridge;

header('Content-Type: text/plain');
header('Cache-Control: no-store');

if (!isset($_REQUEST['State'])) {
    echo 'error';
    exit();
}

$stateId = urldecode((string) $_REQUEST['State']);

$state = Auth\State::loadState($stateId, SspNtkBridge::STAGEID);

if (empty($state['notakey:stageOneComplete'])) {
    sleep(10);
    echo 'error';
    exit();
}

try {
    $state['notakey:bridge']->setService($state);
} catch (Exception $e) {
    sleep(10);
    echo 'error';
    Logger::error("Unable to set service " . $e->getMessage());
    exit();
}

$res = false;
if (isset($state['notakey:uuid'])) {
    try {
        $res = $state['notakey:bridge']->queryAuth($state, $state['notakey:uuid']);
    } catch (Exception $e) {
        Logger::error("UUID query failed: " . $e->getMessage());
    }
}

if (!$res) {
    sleep(10);
    echo 'error';
    Logger::error("UUID query error: " . ($state['notakey:uuid'] ?? '(none)'));
    exit();
}

Logger::info("queryAuth response data set to " . json_encode($res));

$status = $state['notakey:bridge']->checkAuthResponse(
    $state,
    $res,
    (string) $state['notakey:uuid'],
    $state['notakey:qrState'] ?? null,
);

Logger::info("UUID {$state['notakey:uuid']} login status $status");

if ($status === 'pending') {
    echo 'noop';
    exit();
}

// auth.php shows the outcome; an invalid request is reported as expired
echo $status === 'invalid' ? 'expired' : $status;
exit();

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

if (!isset($state['notakey:qruuid'])) {
    echo 'noop';
    sleep(2);
    exit();
}

$res = false;
try {
    $res = $state['notakey:bridge']->queryAuth($state, $state['notakey:qruuid']);
} catch (Exception $e) {
    Logger::error("Unable to query auth UUID {$state['notakey:qruuid']}: " . $e->getMessage());
}

if (!$res) {
    sleep(10);
    echo 'error';
    Logger::error("Unable to query auth UUID {$state['notakey:qruuid']}");
    exit();
}

Logger::info("queryAuth response data set to " . json_encode($res));
if (isset($res['response_type']) && $res['response_type'] == 'ApproveRequest') {
    Logger::info("UUID {$state['notakey:qruuid']} login confirmed");
    $state['notakey:bridge']->setAuthState($state, $res);
    $state['notakey:bridge']->setUser($state, $res);

    Auth\State::saveState($state, SspNtkBridge::STAGEID);

    echo 'approved';
    exit();
}

if (isset($res['response_type']) && $res['response_type'] == 'DenyRequest') {
    Logger::info("UUID {$state['notakey:qruuid']} login denied");
    $state['notakey:stageOneComplete'] = false;
    unset($state['notakey:qruuid']);
    Auth\State::saveState($state, SspNtkBridge::STAGEID);
    echo 'denied';
    exit();
}

if (!empty($res['expired'])) {
    Logger::info("UUID {$state['notakey:qruuid']} login expired");
    $state['notakey:stageOneComplete'] = false;
    unset($state['notakey:qruuid']);
    Auth\State::saveState($state, SspNtkBridge::STAGEID);
    echo 'expired';
    exit();
}

echo 'noop';
sleep(2);
exit();

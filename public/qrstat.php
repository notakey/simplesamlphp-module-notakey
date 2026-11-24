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

/** @var SspNtkBridge $bridge */
$bridge = $state['notakey:bridge'];
$uuid = (string) $state['notakey:qruuid'];

$res = false;
$expectedState = null;
try {
    $bridge->setService($state);
    // The callback state this sign-in put in its QR code; the request must carry it
    $expectedState = $bridge->getCallbackState();
    $res = $bridge->queryAuth($state, $uuid);
} catch (Exception $e) {
    Logger::error("Unable to query auth UUID $uuid: " . $e->getMessage());
}

if (!$res) {
    // Forget the id, so that a bogus callback cannot keep this sign-in in an error loop
    unset($state['notakey:qruuid']);
    $state['notakey:stageOneComplete'] = isset($state['notakey:uuid']);
    Auth\State::saveState($state, SspNtkBridge::STAGEID);
    sleep(10);
    echo 'error';
    Logger::error("Unable to query auth UUID $uuid");
    exit();
}

Logger::info("queryAuth response data set to " . json_encode($res));

$status = $bridge->checkAuthResponse($state, $res, $uuid, $expectedState);

if ($status === 'pending') {
    echo 'noop';
    sleep(2);
    exit();
}

unset($state['notakey:qruuid']);

if ($status === 'approved') {
    Logger::info("UUID $uuid login confirmed");
    $res['uuid'] = $uuid;
    $bridge->setAuthState($state, $res);
    // auth.php checks the request again against this state before signing in
    $state['notakey:qrState'] = $expectedState;
    Auth\State::saveState($state, SspNtkBridge::STAGEID);
    echo 'approved';
    exit();
}

Logger::info("UUID $uuid login $status");
$state['notakey:stageOneComplete'] = isset($state['notakey:uuid']);
Auth\State::saveState($state, SspNtkBridge::STAGEID);

if ($status === 'invalid') {
    // not a final status for the page: it keeps waiting for a valid QR sign-in
    echo 'noop';
    exit();
}

echo $status;
exit();

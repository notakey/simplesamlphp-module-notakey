<?php

declare(strict_types=1);

use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Module\notakey\Auth\Source\Process;
use SimpleSAML\Module\notakey\SspNtkBridge;

if (!isset($_REQUEST['State'])) {
    throw new Error\BadRequest('Missing "State" parameter.');
}

$stateId = urldecode((string) $_REQUEST['State']);

$state = Auth\State::loadState($stateId, SspNtkBridge::STAGEID);

if (!empty($state['notakey:stepUpRequired']) && empty($state['notakey:stepupAuthCompleted'])) {
    $state['notakey:bridge']->stepupAuth($state);
    exit();
}

if ($state['notakey:mode'] == 'filter') {
    Auth\ProcessingChain::resumeProcessing($state);
    exit();
}

Process::resume();
exit();

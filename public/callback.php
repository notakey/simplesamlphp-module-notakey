<?php

declare(strict_types=1);

use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Session;

if (!isset($_REQUEST['state'])) {
    throw new Error\BadRequest('Missing "state" parameter.');
}

if (!isset($_REQUEST['uuid'])) {
    throw new Error\BadRequest('Missing "uuid" parameter.');
}

$auth_uuid = urldecode((string) $_REQUEST['uuid']);
$stateParts = explode(':', urldecode((string) $_REQUEST['state']), 3);

if (count($stateParts) !== 3) {
    throw new Error\BadRequest('Invalid "state" parameter.');
}

[$service_id, $auth_state, $session_id] = $stateParts;

$session = Session::getSession($session_id);

if (is_null($session)) {
    throw new Error\BadRequest('Session cannot be initialized');
}

$state_str = $session->getData('\SimpleSAML\Auth\State', $auth_state);

if (!is_string($state_str)) {
    throw new Error\BadRequest('State cannot be initialized');
}

$state = unserialize($state_str);

if (!is_array($state) || !isset($state['notakey:bridge']) || !is_object($state['notakey:bridge'])) {
    throw new Error\BadRequest('State cannot be unserialized');
}

$state['notakey:bridge']->setService($state, $service_id);
$state['notakey:stageOneComplete'] = true;
$state['notakey:qruuid'] = $auth_uuid;

$state_str = serialize($state);
$session->setData('\SimpleSAML\Auth\State', $state[Auth\State::ID], $state_str);

http_response_code(204);
exit();

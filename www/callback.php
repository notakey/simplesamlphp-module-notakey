<?php

if (!isset($_REQUEST['state'])) {
    throw new  \SimpleSAML\Error\BadRequest('Missing "state" parameter.');
}

if (!isset($_REQUEST['uuid'])) {
    throw new  \SimpleSAML\Error\BadRequest('Missing "uuid" parameter.');
}

$auth_uuid = urldecode($_REQUEST['uuid']);
list($service_id, $auth_state, $session_id) = explode(':', urldecode($_REQUEST['state']), 3);

$session = \SimpleSAML\Session::getSession($session_id);

if (is_null($session)) {
    throw new  \SimpleSAML\Error\BadRequest('Session cannot be initialized');
}

$state_str = $session->getData(' \SimpleSAML\Auth\State', $auth_state);

if (is_null($state_str)) {
    throw new  \SimpleSAML\Error\BadRequest('State cannot be initialized');
}

$state = unserialize($state_str);

if ($state === false || !is_object($state['notakey:bridge'])) {
    throw new  \SimpleSAML\Error\BadRequest('State cannot be unserialized');
}

$state['notakey:bridge']->setService($state, $service_id);
$state['notakey:stageOneComplete'] = true;
$state['notakey:qruuid'] = $auth_uuid;

$state_str = serialize($state);
$session->setData(' \SimpleSAML\Auth\State', $state[\SimpleSAML\Auth\State::ID], $state_str);



/// validation code


header("HTTP/1.0 204 No Content");
exit();

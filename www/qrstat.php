<?php

$loginProcedureExpired = false;
$badUserPass = false;
$authRequestDenied = false;
$apiTestOK = false;


$stateId = urldecode($_REQUEST['State']);

if (!isset($_REQUEST['State'])) {
	echo 'error';
	throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$service_id = intval($_REQUEST['service_id']);

SimpleSAML\Logger::info("StateID set to $stateId");

$sid = SimpleSAML_Auth_State::parseStateID($stateId);

SimpleSAML\Logger::info("SID data set to ".json_encode($sid));

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
//var_dump($state);

if(!isset($state['notakey:qruuid'])){
    sleep(1);
    SimpleSAML\Logger::info("No UUID in state");
	echo 'noop';
	exit();
}

if(!($res = $state['notakey:bridge']->queryAuth($state['notakey:qruuid']))){
	sleep(1);
	echo 'error';
	exit();
}

SimpleSAML\Logger::info("queryAuth response data set to ".print_r($res, true));
if(isset($res['response_type']) && $res['response_type'] == 'ApproveRequest'){
    SimpleSAML\Logger::info("UUID {$state['notakey:uuid']} login confirmed");
    $state['notakey:bridge']->setAuthState($state, $res);
    $state['notakey:bridge']->setUser($state, $res);

    SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);

	echo 'approved';
	exit();
}

if(isset($res['response_type']) && $res['response_type'] == 'DenyRequest'){
	echo 'denied';
	exit();
}

if($res['expired']){
	echo 'expired';
	exit();
}

echo 'noop';
sleep(1);
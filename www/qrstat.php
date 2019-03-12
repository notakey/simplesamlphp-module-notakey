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

// SimpleSAML\Logger::debug("StateID set to $stateId");

$sid = SimpleSAML_Auth_State::parseStateID($stateId);

// SimpleSAML\Logger::debug("SID data set to ".json_encode($sid));

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
//var_dump($state);

if(!isset($state['notakey:qruuid'])){
    // sleep(2);
    // SimpleSAML\Logger::debug("No UUID in state");
    echo 'noop';
    sleep(2);
	exit();
}

if(!($res = $state['notakey:bridge']->queryAuth($state['notakey:qruuid']))){
	sleep(10);
    echo 'error';
    SimpleSAML\Logger::error("Unable to query auth UUID {$state['notakey:qruuid']}");
	exit();
}

SimpleSAML\Logger::info("queryAuth response data set to ".json_encode($res, true));
if(isset($res['response_type']) && $res['response_type'] == 'ApproveRequest'){
    SimpleSAML\Logger::info("UUID {$state['notakey:qruuid']} login confirmed");
    $state['notakey:bridge']->setAuthState($state, $res);
    $state['notakey:bridge']->setUser($state, $res);

    SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);

	echo 'approved';
	exit();
}

if(isset($res['response_type']) && $res['response_type'] == 'DenyRequest'){
    SimpleSAML\Logger::info("UUID {$state['notakey:qruuid']} login denied");
    $state['notakey:stageOneComplete'] = false;
    unset($state['notakey:qruuid']);
    SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);
    echo 'denied';
	exit();
}

if($res['expired']){
    SimpleSAML\Logger::info("UUID {$state['notakey:qruuid']} login expired");
    $state['notakey:stageOneComplete'] = false;
    unset($state['notakey:qruuid']);
    SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);
    echo 'expired';
	exit();
}

echo 'noop';
sleep(2);
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

SimpleSAML\Logger::info("StateID set to $stateId");

$sid = SimpleSAML_Auth_State::parseStateID($stateId);

SimpleSAML\Logger::info("SID data set to ".json_encode($sid));

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
// var_dump($state);


if(!isset($state['notakey:stageOneComplete']) || !$state['notakey:stageOneComplete']) {
	sleep(1);
	echo 'error';
	// throw new SimpleSAML_Error_BadRequest('Invalid auth stage.');
	exit();
}

try {
	$state['notakey:bridge']->setService($state);
} catch (Exception $e){
	sleep(5);
    echo 'error';
	SimpleSAML\Logger::error("Unable to set service ".$e->getMessage());
	exit();
}


if(!isset($state['notakey:uuid']) || !($res = $state['notakey:bridge']->queryAuth($state['notakey:uuid']))){
	sleep(5);
    echo 'error';
    SimpleSAML\Logger::error("UUID query error: {$state['notakey:uuid']}");
	exit();
}

SimpleSAML\Logger::info("queryAuth response data set to ".json_encode($res));
if(isset($res['response_type']) && $res['response_type'] == 'ApproveRequest'){
    echo 'approved';
    SimpleSAML\Logger::info("UUID {$state['notakey:uuid']} login confirmed");
	exit();
}

if(isset($res['response_type']) && $res['response_type'] == 'DenyRequest'){
    echo 'denied';
	SimpleSAML\Logger::info("UUID {$state['notakey:uuid']} login denied");
	exit();
}

if($res['expired']){
    echo 'expired';
    SimpleSAML\Logger::info("UUID {$state['notakey:uuid']} login expired");
	exit();
}

echo 'noop';
sleep(1);

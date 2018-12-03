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
	sleep(1);
	echo 'error'.' '.$e->getMessage() ;
	exit();
}


if(!($res = $state['notakey:bridge']->queryAuth($state['notakey:uuid']))){
	sleep(1);
	echo 'error';
	exit();
}

SimpleSAML\Logger::info("queryAuth response data set to ".json_encode($res));
if(isset($res['response_type']) && $res['response_type'] == 'ApproveRequest'){
	SimpleSAML\Logger::info("UUID {$state['notakey:uuid']} login confirmed");
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

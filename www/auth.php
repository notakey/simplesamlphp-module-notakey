<?php

if (!isset($_REQUEST['ReturnTo'])) {
	throw new SimpleSAML_Error_BadRequest('Missing "ReturnTo" parameter.');
}

if (!isset($_REQUEST['State'])) {
	throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$authstate = 'pending';
$apiTestOK = true;
$warning_messages = array();
$service_id = null;
$username = '';
$remember = '';

$returnTo = SimpleSAML\Utils\HTTP::checkURLAllowed($_REQUEST['ReturnTo']);

SimpleSAML\Logger::info("ReturnTo URL verified");

$stateId = urldecode($_REQUEST['State']);

// SimpleSAML\Logger::info("StateID set to $stateId");

$sid = SimpleSAML_Auth_State::parseStateID($stateId);

SimpleSAML\Logger::info("SID data set to ".json_encode($sid));

if (!is_null($sid['url'])) {
	SimpleSAML\Utils\HTTP::checkURLAllowed($sid['url']);
    SimpleSAML\Logger::info("URL set to {$sid['url']}");
}

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
// var_dump($state);

$state['notakey:stageOneComplete'] = (isset($state['notakey:stageOneComplete']))?$state['notakey:stageOneComplete']:false;
$username = $state['notakey:bridge']->getRememberUsername();

// Username has been submitted
if(isset($state['notakey:stageOneComplete']) && $state['notakey:stageOneComplete']) {
	try {
		$state['notakey:bridge']->setService($state);
	} catch (Exception $e){
		$warning_messages[] = $e->getMessage();
	}

	SimpleSAML\Logger::info("Querying API for response status");
	if($res = $state['notakey:bridge']->queryAuth($state['notakey:uuid'])){
		// SimpleSAML\Logger::info("queryAuthApi response data set to ".print_r($res, true));
		if(isset($res['response_type']) && $res['response_type'] == 'ApproveRequest'){
			SimpleSAML\Logger::info("API request UUID {$state['notakey:uuid']} login OK");

			$state['notakey:bridge']->setUser($state, $res);
			$stateId = SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);
			SimpleSAML\Utils\HTTP::redirectTrustedURL($returnTo);
			$authstate = 'success';
		}

		if(isset($res['response_type']) && $res['response_type'] == 'DenyRequest'){
			SimpleSAML\Logger::info("API request UUID {$state['notakey:uuid']} denied login");
			$warning_messages[] = 'Authentication request denied by user, please try again.';
			$state['notakey:stageOneComplete'] = false;
			$authstate = 'denied';
		}

		if($res['expired']){
			SimpleSAML\Logger::info("API request UUID {$state['notakey:uuid']} expired");
			$warning_messages[] = 'Authentication procedure expired, please try again.';
			$state['notakey:stageOneComplete'] = false;
			$authstate = 'expired';
		}
	}else{
		SimpleSAML\Logger::info("API request UUID {$state['notakey:uuid']} error");
		$warning_messages[] = 'Authentication procedure expired, please try again.';
		$state['notakey:stageOneComplete'] = false;
		$authstate = 'expired';
	}
}

// We are in a filter mode and only one endpoint exists

if ($state['notakey:mode'] == 'filter' && count($state['notakey:bridge']->getServices()) == 1 && $authstate == 'pending') {
	SimpleSAML\Logger::info("Auto submitting auth request in filter mode");
	$sv_list = array_keys($state['notakey:bridge']->getServices());
	$service_id = array_pop($sv_list);
	$username = $state['notakey:bridge']->getUserId($state);
	if($state['notakey:bridge']->isRememberMeEnabled() && $state['notakey:bridge']->isRememberMeChecked()){
		$remember = 'yes';
	}
}

// We get a form submission

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	SimpleSAML\Logger::info("Processing login request");
	$username = (string)$_REQUEST['username'];
	$service_id = isset($_REQUEST['service_id'])?$_REQUEST['service_id']:null;
	if(isset($_REQUEST['remember_me']))
		$remember = (string)$_REQUEST['remember_me'];
}

if($username != '' && !is_null($service_id)){
	try {
		$state['notakey:bridge']->setService($state, $service_id);
	} catch (Exception $e){
		$warning_messages[] = $e->getMessage();
		$apiTestOK = false;
	}

	sspmod_notakey_SspNtkBridge::d(__FILE__.":".__LINE__." setService selected $service_id");
	$req = null;
	if($apiTestOK){
		try {
			$req = $state['notakey:bridge']->startAuth($username, $state, $remember);
		} catch (Exception $e){
			$warning_messages[] = $e->getMessage();
		}
	}

	sspmod_notakey_SspNtkBridge::d(__FILE__.":".__LINE__." Auth request created");

	if($req){
		// start new session token if auth request proceeds
		$stateId = SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);
	}
}

$config = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($config, 'notakey:auth.tpl.php');

$t->data['state'] = $state;
$t->data['js_block'] = "";
// $t->data['jquery'] = array('version' => '1.8', 'core' => 1);
$t->data['jquery'] = array('core' => TRUE, 'ui' => TRUE, 'css' => TRUE);

$base_url = SimpleSAML\Utils\HTTP::getBaseURL();

$t->data['js_qr_check'] = '<script type="text/javascript">

    function getQrAuthProgress(){
        $.ajax({
            url: \''.$base_url.'module/notakey/qrstat?State='.urlencode($stateId).'&service_id=0\',
            success: function(data) {
                // $("#progress").html(data);
                if(data == "approved" || data == "denied" || data == "expired") {
                    location.href = \''.$base_url.'module/notakey/auth?State='.urlencode($stateId).'&ReturnTo=' . urlencode($returnTo).'\';
                        return;
                }
                getQrAuthProgress();
            },
            error: function (err) {
                console.log("AJAX error in request: " + JSON.stringify(err, null, 2));
                location.href = \''.$base_url.'module/notakey/auth?State='.urlencode($stateId).'&ReturnTo=' . urlencode($returnTo).'\';
            }
        });
    }

    getQrAuthProgress();
</script>';

if($state['notakey:stageOneComplete']){
		$t->data['js_block'] = $t->data['js_block'].'<script type="text/javascript">

		    function getProgress(){
		        $.ajax({
		            url: \''.$base_url.'module/notakey/status?State='.urlencode($stateId).'\',
		            success: function(data) {
		                // $("#progress").html(data);
		                if(data == "approved" || data == "denied" || data == "expired") {
		                	location.href = \''.$base_url.'module/notakey/auth?State='.urlencode($stateId).'&ReturnTo=' . urlencode($returnTo).'\';
		                  	return;
		                }
		               	getProgress();
		            },
		            error: function (err) {
		                console.log("AJAX error in request: " + JSON.stringify(err, null, 2));
		                location.href = \''.$base_url.'module/notakey/auth?State='.urlencode($stateId).'&ReturnTo=' . urlencode($returnTo).'\';
		            }
		        });

		    }

		    getProgress();
		</script>';
}

$t->data['auth_state'] = $authstate;
$t->data['state_id'] = $stateId;
$t->data['return_to'] = $returnTo;
$t->data['service_list'] = $state['notakey:bridge']->getServices();
$t->data['warning_messages'] = $warning_messages;
$t->data['sel_service'] = $service_id;
$t->data['sel_user'] = $username;
$t->data['qr_link'] = $base_url."module/notakey/qr?State=".urlencode($stateId)."&service_id=0";

if (array_key_exists('forcedUsername', $state)) {
	$t->data['sel_user'] = $state['forcedUsername'];
}

$t->data['rememberMeEnabled'] = $state['notakey:bridge']->isRememberMeEnabled();
$t->data['rememberMeChecked'] = $state['notakey:bridge']->isRememberMeChecked();

// TODO
// Add error code display in template
// $t->data['errorcode'] = $errorCode;
// $t->data['errorcodes'] = SimpleSAML\Error\ErrorCodes::getAllErrorCodeMessages();
// $t->data['errorparams'] = $errorParams;

$t->show();




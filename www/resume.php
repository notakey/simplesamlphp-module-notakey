<?php

if (!isset($_REQUEST['State'])) {
	throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
// var_dump($state);


if($state['notakey:stepUpRequired'] && !$state['notakey:stepupAuthCompleted']){
    $state['notakey:bridge']->stepupAuth($state);
    assert ( 'FALSE' );
}

if($state['notakey:mode'] == 'filter'){
	SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
	assert ( 'FALSE' );
}

sspmod_notakey_Auth_Source_Process::resume();
assert ( 'FALSE' );
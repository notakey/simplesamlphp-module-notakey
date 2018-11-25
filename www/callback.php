<?php

if (!isset($_REQUEST['State'])) {
	throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
// var_dump($state);

if($state['notakey:mode'] == 'filter'){
	SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
	assert ( 'FALSE' );
}

sspmod_notakey_Auth_Source_Process::resume();
assert ( 'FALSE' );

/**
 *
 *     @session_request = query_auth_by_uuid params.require(:uuid), params.require(:state)

    return render plain: "No Content", :status => 204 if @session_request
    return render plain: "Request not found", :status => 400
 */
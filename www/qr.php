<?php

if (!isset($_REQUEST['State'])) {
	throw new SimpleSAML_Error_BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);
$service_id = intval($_REQUEST['service_id']);

$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
$endpoint = $state['notakey:bridge']->getService($service_id);

$query = array();

$query['a'] = "a";
$query['k'] = $endpoint['service_id'];

$base_url = SimpleSAML\Utils\HTTP::getBaseURL();
$query['c'] = $base_url."module/notakey/callback";

list($state_id, $session_data) = explode(":", $stateId, 2);
$session = SimpleSAML_Session::getSessionFromRequest();

assert('!is_null($$session)');

$query['s'] = $service_id.':'.$state_id.':'.$session->getSessionId();

$query['m'] = sspmod_notakey_SspNtkBridge::auth_action;
$query['d'] = "Proceed with login to ".$endpoint['name'].'?';
$query['t'] = 600;

// var_dump($session);

QRcode::png('notakey://qr?'.http_build_query($query), false, QR_ECLEVEL_H, 9, 0);


/*
def qr_code( root_url, session_id )
    params = {
      a: "a",
      k: DashboardClient.access_id,
      s: session_id,
      c: "#{root_url}auth/callback",
      m: DashboardClient.action,
      d: DashboardClient.description,
      t: 600
    }.to_query.gsub("+", "%20")

    qr_string = "notakey://qr?#{params}"
    puts "INFO: QR is: #{qr_string}"
    qr_string
  end

  // $sid = explode(":", $stateId, 2);
  // $session = SimpleSAML_Session::getSessionFromRequest();
  // $state = $session->getData('SimpleSAML_Auth_State', $sid['id']);


*/
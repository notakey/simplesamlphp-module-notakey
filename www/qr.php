<?php

if (!isset($_REQUEST['State'])) {
    throw new  \SimpleSAML\Error\BadRequest('Missing "State" parameter.');
}

$stateId = urldecode($_REQUEST['State']);
$service_id = intval($_REQUEST['service_id']);

$state =  \SimpleSAML\Auth\State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);
$state['notakey:bridge']->setService($state, $service_id);
$endpoint = $state['notakey:bridge']->getService($service_id);

$query = array();

$query['a'] = "a";
$query['k'] = $endpoint['service_id'];

$query['s'] = $state['notakey:bridge']->getCallbackState();

if (isset($endpoint['profile_id'])) {
    $query['p'] = $endpoint['profile_id'];
} else {
    $base_url = SimpleSAML\Utils\HTTP::getBaseURL();
    $query['c'] = $base_url . "module/notakey/callback";

    $query['m'] = sspmod_notakey_SspNtkBridge::auth_action;
    $query['d'] = $state['notakey:bridge']->parseAuthMessage("Proceed with login to " . $endpoint['name'] . '?');
    $query['t'] = 600;
}

// var_dump($session);

QRcode::png('notakey://qr?' . http_build_query($query), false, QR_ECLEVEL_H, 9, 0);


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
  // $session = \SimpleSAML\Session::getSessionFromRequest();
  // $state = $session->getData(' \SimpleSAML\Auth\State', $sid['id']);


*/

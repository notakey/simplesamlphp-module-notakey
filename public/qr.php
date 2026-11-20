<?php

declare(strict_types=1);

use chillerlan\QRCode\Common\EccLevel;
use chillerlan\QRCode\Output\QRGdImagePNG;
use chillerlan\QRCode\QRCode;
use chillerlan\QRCode\QROptions;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Module\notakey\SspNtkBridge;

if (!isset($_REQUEST['State'])) {
    throw new Error\BadRequest('Missing "State" parameter.');
}

$stateId = urldecode((string) $_REQUEST['State']);
$service_id = intval($_REQUEST['service_id'] ?? 0);

$state = Auth\State::loadState($stateId, SspNtkBridge::STAGEID);
$state['notakey:bridge']->setService($state, $service_id);
$endpoint = $state['notakey:bridge']->getService($service_id);

$query = [];

$query['a'] = "a";
$query['k'] = $endpoint['service_id'];

$query['s'] = $state['notakey:bridge']->getCallbackState();

if (!empty($endpoint['profile_id'])) {
    $query['p'] = $endpoint['profile_id'];
} else {
    $query['c'] = Module::getModuleURL('notakey/callback.php');
    $query['m'] = SspNtkBridge::AUTH_ACTION;
    $query['d'] = $state['notakey:bridge']->parseAuthMessage("Proceed with login to " . $endpoint['name'] . '?');
    $query['t'] = 600;
}

$options = new QROptions([
    'outputInterface' => QRGdImagePNG::class,
    'outputBase64' => false,
    'eccLevel' => EccLevel::H,
    'scale' => 9,
    'addQuietzone' => false,
]);

header('Content-Type: image/png');
header('Cache-Control: no-store');
echo (new QRCode($options))->render('notakey://qr?' . http_build_query($query));
exit();

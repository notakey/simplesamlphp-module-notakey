<?php


// $stateId = urldecode($_REQUEST['State']);

// $state = SimpleSAML_Auth_State::loadState($stateId, sspmod_notakey_SspNtkBridge::STAGEID);

QRcode::png('https://github.com/ziplr/php-qr-code', false, QR_ECLEVEL_H, 9, 0);
<?php

declare(strict_types=1);

use Detection\MobileDetect;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\notakey\SspNtkBridge;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

if (!isset($_REQUEST['ReturnTo'])) {
    throw new Error\BadRequest('Missing "ReturnTo" parameter.');
}

if (!isset($_REQUEST['State'])) {
    throw new Error\BadRequest('Missing "State" parameter.');
}

$httpUtils = new Utils\HTTP();

$authstate = 'none';
$apiTestOK = true;
$warning_messages = [];
$service_id = null;
$username = '';
$remember = '';

$returnTo = $httpUtils->checkURLAllowed((string) $_REQUEST['ReturnTo']);

Logger::debug("ReturnTo URL verified");

$stateId = urldecode((string) $_REQUEST['State']);

$sid = Auth\State::parseStateID($stateId);

Logger::debug("SID data set to " . json_encode($sid));

if (!is_null($sid['url'])) {
    $httpUtils->checkURLAllowed($sid['url']);
    Logger::debug("URL set to {$sid['url']}");
}

$state = Auth\State::loadState($stateId, SspNtkBridge::STAGEID);

/** @var \SimpleSAML\Module\notakey\SspNtkBridge $bridge */
$bridge = $state['notakey:bridge'];

$state['notakey:stageOneComplete'] = $state['notakey:stageOneComplete'] ?? false;
$username = $bridge->getRememberUsername();

// Username has been submitted
if ($state['notakey:stageOneComplete'] && isset($state['notakey:uuid'])) {
    try {
        $bridge->setService($state);
    } catch (Exception $e) {
        $warning_messages[] = $e->getMessage();
    }

    $authstate = 'pending';

    Logger::info("Querying API for response status");
    $res = false;
    try {
        $res = $bridge->queryAuth($state, $state['notakey:uuid']);
    } catch (Exception $e) {
        Logger::warning("API request UUID {$state['notakey:uuid']} query failed: " . $e->getMessage());
    }

    if ($res) {
        if (isset($res['response_type']) && $res['response_type'] == 'ApproveRequest') {
            Logger::info("API request UUID {$state['notakey:uuid']} login OK");

            $bridge->setUser($state, $res);
            $stateId = Auth\State::saveState($state, SspNtkBridge::STAGEID);
            $httpUtils->redirectTrustedURL($returnTo);
        }

        if (isset($res['response_type']) && $res['response_type'] == 'DenyRequest') {
            Logger::info("API request UUID {$state['notakey:uuid']} denied login");
            $warning_messages[] = 'Authentication request denied by user, please try again.';
            $state['notakey:stageOneComplete'] = false;
            $authstate = 'denied';
        }

        if (!empty($res['expired'])) {
            Logger::info("API request UUID {$state['notakey:uuid']} expired");
            $warning_messages[] = 'Authentication procedure expired, please try again.';
            $state['notakey:stageOneComplete'] = false;
            $authstate = 'expired';
        }
    } else {
        Logger::info("API request UUID {$state['notakey:uuid']} error");
        $warning_messages[] = 'Authentication procedure expired, please try again.';
        $state['notakey:stageOneComplete'] = false;
        $authstate = 'expired';
    }
}

// We are in a filter mode and only one endpoint exists
if ($state['notakey:mode'] == 'filter' && count($bridge->getServices()) == 1 && $authstate == 'none') {
    Logger::info("Auto submitting auth request in filter mode");
    $sv_list = array_keys($bridge->getServices());
    $service_id = array_pop($sv_list);
    $username = $bridge->getUserId($state);
    if ($bridge->isRememberMeEnabled() && $bridge->isRememberMeChecked()) {
        $remember = 'yes';
    }
}

if (isset($state['forcedUsername'])) {
    Logger::info("Auto submitting auth request in pre-auth mode");
    $sv_list = array_keys($bridge->getServices());
    $service_id = array_pop($sv_list);
    $username = $state['forcedUsername'];

    if ($bridge->isRememberMeEnabled() && $bridge->isRememberMeChecked()) {
        $remember = 'yes';
    }
}

// We get a form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Logger::info("Processing login request");
    $username = (string) ($_REQUEST['username'] ?? '');
    $service_id = isset($_REQUEST['service_id']) ? (string) $_REQUEST['service_id'] : null;
    if (isset($_REQUEST['remember_me'])) {
        $remember = (string) $_REQUEST['remember_me'];
    }
}

if ($username != '' && !is_null($service_id)) {
    try {
        $bridge->setService($state, $service_id);
    } catch (Exception $e) {
        $warning_messages[] = $e->getMessage();
        $apiTestOK = false;
    }

    SspNtkBridge::d(__FILE__ . ":" . __LINE__ . " setService selected $service_id");
    $req = null;
    if ($apiTestOK) {
        try {
            $req = $bridge->startAuth($username, $state, $remember);
        } catch (Exception $e) {
            $warning_messages[] = $e->getMessage();
        }
    }

    SspNtkBridge::d(__FILE__ . ":" . __LINE__ . " Auth request created");

    if ($req) {
        // start new session token if auth request proceeds
        $stateId = Auth\State::saveState($state, SspNtkBridge::STAGEID);
    }
}

$config = Configuration::getInstance();
$services = $bridge->getServices();

if (count($services) > 1) {
    $t = new Template($config, 'notakey:auth_multi.twig');
    $t->data['service_list'] = $services;
    $t->data['service'] = null;
    if (!is_null($service_id) && isset($services[$service_id])) {
        $t->data['service'] = $services[$service_id];
    }
} else {
    $t = new Template($config, 'notakey:auth.twig');
    $t->data['service'] = array_pop($services);
}

$detect = new MobileDetect();
$t->data['mobile'] = true;
if (!$detect->isMobile() && !$detect->isTablet()) {
    $t->data['mobile'] = false;
}

$authUrl = Module::getModuleURL('notakey/auth.php', ['State' => $stateId, 'ReturnTo' => $returnTo]);

$t->data['stage_one_complete'] = $state['notakey:stageOneComplete'];
$t->data['auth_state'] = $authstate;
$t->data['state_id'] = $stateId;
$t->data['return_to'] = $returnTo;
$t->data['form_url'] = Module::getModuleURL('notakey/auth.php');
$t->data['auth_url'] = $authUrl;
$t->data['status_url'] = Module::getModuleURL('notakey/status.php', ['State' => $stateId]);
$t->data['qrstat_url'] = Module::getModuleURL('notakey/qrstat.php', ['State' => $stateId, 'service_id' => 0]);
$t->data['qr_link'] = Module::getModuleURL('notakey/qr.php', ['State' => $stateId, 'service_id' => 0]);

$t->data['warning_messages'] = $warning_messages;
$t->data['selected_service'] = $service_id;
$t->data['username_hint'] = $username;

if (array_key_exists('forcedUsername', $state)) {
    $t->data['username_hint'] = $state['forcedUsername'];
}

$t->data['rememberMeEnabled'] = $bridge->isRememberMeEnabled();
$t->data['rememberMeChecked'] = $bridge->isRememberMeChecked();

$t->send();

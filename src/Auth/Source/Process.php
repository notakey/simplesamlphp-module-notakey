<?php

declare(strict_types=1);

namespace SimpleSAML\Module\notakey\Auth\Source;

use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\notakey\SspNtkBridge;
use SimpleSAML\Utils;

/**
 * Notakey authentication source.
 *
 * Use as 'notakey:Process' in authsources.php.
 */
class Process extends Auth\Source
{
    /**
     * NtkAsApi bridge reference placeholder
     */
    private SspNtkBridge $ntkbridge;

    public function __construct(array $info, array &$config)
    {
        parent::__construct($info, $config);

        $bridgeConfig = $config;
        $bridgeConfig['notakey.authsource'] = $this->authId;

        $this->ntkbridge = new SspNtkBridge($bridgeConfig, self::class . '::__construct');
    }

    /**
     * Log in using an external authentication helper.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        $attributes = SspNtkBridge::getUserAttrs($state);
        if ($attributes !== null) {
            /*
             * The user is already authenticated.
             *
             * Add the users attributes to the $state-array, and return control
             * to the authentication process.
             */
            Logger::info("authenticate: User attributes found " . print_r($attributes, true));
            $state['Attributes'] = $attributes;
            return;
        }

        /*
         * The user isn't authenticated. We therefore need to
         * send the user to the login page.
         */
        Logger::info("authenticate: User not authenticated");

        $state['notakey:AuthID'] = $this->authId;
        $state['notakey:bridge'] = $this->ntkbridge;
        $state['notakey:stageOneComplete'] = false;
        $state['notakey:mode'] = 'source';
        $state['notakey:authtime'] = time();
        $state['notakey:stepUpRequired'] = false;

        Logger::info("authenticate: AuthID is " . $this->authId);

        $stateId = Auth\State::saveState($state, SspNtkBridge::STAGEID);

        $returnTo = Module::getModuleURL('notakey/resume.php', [
            'State' => $stateId,
        ]);

        $authPage = Module::getModuleURL('notakey/auth.php');

        (new Utils\HTTP())->redirectTrustedURL($authPage, [
            'ReturnTo' => $returnTo,
            'State' => $stateId,
        ]);
    }

    /**
     * Resume authentication after the user has completed the Notakey authentication page.
     */
    public static function resume(): void
    {
        if (!isset($_REQUEST['State'])) {
            throw new Error\BadRequest('Missing "State" parameter.');
        }

        $stateId = (string) $_REQUEST['State'];

        // sanitize the input
        $sid = Auth\State::parseStateID($stateId);
        if (!is_null($sid['url'])) {
            (new Utils\HTTP())->checkURLAllowed($sid['url']);
        }

        $state = Auth\State::loadState($stateId, SspNtkBridge::STAGEID);

        $source = Auth\Source::getById($state['notakey:AuthID']);
        if ($source === null) {
            /*
             * The only way this should fail is if we remove or rename the authentication source
             * while the user is at the login page.
             */
            throw new Error\Exception('Could not find authentication source with id ' . $state['notakey:AuthID']);
        }

        /*
         * Make sure that we haven't switched the source type while the
         * user was at the authentication page.
         */
        if (!($source instanceof self)) {
            throw new Error\Exception('Authentication source type changed.');
        }

        /*
         * Check that the user is actually logged in, and didn't simply skip the login page.
         */
        $attributes = SspNtkBridge::getUserAttrs($state);
        if ($attributes === null) {
            throw new Error\Exception('User not authenticated after login page.');
        }

        $state['Attributes'] = $attributes;

        Auth\Source::completeAuth($state);
    }

    /**
     * This function is called when the user start a logout operation, for example
     * by logging out of a SP that supports single logout.
     *
     * @param array &$state The logout state array.
     */
    public function logout(array &$state): void
    {
    }
}

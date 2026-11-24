<?php

declare(strict_types=1);

namespace SimpleSAML\Module\notakey\Auth\Process;

use SimpleSAML\Auth;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Module;
use SimpleSAML\Module\notakey\SspNtkBridge;
use SimpleSAML\Module\saml\Error\NoPassive;
use SimpleSAML\Utils;

/**
 * Notakey 2FA Authentication Processing filter
 *
 * Filter for requesting the second factor auth using mobile device.
 * Use as 'notakey:Filter' in authproc configuration.
 */
class Filter extends Auth\ProcessingFilter
{
    /**
     * NtkAsApi bridge reference placeholder
     */
    private SspNtkBridge $ntkbridge;

    public function __construct(array &$config, $reserved)
    {
        parent::__construct($config, $reserved);

        $bridgeConfig = $config;
        // TODO: use actual backend auth source ID
        $bridgeConfig['notakey.authsource'] = 'ntk-auth-filter';

        $this->ntkbridge = new SspNtkBridge($bridgeConfig, self::class . '::__construct');
    }

    /**
     * Checks if Notakey is disabled for the given entity.
     *
     * @param mixed $option The notakey.disable option from metadata.
     * @param string $entityId The entity ID of the other party.
     */
    private static function checkDisable(mixed $option, string $entityId): bool
    {
        if (is_array($option)) {
            return in_array($entityId, $option, true);
        }

        return (bool) $option;
    }

    /**
     * Process an authentication response.
     *
     * Saves the state and redirects the user to the Notakey authentication page.
     *
     * @param array &$state The state of the response.
     */
    public function process(array &$state): void
    {
        $spEntityId = $state['Destination']['entityid'];
        $idpEntityId = $state['Source']['entityid'];

        if (isset($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $metadata = MetaDataStorageHandler::getMetadataHandler();
            $state['Source'] = $metadata->getMetaData($idpEntityId, 'saml20-idp-remote');
        }

        // Do not use notakey if disabled per source or destination
        if (
            isset($state['Source']['notakey.disable'])
            && self::checkDisable($state['Source']['notakey.disable'], $spEntityId)
        ) {
            Logger::debug('notakey: Notakey disabled for entity ' . $spEntityId . ' with IdP ' . $idpEntityId);
            return;
        }

        if (
            isset($state['Destination']['notakey.disable'])
            && self::checkDisable($state['Destination']['notakey.disable'], $idpEntityId)
        ) {
            Logger::debug('notakey: Notakey disabled for entity ' . $spEntityId . ' with IdP ' . $idpEntityId);
            return;
        }

        if (isset($state['isPassive']) && $state['isPassive'] == true) {
            throw new NoPassive('Unable to give use 2FA on passive request.');
        }

        // NTK is used as auth source too
        if (
            isset($state['notakey:mode'])
            && $state['notakey:mode'] == 'source'
            && isset($state['notakey:authtime'])
            && (time() - $state['notakey:authtime']) < 60
        ) {
            Logger::debug('notakey: Skipped secondary verification as we have valid auth');
            return;
        }

        $state['notakey:bridge'] = $this->ntkbridge;
        $state['notakey:bridge.source'] = $spEntityId;
        $state['notakey:bridge.destination'] = $idpEntityId;
        $state['notakey:stageOneComplete'] = false;
        $state['notakey:mode'] = 'filter';
        $state['notakey:authtime'] = time();
        $state['notakey:stepUpRequired'] = false;

        $stateId = Auth\State::saveState($state, SspNtkBridge::STAGEID);

        $returnTo = Module::getModuleURL('notakey/resume.php', ['State' => $stateId]);

        $url = Module::getModuleURL('notakey/auth.php');
        (new Utils\HTTP())->redirectTrustedURL($url, ['State' => $stateId, 'ReturnTo' => $returnTo]);
    }
}

<?php
/**
 * Notakey 2FA Authentication Processing filter
 *
 * Filter for requesting the second factor auth using mobile device
 *
 */
class sspmod_notakey_Auth_Process_Filter extends SimpleSAML_Auth_ProcessingFilter
{
	/*
	 * NtkAsApi bridge reference placeholder
	 *
	 * @var object
	 */
	private $ntkapi;

	public function __construct($config, $reserved)
	{
		assert('is_array($config)');
		parent::__construct($config, $reserved);

		/*
		if (array_key_exists('hiddenAttributes', $config)) {
			if (!is_array($config['hiddenAttributes'])) {
				throw new SimpleSAML_Error_Exception(
						'Consent: hiddenAttributes must be an array. ' .
						var_export($config['hiddenAttributes']) . ' given.'
						);
			}
			$this->_hiddenAttributes = $config['hiddenAttributes'];
		}
		*/

		$className = SimpleSAML\Module::resolveClass("sspmod_notakey_SspNtkBridge", 'SspNtkBridge');

		// TODO
		// Use actual backend auth source ID
		$config['notakey.authsource'] = 'ntk-auth-filter';

		$this->ntkbridge =  new $className($config, 'sspmod_notakey_Auth_Process_Filter::__construct');

	}


	/**
	 * Process a authentication response
	 *
	 * This function saves the state, and redirects the user to the page where
	 * the user can authorize the release of the attributes.
	 * If storage is used and the consent has already been given the user is
	 * passed on.
	 *
	 * @param array &$state The state of the response.
	 *
	 * @return void
	 */
	public function process(&$state)
	{
		assert('is_array($state)');
		assert('array_key_exists("Destination", $state)');
		assert('array_key_exists("entityid", $state["Destination"])');
		assert('array_key_exists("metadata-set", $state["Destination"])');
		assert('array_key_exists("entityid", $state["Source"])');
		assert('array_key_exists("metadata-set", $state["Source"])');

		$spEntityId = $state['Destination']['entityid'];
		$idpEntityId = $state['Source']['entityid'];

		if (isset($state['saml:sp:IdP'])) {
			$idpEntityId     = $state['saml:sp:IdP'];
			$idpmeta         = $metadata->getMetaData($idpEntityId, 'saml20-idp-remote');
			$state['Source'] = $idpmeta;
		}

		// Do not use notakey if disabled per source or destination
		if (isset($state['Source']['notakey.disable']) && self::checkDisable($state['Source']['notakey.disable'], $spEntityId)) {
			SimpleSAML\Logger::debug('notakey: Notakey disabled for entity ' . $spEntityId . ' with IdP ' . $idpEntityId);
			return;
		}

		if (isset($state['Destination']['notakey.disable']) && self::checkDisable($state['Destination']['notakey.disable'], $idpEntityId)) {
			SimpleSAML\Logger::debug('notakey: Notakey disabled for entity ' . $spEntityId . ' with IdP ' . $idpEntityId);
			return;
		}

		if (isset($state['isPassive']) && $state['isPassive'] == true) {
			throw new  SimpleSAML\Module\saml\Error\NoPassive(
					'Unable to give use 2FA on passive request.'
					);
		}

		// NTK is used as auth source too
		if($state['notakey:mode'] == 'source' &&
				isset($state['notakey:authtime']) &&
				(time() - $state['notakey:authtime']) < 60 ){
			SimpleSAML\Logger::debug('notakey: Skipped secondary verification as we have valid auth');
			return;
		}

		$state['notakey:bridge']              = $this->ntkbridge;
		$state['notakey:bridge.source']       = $spEntityId;
		$state['notakey:bridge.destination']  = $idpEntityId;
		$state['notakey:stageOneComplete']    = false;
		$state['notakey:mode']                = 'filter';
		$state['notakey:authtime']            = time();

		$stateId  = SimpleSAML_Auth_State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID );

		$returnTo = SimpleSAML\Module::getModuleURL ( 'notakey/resume', array ( 'State' => $stateId ) );

		$url = SimpleSAML\Module::getModuleURL('notakey/auth');
		SimpleSAML\Utils\HTTP::redirectTrustedURL($url, array('State' => $stateId, 'ReturnTo' => $returnTo));

		assert ( 'FALSE' );

	}
}
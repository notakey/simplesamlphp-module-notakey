<?php

/**
 * Notakey SimpleSAML adapter
 *
 */


class sspmod_notakey_SspNtkBridge {

	/*
	 * Stage constant set in auth.php
	 */

    const STAGEID = 'notakey:Process';

    /*
	 * Auth request title
	 */

    const auth_action = 'Confirm login';

    /*
	 * Auth request description
	 */

    const auth_description = 'Log in as %s?';

	/*
	 * Endpoint configuration array
	 *
	 */
	private $endpoints = array ();

	/*
	 * Warning message array
	 *
	 */
	private $warnings = array ();

	/**
	 * Whether debug output is enabled.
	 *
	 * @var bool
	 */
	private $debug;

	/**
	 * Attribute mapping definitions
	 *
	 * @var array
	 */
	private static $attrmap = array(
			'uid' => 'notakey:attr.username',
			'displayName' => 'notakey:attr.display_name',
			'firstName' => 'notakey:attr.first_name',
			'lastName' => 'notakey:attr.last_name',
			'mainPhone' => 'notakey:attr.phone',
			'mail' => 'notakey:attr.email',
			'guid' => 'notakey:attr.guid',
			'authId' => 'notakey:attr.auth_id',
			'authBackend' => 'notakey:application_id',
			'authBackendName' => 'notakey:service_name',
			'authCreatedOn' => 'notakey:attr.created_at',
			'authExpiresOn' => 'notakey:attr.expires_at',
	);

	/**
	 * Define in which attribute username for NTK is stored.
	 *
	 * @var string
	 */

	private $uid_attr;

	/**
	 * Strip domain part of username when returning attrs to SP.
	 *
	 * @var bool
	 */

	private $stripdomain = false;

	/**
	 * Remember username in auth form.
	 *
	 * @var bool
	 */
	private $rememberMeChecked = false;
	private $rememberMeEnabled = false;

	/**
	 * Source auth ID.
	 *
	 * @var string
	 */
	private $authId;

	/**
	 * Constructor for this configuration parser.
	 *
	 * @param array $config  Configuration for the uath source or filter.
	 * @param string $location  The location of this configuration. Used for error reporting.
	 */
	public function __construct($config, $location) {
		assert('is_array($config)');
		assert('is_string($location)');

		$config = SimpleSAML_Configuration::loadFromArray ( $config );

		$this->debug = $config->getBoolean('debug', FALSE);
		$this->d("Debugging enabled");
		$this->authId = $config->getString('notakey.authsource', 'notakey');
		$this->stripdomain = $config->getBoolean('attrs.stripdomain', FALSE);;
		$this->endpoints = $config->getArray ( 'endpoints', array() );
		$this->d("Loaded ".count($this->endpoints)." NTK endpoints");
		$this->uid_attr = $config->getString ( 'user_id.attr', 'sAMAccountName');
		$this->d("Username will be taken from  ".$this->uid_attr." attribute");

		$this->rememberMeEnabled = $config->getBoolean('remember.username.enabled', false);
		$this->rememberMeChecked = $config->getBoolean('remember.username.checked', false);

		// get the "remember me" config options
		$sspcnf = SimpleSAML_Configuration::getInstance();
		if(!$this->rememberMeEnabled)
			$this->rememberMeEnabled = $sspcnf->getBoolean('session.rememberme.enable', FALSE);

		if(!$this->rememberMeChecked)
			$this->rememberMeChecked = $sspcnf->getBoolean('session.rememberme.checked', FALSE);

		if (count($this->endpoints) == 0) {
			throw new SimpleSAML_Error_Exception('Missing or invalid API endpoint configuration, check authsources.' );
		}
	}


	/**
	 * Check if the "remember me" feature is enabled.
	 * @return bool TRUE if enabled, FALSE otherwise.
	 */
	public function isRememberMeEnabled() {
		return $this->rememberMeEnabled;
	}

	/**
	 * Check if the "remember me" checkbox should be checked.
	 * @return bool TRUE if enabled, FALSE otherwise.
	 */
	public function isRememberMeChecked() {
		return $this->rememberMeChecked;
	}

	public function getAuthId(){
		$this->d("getAuthId is  ".$this->authId." ");
		return $this->authId;
	}

	public function getUserId(&$state) {
		if(!isset($state['Attributes'][$this->uid_attr])){
			throw new SimpleSAML_Error_Exception('Missing username attribute in Auth source. Please check filter configuration.');
		}

		return $state['Attributes'][$this->uid_attr][0];
	}

	public function getWarnings() {
		return $this->warnings;
	}

	public function setUser(&$state, $res) {
		if (! isset ( $res['id'] )) {
			SimpleSAML\Logger::info("setUser: Remote user not set, \$res->id empty" );
			return false;
		}

		$user = $res['username'];
		if($this->stripdomain){
			$domain = '';
			if(strpos($res['username'], '@') > 0){
				list($user, $domain) = explode('@', $res['username'], 2);
			}
			$state ['notakey:attr.username'] = $user;
			$state ['notakey:attr.upn'] = $domain;
		}else{
			$state ['notakey:attr.username'] = $res['username'];
		}

		$state ['notakey:attr.uid'] = $res['id'];
		$state ['notakey:attr.display_name'] = $res['full_name'];
		$state ['notakey:attr.email'] = $res['email'];
		$state ['notakey:attr.phone'] = $res['main_phone_number'];

		$state ['notakey:attr.auth_id'] = $res['uuid'];

        // Pre 2.14.2 versions did not have this attribute
        if(isset($res['user_id'])){
            $state ['notakey:attr.guid'] = $res['user_id'];
        }


		SimpleSAML\Logger::info("setUser: Populated user $user / {$res['full_name']} / UUID : {$res['uuid']} attribute data" );

		//var_dump($state);
		// exit;

		return true;
	}

	public function getServices() {
		return $this->endpoints;
    }

    public function getService($endpoint_id) {
        if (!isset($this->endpoints[$endpoint_id])) {
			throw new SimpleSAML_Error_Exception ( 'No backend service not defined.' );
        }

		return $this->endpoints[$endpoint_id];
	}

	public function setService(&$state, $endpoint_id = null) {
		if (count ( $this->endpoints ) == 0) {
			throw new SimpleSAML_Error_Exception ( 'No backend services defined.' );
			return false;
		}

		//var_dump($state);

		if (is_null ( $endpoint_id ) ){
			if ( isset ( $state ['notakey:service_id'] ) && isset ( $this->endpoints [$state ['notakey:service_id']] )) {
				SimpleSAML\Logger::info("setService: Backend {$this->endpoints[$state['notakey:service_id']]['name']} ({$state['notakey:service_id']}) selected" );
				return $this->loadNtkApi($state ['notakey:service_id']);
			}

			throw new SimpleSAML_Error_Exception ( 'Invalid session state.' );
			return false;
		}

		if (! isset ( $this->endpoints [$endpoint_id] )) {
			SimpleSAML\Logger::info("setService: Service ID $endpoint_id undefined" );
			throw new SimpleSAML_Error_Exception ( 'Please select your service provider.' );
			return false;
		}

		$this->loadNtkApi($endpoint_id);

		SimpleSAML\Logger::info("setService: New backend {$this->endpoints[$endpoint_id]['name']} ($endpoint_id) selected" );

		$state ['notakey:service_id'] = $endpoint_id;
		$state ['notakey:application_id'] = $this->endpoints[$endpoint_id]['service_id'];

		if (! $this->checkApiAccess ( $state )) {
			throw new SimpleSAML_Error_Exception ( 'Selected backend not available at the moment, please try later.' );
			return false;
		}

		return true;
	}

	public function getRememberUsername(){
		SimpleSAML\Logger::debug("getRememberUsername: called for {$this->getAuthId()}" );

		if ($this->isRememberMeEnabled()) {
			if (isset($_COOKIE[$this->getAuthId() . '-username'])){
				SimpleSAML\Logger::info("getRememberUsername: Preset username ".$_COOKIE[$this->getAuthId() . '-username']." for {$this->getAuthId()}" );
				return $_COOKIE[$this->getAuthId() . '-username'];
			}
		}

		return '';
	}

	private function setRememberCookie($username, $remember = ''){
		SimpleSAML\Logger::debug("setRememberCookie: called with ".$username." $remember for {$this->getAuthId()}" );
		if ($this->isRememberMeEnabled()) {
			$sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
			$params = $sessionHandler->getCookieParams();
			$params['expire'] = time();
			$params['expire'] += ( strtolower($remember) == 'yes') ? 31536000 : -300;
			\SimpleSAML\Utils\HTTP::setCookie($this->getAuthId() . '-username', $username, $params, FALSE);
			SimpleSAML\Logger::info("setRememberCookie: Stored username ".$username." for {$this->getAuthId()}" );
		}

		return true;
	}

	public function startAuth($username, &$state, $remember = '') {
		$this->setRememberCookie($username, $remember);

		$areq =  $this->ntkapi->authExt($username);

		if(isset($areq['uuid'])){
            $this->setAuthState($state, $areq);
			return true;
		}



		return false;
    }

    public function setAuthState(&$state, $areq){
        $state['notakey:uuid'] = $areq['uuid'];
        $state['notakey:stageOneComplete'] = true;


        $state['notakey:attr.logo_url'] = $areq['logo_url'];
        $state['notakey:attr.logo_sash_url'] = $areq['logo_sash_url'];
        $state['notakey:attr.created_at'] = $areq['created_at'];
        $state['notakey:attr.expires_at'] = $areq['expires_at'];
    }

	public function queryAuth($uuid) {
		$s = $this->ntkapi->query($uuid);

		return $s;
	}

	private function checkApiAccess(&$state) {
		$res = $this->ntkapi->serviceName();

		if ($res) {
			SimpleSAML\Logger::info("checkApiAccess: Connectivity to $res verified" );
			$state ['notakey:service_name'] = $res;
			return true;
		}

		return false;
	}

	/**
	 * Retrieve attributes for the user. Must be able to call from static context.
	 *
	 * @return array|NULL The user's attributes, or NULL if the user isn't authenticated.
	 */

	public static function getUserAttrs(&$state) {
		if (! isset ( $state ['notakey:attr.uid'] )) {
			/* The user isn't authenticated. */
			return NULL;
		}

		list($state['notakey:attr.first_name'], $state['notakey:attr.last_name']) = explode(' ' , $state ['notakey:attr.display_name'], 2);

		$attributes = array ();

		foreach(self::$attrmap as $attr=>$st_attr){
			if(!isset($state[$st_attr])){
				$attributes[$attr] = array( "" );
			}

			$attributes[$attr] = array( $state[$st_attr] );
		}

		if(isset($state['notakey:attr.upn'])){
			$attributes['domain'] = array( $state['notakey:attr.upn']);
		}

		return $attributes;
	}

	private function loadNtkApi($endpoint_id){

		if(empty($this->endpoints[$endpoint_id]['url']) || empty($this->endpoints[$endpoint_id]['service_id'])){
			throw new SimpleSAML_Error_Exception('Missing or invalid API endpoint configuration, check authsources.php.' );
		}

		$className = SimpleSAML\Module::resolveClass( 'sspmod_notakey_NtkAsApi', 'NtkAsApi');

		$this->ntkapi = new $className($this->endpoints[$endpoint_id], 'sspmod_notakey_SspNtkBridge::loadNtkApi');

		$this->ntkapi->setLogger('sspmod_notakey_SspNtkBridge::l');

		$this->ntkapi->setServiceId($this->endpoints[$endpoint_id]['service_id']);

		return true;
	}

	public static function d($msg) {

		//if($this->debug)
			SimpleSAML\Logger::debug( $msg );
	}

	public static function l($msg) {
		SimpleSAML\Logger::info($msg);
	}

}


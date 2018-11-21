<?php

/**
 * Notakey authentication source and filter core API interface.
 *
 * Core API call processing towards Notakey Authentcation Server
 *
 */

/*
$className = SimpleSAML\Module::resolveClass(
		$config[0],
		'Consent_Store',
		'sspmod_notakey_NtkAsApi'
		);

if (!class_exists($classname)){
}
*/

class sspmod_notakey_NtkAsApi {

	/**
	 * Whether debug output is enabled.
	 *
	 * @var bool
	 */
	private $debug;

	/**
	 * Base URL for API access
	 *
	 * @var array
	 */
	private $base_url = array ();

	/**
	 * Reference to API instance
	 *
	 * @var
	 */
	private $api = '';

	/**
	 * Selected application from service list
	 *
	 * @var string
	 */
	private $application_id = '';

	/**
	 * User data placeholer
	 *
	 * @var array
	 */
	private $user = '';

	/**
	 * Auth request UUID placeholder
	 *
	 * @var string
	 */
	private $uuid = '';

	/**
	 * Auth backend service identifier
	 *
	 * @var string
	 */
	private $service_id = '';

	/**
	 * Logger callback
	 *
	 * @var string
	 */
	private $logger = null;


	/**
	 * Constructor for this configuration parser.
	 *
	 * @param array $config  Configuration.
	 * @param string $location  The location of this configuration. Used for error reporting.
	 */
	public function __construct($config, $location) {
		assert('is_array($config)');
		assert('is_string($location)');

		if(!isset($config['debug'])){
			$config['debug'] = false;
		}

		/* Parse configuration. */
		$config = SimpleSAML_Configuration::loadFromArray($config, $location);
		$this->debug = $config->getBoolean('debug', FALSE);

		$this->base_url = $config->getString('url');

		if(empty($this->base_url)){
			throw new Exception ( 'Missing URL configuration in '.$location );
		}

		$this->base_url .= 'api/v2/';
	}

	public function auth($username, $action = '', $description = '') {
		$p = $this->authExt($username, $action, $description);

		if ($p) {

			// TODO
			// Check if we have this error handling in place
			if (isset ( $p['status'] ) && $p['status'] == 'error') {
				throw new Exception ( $res->error_message );
				return false;
			}

			if (isset ( $p['uuid'] )) {
				$this->l ( "Login for user $username sent OK" );
				$this->uuid = $p['uuid'];
				return $p['uuid'];
			}
		}

		$this->l ( "Login request for user $username failed" );
		return false;
	}

	public function authExt($username, $action = '', $description = '') {
		$domain = '';

		if (! empty ( $entity_id )) {
			$uparam = parse_url ( $entity_id );
			if (isset ( $uparam ['host'] )) {
				$domain = $uparam ['host'];
			}
		}

		$attr_array = array (
				array (),
				array ()
		);

		$method = 'auth_request';

		$p = array (
				'action' => 'Confirm login',
				'description' => 'Log in as '.$username.'?'
		);

		if(!empty($action)){
			$p['action'] = str_replace(array('{}'), $username, $action);
		}

		if(!empty($description)){
			$p['description'] = str_replace(array('{}'), $username, $description);
		}

		$res = $this->callApi ( '/application_user/' . $username . '/' . $method . '/', 'POST', $p );

		// $this->l(print_r($res, true));

		if (!$res) {
			$this->l ( "Login request for user $username failed" );
			throw new Exception ( 'Authentication server responded with bad status, check if the specified username is valid.' );
			return false;
		}

		return (array) $res;
	}

	public function setServiceId($service_id){

		if(empty($service_id)){
			throw new Exception ( 'Invalid or missing service access key, cannot initiate session.' );
		}

		$this->service_id = $service_id;

		$this->api = $this->base_url.'application/'.$service_id;
		return true;
	}

	public function serviceName(){
		$res = $this->callApi ( '/', 'GET' );

		if (isset ( $res->id ) && isset($res->display_name)) {
			$this->l ( "serviceName: Connectivity to $res->id / $res->display_name verified" );
			return $res->display_name;
		}

		return false;
	}

	public function query($uuid) {

		if(empty($uuid)){
			throw new Exception ( 'Invalid authentication state, cannot verify session.' );
		}

		$res = $this->callApi ( '/auth_request/' . $uuid , 'GET' );

		if ($res) {
			return (array) $res;
		}

		return false;
	}

	private function serializeApiParams($p) {
		if (! is_array ( $p )) {
			throw new Exception ( 'Invalid value for serializeApiParams' );
		}

		$s = json_encode ( $p );
		// $this->l("serializeApiParams: $s");
		return $s;
	}

	private function callApi($method, $mode = 'GET', $params = NULL) {
		if ($mode == 'GET') {
			try {
				$response = \Httpful\Request::get ( $this->api . $method )->expectsJson ()->send ();
			} catch ( Exception $e ) {
				$this->l ( "callApi: GET $method exception caught" );
				return false;
			}
		}

		if ($mode == 'POST') {
			try {
				$response = \Httpful\Request::post ( $this->api . $method )->sendsJson ()->expectsJson ()->body ( $this->serializeApiParams ( $params ) )->send ();
			} catch ( Exception $e ) {
				$this->l ( "callApi: POST $method exception caught" );
				return false;
			}
		}

		if ($mode == 'PATCH') {
			//TODO
		}

		if ($mode == 'PUT') {
			//TODO
		}

		$this->l ( "callApi: $method returned code $response->code" );
		if ($response->code >= 200 && $response->code < 300) {
			return $response->body;
		}

		return false;
	}

	public function setLogger($callback 	) {
		$this->logger = $callback;
	}

	public function l($msg) {
		if($this->logger)
			call_user_func($this->logger, $msg);
	}

	private function getServiceAppID(&$state, $service) {
		$apr = explode ( '/', $this->endpoints [$service] ['api'] );
		return array_pop ( $apr );
	}

	private function checkApiAccess(&$state) {
		$res = $this->callApi ( '/', 'GET' );

		$ret = false;
		if (isset ( $res->id )) {
			$this->l ( "checkApiAccess: Connectivity to $res->display_name verified" );
			$state ['notakey:service_name'] = $res->display_name;
			$ret = true;
		}

		return $ret;
	}

}


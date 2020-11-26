<?php

/**
 * Notakey authentication source and filter core API interface.
 *
 * Core API call processing towards Notakey Authentcation Server
 *
 */

/*
$className = \SimpleSAML\Module::resolveClass(
		$config[0],
		'Consent_Store',
		'sspmod_notakey_NtkAsApi'
		);

if (!class_exists($classname)){
}
*/

class sspmod_notakey_NtkAsApi
{

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
    private $base_url = '';

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
     * Persistance layer using KV
     *
     * @var object
     */
    private $store = null;

    /**
     * API authentication credentials
     *
     * @var string
     */
    private $api_client = null;

    private $api_secret = null;

    private $_accessToken = null;

    private $profile_id = null;

    private $_accessTokenExpires = null;

    /**
     * Constructor for this configuration parser.
     *
     * @param array $config  Configuration.
     * @param string $location  The location of this configuration. Used for error reporting.
     */
    public function __construct($config, $location)
    {
        assert('is_array($config)');
        assert('is_string($location)');

        if (!isset($config['debug'])) {
            $config['debug'] = false;
        }

        /* Parse configuration. */
        $config = \SimpleSAML\Configuration::loadFromArray($config, $location);
        $this->debug = $config->getBoolean('debug', FALSE);

        $this->base_url = $this->trimUrl($config->getString('url'));

        if (empty($this->base_url)) {
            throw new Exception('Missing URL configuration in ' . $location);
        }

        $this->api_client = $config->getString('client_id');

        if (empty($this->api_client)) {
            throw new Exception('Missing API client_id configuration in ' . $location);
        }

        $this->api_secret = $config->getString('client_secret');

        if (empty($this->api_secret)) {
            throw new Exception('Missing API client_secret configuration in ' . $location);
        }

        $this->profile_id = $config->getString('profile_id', null);

        $this->store = \SimpleSAML\Store::getInstance();

        if (is_null($this->store)) {
            throw new Exception('Cannot get instance of Store module');
        }
    }

    public function auth($username, $action = '', $description = '')
    {
        $p = $this->authExt($username, $action, $description);

        if ($p) {

            // TODO
            // Check if we have this error handling in place
            if (isset($p['status']) && $p['status'] == 'error') {
                // throw new Exception($res->error_message);
                return false;
            }

            if (isset($p['uuid'])) {
                $this->l("Login for user $username sent OK");
                return $p['uuid'];
            }
        }

        $this->l("Login request for user $username failed");
        return false;
    }

    public function parseAuthMessage($m)
    {
        return str_replace(array("\n", "\r", "\0", "\t"), '', $m);
    }

    public function authExt($username, $action = '', $description = '', $state = '')
    {
        $p = array(
            'username' => $username
        );

        if ($this->profile_id) {
            $p['profile'] = $this->profile_id;
            $p['state'] = urlencode($state);
        } else {
            $p['action'] = sspmod_notakey_SspNtkBridge::auth_action;
            $p['description'] = $this->parseAuthMessage(sprintf(sspmod_notakey_SspNtkBridge::auth_description, $username));


            if (!empty($action)) {
                $p['action'] = $this->parseAuthMessage(str_replace(array('{}'), $username, $action));
            }

            if (!empty($description)) {
                $p['description'] = $this->parseAuthMessage(str_replace(array('{}'), $username, $description));
            }
        }

        $res = $this->callAuthenticatedApi('auth', 'POST', $p);

        // $this->l(print_r($res, true));

        if (!$res) {
            $this->l("Login request for user $username failed");
            throw new Exception('Authentication server responded with bad status, check if the specified username is valid.');
            return false;
        }

        return (array) $res;
    }

    public function setServiceId($service_id)
    {

        if (empty($service_id)) {
            throw new Exception('Invalid or missing service access key, cannot initiate session.');
        }

        $this->service_id = $service_id;

        $this->api = $this->trimUrl($this->base_url . '/api/v3/services/' . $service_id);
        return true;
    }

    public function serviceName()
    {
        $res = $this->callAuthenticatedApi('', 'GET');

        if (isset($res->id) && isset($res->display_name)) {
            $this->l("serviceName: Connectivity to $res->id / $res->display_name verified");
            return $res->display_name;
        }

        return false;
    }

    private function trimUrl($url)
    {
        return rtrim($url, "/ \t\n\r\0");
    }

    public function query($uuid)
    {

        if (empty($uuid)) {
            throw new Exception('Invalid authentication state, cannot verify session.');
        }

        $res = $this->callAuthenticatedApi('auth/' . $uuid, 'GET');

        if ($res) {
            return (array) $res;
        }

        return false;
    }

    private function serializeApiParams($p)
    {
        if (!is_array($p)) {
            throw new Exception('Invalid value for serializeApiParams');
        }

        $s = json_encode($p);
        // $this->l("serializeApiParams: $s");
        return $s;
    }

    private function acquireAccessToken()
    {
        // curl --request POST \
        // --url https://{nas}/api/token \
        // --header 'accept: application/json' \
        // --header 'authorization: Basic MG9hY...' \
        // --header 'cache-control: no-cache' \
        // --header 'content-type: application/x-www-form-urlencoded' \
        // --data 'grant_type=client_credentials&redirect_uri=http%3A%2F%2Flocalhost%3A8080&
        // scope=customScope'

        if ($this->accessTokenValid()) {
            return true;
        }

        $p = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->api_client,
            'client_secret' => $this->api_secret,
            'scope' => 'urn:notakey:auth'
        ];

        $h = [
            'Authorization: Basic ' . base64_encode($this->api_client . ':' . $this->api_secret)
        ];

        $res = $this->callProtoApi($this->base_url . '/api/token', 'POST', $p, $h);

        // $this->l(print_r($res, true));

        if (!$res) {
            $this->l("Api authentication failed");
            throw new Exception('Authentication server call failed, authentication procedure failed');
            return false;
        }

        return $this->saveAccessToken($res);
    }

    private function getAccessToken()
    {
        if ($this->_accessToken && $this->_accessTokenExpires) {
            return;
        }
        try {
            $token = $this->store->get('ntk_access_token', md5($this->base_url));
            if ($token) {
                list($this->_accessToken, $this->_accessTokenExpires) = unserialize($token);
            }
        } catch (Exception $ex) {
            $this->l("getAccessToken no valid token found: " . $ex->getMessage());
        }
    }

    private function getAccessTokenHeader()
    {
        $this->getAccessToken();
        return array("Authorization" => "Bearer " . $this->_accessToken);
    }

    private function saveAccessToken($token_arr)
    {
        if (empty($token_arr->access_token) || $token_arr->created_at == 0 || $token_arr->expires_in == 0) {
            throw new Exception('Authentication server call failed, failed to secure connection');
            return false;
        }
        $this->_accessToken = $token_arr->access_token;
        $this->_accessTokenExpires = $token_arr->created_at + $token_arr->expires_in;

        if ($this->_accessTokenExpires < time()) {
            throw new Exception('Authentication server call failed, failed to secure connection');
            return false;
        }

        $this->store->set('ntk_access_token', md5($this->base_url), serialize([$this->_accessToken, $this->_accessTokenExpires]), $this->_accessTokenExpires);

        $this->l("saveAccessToken saved token, expires: " . date("H:i:s", $this->_accessTokenExpires));

        return true;
    }

    private function accessTokenValid()
    {
        $this->getAccessToken();
        if (time() > $this->_accessTokenExpires) {
            return false;
        }

        return true;
    }

    private function callAuthenticatedApi($method, $mode = 'GET', $params = null)
    {
        if (!$this->accessTokenValid()) {
            $this->acquireAccessToken();
        }

        return $this->callApi($method, $mode, $params, $this->getAccessTokenHeader());
    }

    private function callApi($method, $mode = 'GET', $params = null, $headers = array())
    {
        return $this->callProtoApi($this->trimUrl($this->api) . ($method == '' ? '' : '/' . $method), $mode, $params, $headers);
    }

    private function callProtoApi($url, $mode = 'GET', $params = null, $headers = array())
    {
        if ($mode == 'GET') {
            try {
                $response = \Httpful\Request::get($url)->addHeaders($headers)->expectsJson()->send();
            } catch (Exception $e) {
                $this->l("callApi: GET $url exception caught");
                return false;
            }
        }

        if ($mode == 'POST') {
            try {
                $response = \Httpful\Request::post($url)->addHeaders($headers)->sendsJson()->expectsJson()->body($this->serializeApiParams($params))->send();
            } catch (Exception $e) {
                $this->l("callApi: POST $url exception caught");
                return false;
            }
        }

        if ($mode == 'PATCH') {
            //TODO
        }

        if ($mode == 'PUT') {
            //TODO
        }

        $this->l("callApi: $url returned code $response->code");
        if ($response->code >= 200 && $response->code < 300) {
            return $response->body;
        }

        return false;
    }

    public function setLogger($callback)
    {
        $this->logger = $callback;
    }

    public function l($msg)
    {
        if ($this->logger)
            call_user_func($this->logger, $msg);
    }

    private function getServiceAppID(&$state, $service_id)
    {
        $apr = explode('/', $this->endpoints[$service_id]['api']);
        return array_pop($apr);
    }

    private function checkApiAccess(&$state)
    {
        $res = $this->callAuthenticatedApi('', 'GET');

        $ret = false;
        if (isset($res->id)) {
            $this->l("checkApiAccess: Connectivity to $res->display_name verified");
            $state['notakey:service_name'] = $res->display_name;
            $ret = true;
        }

        return $ret;
    }
}

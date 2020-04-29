<?php

/**
 * Notakey SimpleSAML adapter
 *
 */


class sspmod_notakey_SspNtkBridge
{

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
    private $endpoints = array();

    private $endpoint_id = null;

    /*
     * Warning message array
     *
     */
    private $warnings = array();

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
        'keyToken' => 'notakey:attr.keytoken',
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

    private $ntk_api = null;

    /**
     * Constructor for this configuration parser.
     *
     * @param array $config  Configuration for the uath source or filter.
     * @param string $location  The location of this configuration. Used for error reporting.
     */
    public function __construct($config, $location)
    {
        assert('is_array($config)');
        assert('is_string($location)');

        $config = \SimpleSAML\Configuration::loadFromArray($config);

        $this->debug = $config->getBoolean('debug', FALSE);
        $this->d("Debugging enabled");
        $this->authId = $config->getString('notakey.authsource', 'notakey');
        $this->stripdomain = $config->getBoolean('attrs.stripdomain', FALSE);;
        $this->endpoints = $config->getArray('endpoints', array());
        $this->d("Loaded " . count($this->endpoints) . " NTK endpoints");
        $this->uid_attr = $config->getString('user_id.attr', 'sAMAccountName');
        $this->d("Username will be taken from  " . $this->uid_attr . " attribute");

        // local remember user name options
        $this->rememberMeEnabled = $config->getBoolean('remember.username.enabled', false);
        $this->rememberMeChecked = $config->getBoolean('remember.username.checked', false);

        // get the "remember me" config options from global config
        $sspcnf = \SimpleSAML\Configuration::getInstance();
        if (!$this->rememberMeEnabled)
            $this->rememberMeEnabled = $sspcnf->getBoolean('session.rememberme.enable', FALSE);

        if (!$this->rememberMeChecked)
            $this->rememberMeChecked = $sspcnf->getBoolean('session.rememberme.checked', FALSE);

        if (count($this->endpoints) == 0) {
            throw new \SimpleSAML\Error\Exception('Missing or invalid API endpoint configuration, check authsources.');
        }
    }


    /**
     * Check if the "remember me" feature is enabled.
     * @return bool TRUE if enabled, FALSE otherwise.
     */
    public function isRememberMeEnabled()
    {
        return $this->rememberMeEnabled;
    }

    /**
     * Check if the "remember me" checkbox should be checked.
     * @return bool TRUE if enabled, FALSE otherwise.
     */
    public function isRememberMeChecked()
    {
        return $this->rememberMeChecked;
    }

    public function getAuthId()
    {
        $this->d("getAuthId is " . $this->authId . " ");
        return $this->authId;
    }

    public function getUserId(&$state)
    {
        if (!isset($state['Attributes'][$this->uid_attr])) {
            throw new \SimpleSAML\Error\Exception('Missing username attribute in Auth source. Please check filter configuration.');
        }

        return $state['Attributes'][$this->uid_attr][0];
    }

    public function getWarnings()
    {
        return $this->warnings;
    }

    public function setUser(&$state, $res)
    {
        if (!isset($res['id'])) {
            \SimpleSAML\Logger::info("setUser: Remote user not set, \$res->id empty");
            return false;
        }

        $user = $res['username'];
        if ($this->stripdomain) {
            $domain = '';
            if (strpos($res['username'], '@') > 0) {
                list($user, $domain) = explode('@', $res['username'], 2);
            }
            $state['notakey:attr.username'] = $user;
            $state['notakey:attr.domain'] = $domain;
        } else {
            $state['notakey:attr.username'] = $res['username'];
        }

        $state['notakey:attr.uid'] = $res['id'];
        $state['notakey:attr.display_name'] = $res['full_name'];
        $state['notakey:attr.email'] = $res['email'];
        $state['notakey:attr.phone'] = $res['main_phone_number'];

        $state['notakey:attr.auth_id'] = $res['uuid'];

        // Pre 2.14.2 versions did not have this attribute
        if (isset($res['user_id'])) {
            $state['notakey:attr.guid'] = $res['user_id'];
        }

        // Keytoken present only in V3 API
        if (isset($res['keytoken'])) {
            $state['notakey:attr.keytoken'] = $res['keytoken'];
        }

        \SimpleSAML\Logger::info("setUser: Populated user $user / {$res['full_name']} / UUID : {$res['uuid']} attribute data");

        //var_dump($state);
        // exit;

        return true;
    }

    public function getServices()
    {
        return $this->endpoints;
    }

    public function getService($endpoint_id)
    {
        if (!isset($this->endpoints[$endpoint_id])) {
            throw new \SimpleSAML\Error\Exception('Backend service not defined.');
        }

        return $this->endpoints[$endpoint_id];
    }

    public function parseAuthMessage($m)
    {
        return $this->ntkapi()->parseAuthMessage($m);
    }

    public function setService(&$state, $endpoint_id = null)
    {
        if (count($this->endpoints) == 0) {
            throw new \SimpleSAML\Error\Exception('No backend services defined.');
            return false;
        }

        //var_dump($state);

        if (is_null($endpoint_id)) {
            if (isset($state['notakey:service_id']) && isset($this->endpoints[$state['notakey:service_id']])) {
                \SimpleSAML\Logger::info("setService: Backend {$this->endpoints[$state['notakey:service_id']]['name']} ({$state['notakey:service_id']}) selected");
                $this->endpoint_id = $state['notakey:service_id'];
                return true;
            }

            throw new \SimpleSAML\Error\Exception('Invalid session state.');
            return false;
        }

        if (!isset($this->endpoints[$endpoint_id])) {
            \SimpleSAML\Logger::info("setService: Service ID $endpoint_id undefined");
            throw new \SimpleSAML\Error\Exception('Please select your service provider.');
            return false;
        }

        $this->endpoint_id = $endpoint_id;

        \SimpleSAML\Logger::info("setService: New backend {$this->endpoints[$endpoint_id]['name']} ($endpoint_id) selected");

        $state['notakey:service_id'] = $endpoint_id;
        $state['notakey:application_id'] = $this->endpoints[$endpoint_id]['service_id'];

        if (isset($this->endpoints[$endpoint_id]['stepup-source']) && !empty($this->endpoints[$endpoint_id]['stepup-source'])) {
            $state['notakey:stepUpRequired'] = true;
            $state['notakey:stepupAuthCompleted'] = false;
            $state['notakey:stepUpSource'] = $this->endpoints[$endpoint_id]['stepup-source'];
            if (isset($this->endpoints[$endpoint_id]['stepup-duration'])) {
                $state['notakey:stepUpDuration'] = $this->endpoints[$endpoint_id]['stepup-duration'];
            }
        }


        if (!$this->checkApiAccess($state)) {
            throw new \SimpleSAML\Error\Exception('Selected backend not available at the moment, please try later.');
            return false;
        }

        return true;
    }

    public function getRememberUsername()
    {
        \SimpleSAML\Logger::debug("getRememberUsername: called for {$this->getAuthId()}");

        if ($this->isRememberMeEnabled()) {
            if (isset($_COOKIE[$this->getAuthId() . '-username'])) {
                \SimpleSAML\Logger::info("getRememberUsername: Preset username " . $_COOKIE[$this->getAuthId() . '-username'] . " for {$this->getAuthId()}");
                return $_COOKIE[$this->getAuthId() . '-username'];
            }
        }

        return '';
    }

    private function setRememberCookie($username, $remember = '')
    {
        \SimpleSAML\Logger::debug("setRememberCookie: called with " . $username . " $remember for {$this->getAuthId()}");
        if ($this->isRememberMeEnabled()) {
            $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
            $params = $sessionHandler->getCookieParams();
            $params['expire'] = time();
            $params['expire'] += (strtolower($remember) == 'yes') ? 31536000 : -300;
            \SimpleSAML\Utils\HTTP::setCookie($this->getAuthId() . '-username', $username, $params, FALSE);
            \SimpleSAML\Logger::info("setRememberCookie: Stored username " . $username . " for {$this->getAuthId()}");
        }

        return true;
    }

    public function checkLoopDetectionCookie()
    {
        \SimpleSAML\Logger::debug("checkLoopDetectionCookie: called for {$this->getAuthId()}");

        if (isset($_COOKIE[$this->getAuthId() . '-loop-detection'])) {
            $time = unserialize(base64_decode($_COOKIE[$this->getAuthId() . '-loop-detection']));
            if ((time() - $time) < 5) {
                throw new \SimpleSAML\Error\Exception('Login loop detected, seems like there is a problem with configuration. Please contact your support.');
                return false;
            }
        } else {
            \SimpleSAML\Logger::debug("checkLoopDetectionCookie: previous login for {$this->getAuthId()} not found");
        }
        return true;
    }

    private function setLoopDetectionCookie()
    {
        \SimpleSAML\Logger::debug("setLoopDetectionCookie: called for {$this->getAuthId()}");
        $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();
        $params['expire'] = time() + 600;
        \SimpleSAML\Utils\HTTP::setCookie($this->getAuthId() . '-loop-detection', base64_encode(serialize(time())), $params, FALSE);

        return true;
    }

    public function getCallbackState()
    {
        // Load session details for state variable
        $stateId = urldecode($_REQUEST['State']);
        list($state_id, $session_data) = explode(":", $stateId, 2);
        $session = \SimpleSAML\Session::getSessionFromRequest();
        return $this->endpoint_id . ':' . $state_id . ':' . $session->getSessionId();
    }

    public function startAuth($username, &$state, $remember = '')
    {
        if (!$this->checkLoopDetectionCookie()) {
            return false;
        }

        $this->setRememberCookie($username, $remember);
        $this->setLoopDetectionCookie();

        $areq =  $this->ntkapi()->authExt($username, '', '', $this->getCallbackState());

        if (isset($areq['uuid'])) {
            $this->setAuthState($state, $areq);
            return true;
        }

        return false;
    }

    public function setAuthState(&$state, $areq)
    {
        $state['notakey:uuid'] = $areq['uuid'];
        $state['notakey:stageOneComplete'] = true;
        $state['notakey:attr.created_at'] = $areq['created_at'];
        $state['notakey:attr.expires_at'] = $areq['expires_at'];
    }

    public function queryAuth($uuid)
    {
        $s = $this->ntkapi()->query($uuid);

        return $s;
    }

    private function checkApiAccess(&$state)
    {
        $res = $this->ntkapi()->serviceName($state);

        if ($res) {
            \SimpleSAML\Logger::info("checkApiAccess: Connectivity to $res verified");
            $state['notakey:service_name'] = $res;
            return true;
        }

        return false;
    }

    /**
     * Retrieve attributes for the user. Must be able to call from static context.
     *
     * @return array|NULL The user's attributes, or NULL if the user isn't authenticated.
     */

    public static function getUserAttrs(&$state)
    {
        if (!isset($state['notakey:attr.uid'])) {
            /* The user isn't authenticated. */
            return NULL;
        }

        if (isset($state['notakey:attr.display_name']) && strpos($state['notakey:attr.display_name'], ' ') > 0) {
            list($state['notakey:attr.first_name'], $state['notakey:attr.last_name']) = explode(' ', $state['notakey:attr.display_name'], 2);
        }

        $attributes = array();

        foreach (self::$attrmap as $attr => $st_attr) {
            if (!isset($state[$st_attr])) {
                $attributes[$attr] = array("");
                continue;
            }

            $attributes[$attr] = array($state[$st_attr]);
        }

        if (isset($state['notakey:attr.domain'])) {
            $attributes['domain'] = array($state['notakey:attr.domain']);
        }

        return $attributes;
    }

    private function ntkapi()
    {

        if ($this->ntk_api) {
            return $this->ntk_api;
        }

        if (empty($this->endpoints[$this->endpoint_id]['url']) || empty($this->endpoints[$this->endpoint_id]['service_id'])) {
            throw new \SimpleSAML\Error\Exception('Missing or invalid API endpoint configuration, check authsources.php.');
        }

        $className = \SimpleSAML\Module::resolveClass('sspmod_notakey_NtkAsApi', 'NtkAsApi');

        $this->ntk_api = new $className($this->endpoints[$this->endpoint_id], 'sspmod_notakey_SspNtkBridge::loadNtkApi');

        $this->ntk_api->setLogger('sspmod_notakey_SspNtkBridge::l');

        $this->ntk_api->setServiceId($this->endpoints[$this->endpoint_id]['service_id']);

        return $this->ntk_api;
    }

    public static function d($msg)
    {

        //if($this->debug)
        \SimpleSAML\Logger::debug($msg);
    }

    public static function l($msg)
    {
        \SimpleSAML\Logger::info($msg);
    }

    public function __sleep()
    {
        return array('endpoint_id', 'debug',  'authId', 'stripdomain', 'endpoints', 'uid_attr', 'rememberMeEnabled', 'rememberMeChecked');
    }

    public function __wakeup()
    {
    }

    public function stepupAuth(&$state)
    {

        if ($this->hasValidStepupState($state['notakey:attr.username'], $state['notakey:service_id'])) {
            self::finalizeStepupAuth($state);
        }

        $as = \SimpleSAML\Auth\Source::getById($state['notakey:stepUpSource']);

        if ($as === NULL) {
            throw new Exception('Invalid authentication source: ' . $state['notakey:stepUpSource']);
        }

        $state['PrimaryLoginCompletedHandler'] = $state['LoginCompletedHandler'];
        $state['LoginCompletedHandler'] = array(get_class(), 'stepupAuthCompleted');

        try {
            // TODO
            // Stepup auth must now must derive from UserPass auth
            $as->setForcedUsername($state['notakey:attr.username']);
            $as->authenticate($state);
        } catch (\SimpleSAML\Error\Exception $e) {
            \SimpleSAML\Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new \SimpleSAML\Error\UnserializableException($e);
            \SimpleSAML\Auth\State::throwException($state, $e);
        }

        /* The previous function never returns, so this code is never
        executed */
        assert('FALSE');
    }

    public static function stepupAuthCompleted(&$state)
    {
        assert('is_array($state)');
        assert('!array_key_exists("LogoutState", $state) || is_array($state["LogoutState"])');

        self::setStepupCookie(
            $state['notakey:service_id'],
            $state['notakey:attr.username'],
            $state['notakey:stepUpDuration']
        );

        unset($state['LoginCompletedHandler']);
        $state['LoginCompletedHandler'] = $state['PrimaryLoginCompletedHandler'];

        self::finalizeStepupAuth($state);
    }

    private static function finalizeStepupAuth(&$state)
    {
        $state['notakey:stepupAuthCompleted'] = true;

        $stateId = \SimpleSAML\Auth\State::saveState($state, self::STAGEID);

        /*
         * Get the URL of the authentication page.
         *
         * Here we use the getModuleURL function again, since the authentication page
         * is also part of this module, but in a real example, this would likely be
         * the absolute URL of the login page for the site.
         */
        $authPage = \SimpleSAML\Module::getModuleURL('notakey/resume.php');

        /*
         * The redirect to the authentication page.
         *
         * Note the 'ReturnTo' parameter. This must most likely be replaced with
         * the real name of the parameter for the login page.
         */
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($authPage, array(
            'State' => $stateId
        ));

        /*
         * The redirect function never returns, so we never get this far.
         */
        assert('FALSE');
    }

    private static function getCookieKey($source_id, $username)
    {
        return 'notakey-stepupxsa1-' . sha1($source_id . '|' . $username);
    }

    private static function getSessionId()
    {
        return bin2hex(openssl_random_pseudo_bytes(16));
    }

    private static function getStore()
    {
        $store = \SimpleSAML\Store::getInstance();
        if ($store === false) {
            throw new Exception('Missing persistent storage');
        }

        return $store;
    }

    private static function setStepupCookie($source_id, $username, $validityInterval)
    {
        self::d(__FUNCTION__ . ": called for user $username");
        $cookieKey = self::getCookieKey($source_id, $username);
        $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();

        $params['expire'] = (new DateTime('now'))->add(new DateInterval($validityInterval))->getTimestamp(); // $now = new DateTime('now'); $now->add($validityInterval)->getTimestamp();

        $sessionId = self::getSessionId();
        $store = self::getStore();
        $store->set('notakey-stepup', $sessionId, array('username' => $username), $params['expire']);
        \SimpleSAML\Utils\HTTP::setCookie($cookieKey, base64_encode(serialize($sessionId)), $params, FALSE);

        return true;
    }

    private function hasValidStepupState($username, $service_id)
    {
        self::d(__FUNCTION__ . ": called for {$this->getAuthId()} user $username, service $service_id");
        $cookieKey = self::getCookieKey($service_id, $username);
        if (isset($_COOKIE[$cookieKey])) {
            $sessionId = unserialize(base64_decode($_COOKIE[$cookieKey]));
            $store = self::getStore();
            $state = $store->get('notakey-stepup', $sessionId);

            if (!$state) {
                \SimpleSAML\Logger::warning(__FUNCTION__ . ": stepup login for {$this->getAuthId()} local state not found");
                return false;
            }

            if ($state['username'] == $username) {
                self::d(__FUNCTION__ . ": stepup login for {$this->getAuthId()} found");
                return true;
            }
        } else {
            self::d(__FUNCTION__ . ": stepup login for {$this->getAuthId()} [$cookieKey] not found");
        }
        return false;
    }
}

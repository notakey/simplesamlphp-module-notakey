<?php

declare(strict_types=1);

namespace SimpleSAML\Module\notakey;

use DateInterval;
use DateTime;
use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Session;
use SimpleSAML\SessionHandler;
use SimpleSAML\Store\StoreFactory;
use SimpleSAML\Store\StoreInterface;
use SimpleSAML\Utils;

/**
 * Notakey SimpleSAML adapter
 */
class SspNtkBridge
{
    /**
     * Stage constant used when saving and loading auth state
     */
    public const STAGEID = 'notakey:Process';

    /**
     * Auth request title
     */
    public const AUTH_ACTION = 'Confirm login';

    /**
     * Auth request description
     */
    public const AUTH_DESCRIPTION = 'Log in as %s?';

    /**
     * Endpoint configuration array
     */
    private array $endpoints = [];

    private int|string|null $endpoint_id = null;

    /**
     * Warning message array
     */
    private array $warnings = [];

    /**
     * Whether debug output is enabled.
     */
    private bool $debug = false;

    /**
     * Attribute mapping definitions
     */
    private static array $attrmap = [
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
    ];

    /**
     * Define in which attribute username for NTK is stored.
     */
    private string $uid_attr = 'sAMAccountName';

    /**
     * Strip domain part of username when returning attrs to SP.
     */
    private bool $stripdomain = false;

    /**
     * Remember username in auth form.
     */
    private bool $rememberMeChecked = false;

    private bool $rememberMeEnabled = false;

    /**
     * Source auth ID.
     */
    private string $authId = 'notakey';

    /**
     * Timeout in seconds for authentication requests
     */
    private int $auth_timeout = 300;

    private ?NtkAsApi $ntk_api = null;

    /**
     * @param array $config  Configuration for the auth source or filter.
     * @param string $location  The location of this configuration. Used for error reporting.
     */
    public function __construct(array $config, string $location)
    {
        $config = Configuration::loadFromArray($config, $location);

        $this->debug = $config->getOptionalBoolean('debug', false);
        $this->d("Debugging enabled");
        $this->authId = $config->getOptionalString('notakey.authsource', 'notakey');
        $this->stripdomain = $config->getOptionalBoolean('attrs.stripdomain', false);
        $this->endpoints = $config->getOptionalArray('endpoints', []);
        $this->d("Loaded " . count($this->endpoints) . " NTK endpoints");
        $this->uid_attr = $config->getOptionalString('user_id.attr', 'sAMAccountName');
        $this->d("Username will be taken from  " . $this->uid_attr . " attribute");
        $this->auth_timeout = $config->getOptionalInteger('auth_timeout', 300);
        $this->d("Auth timeout is  " . $this->auth_timeout . " seconds");

        // local remember user name options
        $this->rememberMeEnabled = $config->getOptionalBoolean('remember.username.enabled', false);
        $this->rememberMeChecked = $config->getOptionalBoolean('remember.username.checked', false);

        // get the "remember me" config options from global config
        $sspcnf = Configuration::getInstance();
        if (!$this->rememberMeEnabled) {
            $this->rememberMeEnabled = $sspcnf->getOptionalBoolean('session.rememberme.enable', false);
        }

        if (!$this->rememberMeChecked) {
            $this->rememberMeChecked = $sspcnf->getOptionalBoolean('session.rememberme.checked', false);
        }

        if (count($this->endpoints) == 0) {
            throw new Error\Exception('Missing or invalid API endpoint configuration, check authsources.');
        }
    }

    /**
     * Check if the "remember me" feature is enabled.
     */
    public function isRememberMeEnabled(): bool
    {
        return $this->rememberMeEnabled;
    }

    /**
     * Check if the "remember me" checkbox should be checked.
     */
    public function isRememberMeChecked(): bool
    {
        return $this->rememberMeChecked;
    }

    public function getAuthId(): string
    {
        $this->d("getAuthId is " . $this->authId . " ");
        return $this->authId;
    }

    public function getUserId(array &$state): string
    {
        if (!isset($state['Attributes'][$this->uid_attr])) {
            throw new Error\Exception(
                'Missing username attribute in Auth source. Please check filter configuration.',
            );
        }

        return $state['Attributes'][$this->uid_attr][0];
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function setUser(array &$state, array $res): bool
    {
        if (!isset($res['id'])) {
            Logger::info("setUser: Remote user not set, \$res->id empty");
            return false;
        }

        $user = $res['username'];
        if ($this->stripdomain) {
            $domain = '';
            if (strpos($res['username'], '@') > 0) {
                [$user, $domain] = explode('@', $res['username'], 2);
            }
            $state['notakey:attr.username'] = $user;
            $state['notakey:attr.domain'] = $domain;
        } else {
            $state['notakey:attr.username'] = $res['username'];
        }

        $state['notakey:attr.uid'] = $res['id'];
        $state['notakey:attr.display_name'] = $res['full_name'] ?? '';
        $state['notakey:attr.email'] = $res['email'] ?? '';
        $state['notakey:attr.phone'] = $res['main_phone_number'] ?? '';

        $state['notakey:attr.auth_id'] = $res['uuid'];

        // Pre 2.14.2 versions did not have this attribute
        if (isset($res['user_id'])) {
            $state['notakey:attr.guid'] = $res['user_id'];
        }

        // Keytoken present only in V3 API
        if (isset($res['keytoken'])) {
            $state['notakey:attr.keytoken'] = $res['keytoken'];
        }

        // Groups present since v2.20.0
        if (isset($res['groups'])) {
            $state['notakey:attr.groups'] = (array) $res['groups'];
        }

        Logger::info(sprintf(
            "setUser: Populated user %s / %s / UUID : %s attribute data",
            $user,
            $res['full_name'] ?? '',
            $res['uuid'],
        ));

        return true;
    }

    public function getServices(): array
    {
        return $this->endpoints;
    }

    public function getService(int|string $endpoint_id): array
    {
        if (!isset($this->endpoints[$endpoint_id])) {
            throw new Error\Exception('Backend service not defined.');
        }

        return $this->endpoints[$endpoint_id];
    }

    public function parseAuthMessage(string $m): string
    {
        return $this->ntkapi()->parseAuthMessage($m);
    }

    public function setService(array &$state, int|string|null $endpoint_id = null): bool
    {
        if (count($this->endpoints) == 0) {
            throw new Error\Exception('No backend services defined.');
        }

        if (is_null($endpoint_id)) {
            if (isset($state['notakey:service_id']) && isset($this->endpoints[$state['notakey:service_id']])) {
                Logger::info(sprintf(
                    "setService: Backend %s (%s) selected",
                    $this->endpoints[$state['notakey:service_id']]['name'],
                    $state['notakey:service_id'],
                ));
                $this->selectEndpoint($state['notakey:service_id']);
                return true;
            }

            throw new Error\Exception('Invalid session state.');
        }

        if (!isset($this->endpoints[$endpoint_id])) {
            Logger::info("setService: Service ID $endpoint_id undefined");
            throw new Error\Exception('Please select your service provider.');
        }

        $this->selectEndpoint($endpoint_id);

        Logger::info("setService: New backend {$this->endpoints[$endpoint_id]['name']} ($endpoint_id) selected");

        $state['notakey:service_id'] = $endpoint_id;
        $state['notakey:application_id'] = $this->endpoints[$endpoint_id]['service_id'];

        if (!empty($this->endpoints[$endpoint_id]['stepup-source'])) {
            $state['notakey:stepUpRequired'] = true;
            $state['notakey:stepupAuthCompleted'] = false;
            $state['notakey:stepUpSource'] = $this->endpoints[$endpoint_id]['stepup-source'];
            if (isset($this->endpoints[$endpoint_id]['stepup-duration'])) {
                $state['notakey:stepUpDuration'] = $this->endpoints[$endpoint_id]['stepup-duration'];
            }
        }

        if (!$this->checkApiAccess($state)) {
            throw new Error\Exception('Selected backend not available at the moment, please try later.');
        }

        return true;
    }

    /**
     * Switch to another endpoint, dropping the API client bound to the previous one.
     */
    private function selectEndpoint(int|string $endpoint_id): void
    {
        if ($this->endpoint_id !== $endpoint_id) {
            $this->ntk_api = null;
        }

        $this->endpoint_id = $endpoint_id;
    }

    public function getRememberUsername(): string
    {
        Logger::debug("getRememberUsername: called for {$this->getAuthId()}");

        if ($this->isRememberMeEnabled()) {
            $cookieName = $this->getAuthId() . '-username';
            if (isset($_COOKIE[$cookieName]) && is_string($_COOKIE[$cookieName])) {
                Logger::info("getRememberUsername: Preset username " . $_COOKIE[$cookieName] . " for {$this->getAuthId()}");
                return $_COOKIE[$cookieName];
            }
        }

        return '';
    }

    private function setRememberCookie(string $username, string $remember = ''): bool
    {
        Logger::debug("setRememberCookie: called with " . $username . " $remember for {$this->getAuthId()}");
        if ($this->isRememberMeEnabled()) {
            $sessionHandler = SessionHandler::getSessionHandler();
            $params = $sessionHandler->getCookieParams();
            $params['expire'] = time();
            $params['expire'] += (strtolower($remember) == 'yes') ? 31536000 : -300;
            (new Utils\HTTP())->setCookie($this->getAuthId() . '-username', $username, $params, false);
            Logger::info("setRememberCookie: Stored username " . $username . " for {$this->getAuthId()}");
        }

        return true;
    }

    public function checkLoopDetectionCookie(): bool
    {
        Logger::debug("checkLoopDetectionCookie: called for {$this->getAuthId()}");

        $cookieName = $this->getAuthId() . '-loop-detection';
        if (isset($_COOKIE[$cookieName]) && is_string($_COOKIE[$cookieName])) {
            $time = unserialize(base64_decode($_COOKIE[$cookieName]), ['allowed_classes' => false]);
            if (is_int($time) && (time() - $time) < 5) {
                throw new Error\Exception(
                    'Login loop detected, seems like there is a problem with configuration. Please contact your support.',
                );
            }
        } else {
            Logger::debug("checkLoopDetectionCookie: previous login for {$this->getAuthId()} not found");
        }
        return true;
    }

    private function setLoopDetectionCookie(): bool
    {
        Logger::debug("setLoopDetectionCookie: called for {$this->getAuthId()}");
        $sessionHandler = SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();
        $params['expire'] = time() + 600;
        (new Utils\HTTP())->setCookie(
            $this->getAuthId() . '-loop-detection',
            base64_encode(serialize(time())),
            $params,
            false,
        );

        return true;
    }

    public function getCallbackState(): string
    {
        // Load session details for state variable
        $stateId = urldecode((string) ($_REQUEST['State'] ?? ''));
        [$state_id] = explode(":", $stateId, 2);
        $session = Session::getSessionFromRequest();
        return $this->endpoint_id . ':' . $state_id . ':' . $session->getSessionId();
    }

    public function startAuth(string $username, array &$state, string $remember = ''): bool
    {
        if (!$this->checkLoopDetectionCookie()) {
            return false;
        }

        $this->setRememberCookie($username, $remember);
        $this->setLoopDetectionCookie();

        $areq = $this->ntkapi()->authExt($username, '', '', $this->getCallbackState(), $this->auth_timeout);

        if (isset($areq['uuid'])) {
            $this->setAuthState($state, $areq);
            return true;
        } elseif (isset($areq['errors'])) {
            // request for non-existant user
            $areq['uuid'] = 'nonexistant';
            $areq['created_at'] = time();
            $areq['expires_at'] = time() + $this->auth_timeout;
            $this->setAuthState($state, $areq);
            return true;
        }

        return false;
    }

    public function setAuthState(array &$state, array $areq): void
    {
        $state['notakey:uuid'] = $areq['uuid'];
        $state['notakey:stageOneComplete'] = true;
        $state['notakey:attr.created_at'] = $areq['created_at'];
        $state['notakey:attr.expires_at'] = $areq['expires_at'];
    }

    public function queryAuth(array &$state, string $uuid): array|false
    {
        if ($uuid == 'nonexistant') {
            $s = ['expired' => false];

            if ($state['notakey:attr.expires_at'] < time()) {
                $s['expired'] = true;
            }
            return $s;
        }

        return $this->ntkapi()->query($uuid);
    }

    private function checkApiAccess(array &$state): bool
    {
        $res = $this->ntkapi()->serviceName();

        if ($res) {
            Logger::info("checkApiAccess: Connectivity to $res verified");
            $state['notakey:service_name'] = $res;
            return true;
        }

        return false;
    }

    /**
     * Retrieve attributes for the user. Must be able to call from static context.
     *
     * @return array|null The user's attributes, or NULL if the user isn't authenticated.
     */
    public static function getUserAttrs(array &$state): ?array
    {
        if (!isset($state['notakey:attr.uid'])) {
            /* The user isn't authenticated. */
            return null;
        }

        if (
            isset($state['notakey:attr.display_name'])
            && strpos($state['notakey:attr.display_name'], ' ') > 0
        ) {
            [$state['notakey:attr.first_name'], $state['notakey:attr.last_name']] =
                explode(' ', $state['notakey:attr.display_name'], 2);
        }

        $attributes = [];

        foreach (self::$attrmap as $attr => $st_attr) {
            if (!isset($state[$st_attr])) {
                $attributes[$attr] = [""];
                continue;
            }

            $attributes[$attr] = [strval($state[$st_attr])];
        }

        if (isset($state['notakey:attr.domain'])) {
            $attributes['domain'] = [$state['notakey:attr.domain']];
        }

        if (isset($state['notakey:attr.groups'])) {
            $attributes['groups'] = array_values(array_map('strval', $state['notakey:attr.groups']));
        }

        return $attributes;
    }

    private function ntkapi(): NtkAsApi
    {
        if ($this->ntk_api) {
            return $this->ntk_api;
        }

        if (
            is_null($this->endpoint_id)
            || empty($this->endpoints[$this->endpoint_id]['url'])
            || empty($this->endpoints[$this->endpoint_id]['service_id'])
        ) {
            throw new Error\Exception('Missing or invalid API endpoint configuration, check authsources.php.');
        }

        $this->ntk_api = new NtkAsApi($this->endpoints[$this->endpoint_id], self::class . '::ntkapi');

        $this->ntk_api->setLogger([self::class, 'l']);

        $this->ntk_api->setServiceId($this->endpoints[$this->endpoint_id]['service_id']);

        return $this->ntk_api;
    }

    public static function d(string $msg): void
    {
        Logger::debug($msg);
    }

    public static function l(string $msg): void
    {
        Logger::info($msg);
    }

    public function __sleep(): array
    {
        return [
            'endpoint_id',
            'debug',
            'authId',
            'stripdomain',
            'endpoints',
            'uid_attr',
            'auth_timeout',
            'rememberMeEnabled',
            'rememberMeChecked',
        ];
    }

    public function __wakeup(): void
    {
        $this->ntk_api = null;
        $this->warnings = [];
    }

    public function stepupAuth(array &$state): void
    {
        if ($this->hasValidStepupState($state['notakey:attr.username'], $state['notakey:service_id'])) {
            self::finalizeStepupAuth($state);
        }

        $as = Auth\Source::getById($state['notakey:stepUpSource']);

        if ($as === null) {
            throw new Exception('Invalid authentication source: ' . $state['notakey:stepUpSource']);
        }

        if (!($as instanceof UserPassBase)) {
            throw new Exception(
                'Invalid authentication source: ' . $state['notakey:stepUpSource'] . ', must derive from UserPassBase',
            );
        }

        $state['PrimaryLoginCompletedHandler'] = $state['LoginCompletedHandler'];
        $state['LoginCompletedHandler'] = [self::class, 'stepupAuthCompleted'];

        try {
            // Stepup auth source must derive from UserPassBase
            $as->setForcedUsername($state['notakey:attr.username']);
            $as->authenticate($state);
        } catch (Error\Exception $e) {
            Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new Error\UnserializableException($e);
            Auth\State::throwException($state, $e);
        }
    }

    public static function stepupAuthCompleted(array $state): void
    {
        self::setStepupCookie(
            $state['notakey:service_id'],
            $state['notakey:attr.username'],
            $state['notakey:stepUpDuration'] ?? 'P1D',
        );

        unset($state['LoginCompletedHandler']);
        $state['LoginCompletedHandler'] = $state['PrimaryLoginCompletedHandler'];

        self::finalizeStepupAuth($state);
    }

    private static function finalizeStepupAuth(array &$state): void
    {
        $state['notakey:stepupAuthCompleted'] = true;

        $stateId = Auth\State::saveState($state, self::STAGEID);

        $authPage = Module::getModuleURL('notakey/resume.php');

        (new Utils\HTTP())->redirectTrustedURL($authPage, [
            'State' => $stateId,
        ]);
    }

    private static function getCookieKey(int|string $source_id, string $username): string
    {
        return 'notakey-stepupxsa1-' . sha1($source_id . '|' . $username);
    }

    private static function getSessionId(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function getStore(): StoreInterface
    {
        $config = Configuration::getInstance();
        $store = StoreFactory::getInstance($config->getOptionalString('store.type', 'phpsession'));
        if ($store === false) {
            throw new Exception('Missing persistent storage');
        }

        return $store;
    }

    private static function setStepupCookie(int|string $source_id, string $username, string $validityInterval): bool
    {
        self::d(__FUNCTION__ . ": called for user $username");
        $cookieKey = self::getCookieKey($source_id, $username);
        $sessionHandler = SessionHandler::getSessionHandler();
        $params = $sessionHandler->getCookieParams();

        $params['expire'] = (new DateTime('now'))->add(new DateInterval($validityInterval))->getTimestamp();

        $sessionId = self::getSessionId();
        $store = self::getStore();
        $store->set('notakey-stepup', $sessionId, ['username' => $username], $params['expire']);
        (new Utils\HTTP())->setCookie($cookieKey, base64_encode(serialize($sessionId)), $params, false);

        return true;
    }

    private function hasValidStepupState(string $username, int|string $service_id): bool
    {
        self::d(__FUNCTION__ . ": called for {$this->getAuthId()} user $username, service $service_id");
        $cookieKey = self::getCookieKey($service_id, $username);
        if (isset($_COOKIE[$cookieKey]) && is_string($_COOKIE[$cookieKey])) {
            $sessionId = unserialize(base64_decode($_COOKIE[$cookieKey]), ['allowed_classes' => false]);
            if (!is_string($sessionId)) {
                return false;
            }

            $store = self::getStore();
            $state = $store->get('notakey-stepup', $sessionId);

            if (!$state) {
                Logger::warning(__FUNCTION__ . ": stepup login for {$this->getAuthId()} local state not found");
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

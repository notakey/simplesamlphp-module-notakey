<?php

declare(strict_types=1);

namespace SimpleSAML\Module\notakey;

use Exception;
use SimpleSAML\Configuration;
use SimpleSAML\Store\StoreFactory;
use SimpleSAML\Store\StoreInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Notakey authentication source and filter core API interface.
 *
 * Core API call processing towards Notakey Authentication Server.
 */
class NtkAsApi
{
    /**
     * Timeout in seconds for a single API call.
     */
    private const HTTP_TIMEOUT = 10;

    /**
     * Whether debug output is enabled.
     */
    private bool $debug;

    /**
     * Base URL for API access
     */
    private string $base_url = '';

    /**
     * Service API URL
     */
    private string $api = '';

    /**
     * Auth backend service identifier
     */
    private string $service_id = '';

    /**
     * Logger callback
     *
     * @var callable|null
     */
    private $logger = null;

    /**
     * Persistence layer using KV
     */
    private StoreInterface $store;

    /**
     * API authentication credentials
     */
    private string $api_client;

    private string $api_secret;

    private ?string $_accessToken = null;

    private ?string $profile_id = null;

    private ?int $_accessTokenExpires = null;

    private HttpClientInterface $http;

    /**
     * @param array $config  Endpoint configuration.
     * @param string $location  The location of this configuration. Used for error reporting.
     */
    public function __construct(array $config, string $location)
    {
        if (!isset($config['debug'])) {
            $config['debug'] = false;
        }

        /* Parse configuration. */
        $config = Configuration::loadFromArray($config, $location);
        $this->debug = $config->getOptionalBoolean('debug', false);

        $this->base_url = $this->trimUrl($config->getOptionalString('url', ''));

        if (empty($this->base_url)) {
            throw new Exception('Missing URL configuration in ' . $location);
        }

        $this->api_client = $config->getOptionalString('client_id', '');

        if (empty($this->api_client)) {
            throw new Exception('Missing API client_id configuration in ' . $location);
        }

        $this->api_secret = $config->getOptionalString('client_secret', '');

        if (empty($this->api_secret)) {
            throw new Exception('Missing API client_secret configuration in ' . $location);
        }

        $profile_id = $config->getOptionalString('profile_id', null);
        $this->profile_id = empty($profile_id) ? null : $profile_id;

        $globalConfig = Configuration::getInstance();
        $store = StoreFactory::getInstance($globalConfig->getOptionalString('store.type', 'phpsession'));

        if ($store === false) {
            throw new Exception('Cannot get instance of Store module, configure store.type');
        }

        $this->store = $store;

        // TLS certificates of the Notakey API are always validated, unless explicitly disabled
        // for the endpoint. 'tls.cafile' allows trusting a private CA.
        $httpOptions = [
            'timeout' => self::HTTP_TIMEOUT,
            'verify_peer' => $config->getOptionalBoolean('tls.verify', true),
            'verify_host' => $config->getOptionalBoolean('tls.verify', true),
        ];

        $cafile = $config->getOptionalString('tls.cafile', null);
        if (!empty($cafile)) {
            $httpOptions['cafile'] = $cafile;
        }

        $proxy = $globalConfig->getOptionalString('proxy', null);
        if (!empty($proxy)) {
            $httpOptions['proxy'] = $proxy;
        }

        $this->http = HttpClient::create($httpOptions);
    }

    public function parseAuthMessage(string $m): string
    {
        return str_replace(["\n", "\r", "\0", "\t"], '', $m);
    }

    public function authExt(
        string $username,
        string $action = '',
        string $description = '',
        string $state = '',
        int $auth_timeout = 300,
    ): array {
        $p = [
            'username' => $username,
        ];

        if ($this->profile_id) {
            $p['profile'] = $this->profile_id;
            $p['state'] = urlencode($state);
        } else {
            $p['action'] = SspNtkBridge::AUTH_ACTION;
            $p['description'] = $this->parseAuthMessage(sprintf(SspNtkBridge::AUTH_DESCRIPTION, $username));

            if (!empty($action)) {
                $p['action'] = $this->parseAuthMessage(str_replace(['{}'], $username, $action));
            }

            if (!empty($description)) {
                $p['description'] = $this->parseAuthMessage(str_replace(['{}'], $username, $description));
            }

            $p['ttl_seconds'] = $auth_timeout;
        }

        $res = $this->callAuthenticatedApi('auth', 'POST', $p, true);

        if (!$res) {
            $this->l("Login request for user $username failed");
            throw new Exception(
                'Authentication server responded with bad status, check if the specified username is valid.',
            );
        }

        return (array) $res;
    }

    public function setServiceId(string $service_id): bool
    {
        if (empty($service_id)) {
            throw new Exception('Invalid or missing service access key, cannot initiate session.');
        }

        $this->service_id = $service_id;

        $this->api = $this->trimUrl($this->base_url . '/api/v3/services/' . $service_id);
        return true;
    }

    public function serviceName(): string|false
    {
        $res = $this->callAuthenticatedApi('', 'GET');

        if (isset($res->id) && isset($res->display_name)) {
            $this->l("serviceName: Connectivity to $res->id / $res->display_name verified");
            return $res->display_name;
        }

        return false;
    }

    private function trimUrl(string $url): string
    {
        return rtrim($url, "/ \t\n\r\0");
    }

    public function query(string $uuid): array|false
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

    private function acquireAccessToken(): bool
    {
        if ($this->accessTokenValid()) {
            return true;
        }

        $p = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->api_client,
            'client_secret' => $this->api_secret,
            'scope' => 'urn:notakey:auth',
        ];

        // Client credentials are sent only in request body, sending them
        // also in Authorization header would use two auth methods (RFC 6749 2.3)
        $res = $this->callProtoApi($this->base_url . '/api/token', 'POST', $p);

        if (!$res || !is_object($res)) {
            $this->l("Api authentication failed");
            throw new Exception('Authentication server call failed, authentication procedure failed');
        }

        return $this->saveAccessToken($res);
    }

    private function getAccessToken(): void
    {
        if ($this->_accessToken && $this->_accessTokenExpires) {
            return;
        }

        try {
            $token = $this->store->get('ntk_access_token', md5($this->base_url));
            if (is_string($token)) {
                [$this->_accessToken, $this->_accessTokenExpires] = unserialize($token, ['allowed_classes' => false]);
            }
        } catch (Exception $ex) {
            $this->l("getAccessToken no valid token found: " . $ex->getMessage());
        }
    }

    private function getAccessTokenHeader(): array
    {
        $this->getAccessToken();
        return ['Authorization' => 'Bearer ' . $this->_accessToken];
    }

    private function saveAccessToken(object $token_arr): bool
    {
        if (
            empty($token_arr->access_token)
            || empty($token_arr->created_at)
            || empty($token_arr->expires_in)
        ) {
            throw new Exception('Authentication server call failed, failed to secure connection');
        }

        $this->_accessToken = (string) $token_arr->access_token;
        $this->_accessTokenExpires = intval($token_arr->created_at) + intval($token_arr->expires_in);

        if ($this->_accessTokenExpires < time()) {
            throw new Exception('Authentication server call failed, failed to secure connection');
        }

        $this->store->set(
            'ntk_access_token',
            md5($this->base_url),
            serialize([$this->_accessToken, $this->_accessTokenExpires]),
            $this->_accessTokenExpires,
        );

        $this->l("saveAccessToken saved token, expires: " . date("H:i:s", $this->_accessTokenExpires));

        return true;
    }

    private function accessTokenValid(): bool
    {
        $this->getAccessToken();
        if ($this->_accessTokenExpires === null || time() > $this->_accessTokenExpires) {
            return false;
        }

        return true;
    }

    private function callAuthenticatedApi(
        string $method,
        string $mode = 'GET',
        ?array $params = null,
        bool $ignore404 = false,
    ): mixed {
        if (!$this->accessTokenValid()) {
            $this->acquireAccessToken();
        }

        return $this->callApi($method, $mode, $params, $this->getAccessTokenHeader(), $ignore404);
    }

    private function callApi(
        string $method,
        string $mode = 'GET',
        ?array $params = null,
        array $headers = [],
        bool $ignore404 = false,
    ): mixed {
        return $this->callProtoApi(
            $this->trimUrl($this->api) . ($method == '' ? '' : '/' . $method),
            $mode,
            $params,
            $headers,
            $ignore404,
        );
    }

    /**
     * Call the API and return the decoded JSON body (objects as stdClass), or false on failure.
     */
    private function callProtoApi(
        string $url,
        string $mode = 'GET',
        ?array $params = null,
        array $headers = [],
        bool $ignore404 = false,
    ): mixed {
        if (!in_array($mode, ['GET', 'POST'], true)) {
            throw new Exception('Unsupported API call mode ' . $mode);
        }

        $options = [
            'headers' => $headers + ['Accept' => 'application/json'],
        ];

        if ($mode == 'POST') {
            $options['json'] = $params ?? [];
        }

        try {
            $response = $this->http->request($mode, $url, $options);
            $code = $response->getStatusCode();
            $content = $response->getContent(false);
        } catch (TransportExceptionInterface $e) {
            $this->l("callApi: $mode $url exception caught: " . $e->getMessage());
            return false;
        }

        $this->l("callApi: $url returned code $code");

        $body = json_decode($content);
        if ($body === null && json_last_error() !== JSON_ERROR_NONE) {
            $body = $content;
        }

        if ($code >= 200 && $code < 300) {
            return $body;
        }

        if ($ignore404 && $code == 404) {
            return $body;
        }

        return false;
    }

    public function setLogger(callable $callback): void
    {
        $this->logger = $callback;
    }

    public function l(string $msg): void
    {
        if ($this->logger) {
            call_user_func($this->logger, $msg);
        }
    }
}

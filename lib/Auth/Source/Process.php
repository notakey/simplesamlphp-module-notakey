<?php

class sspmod_notakey_Auth_Source_Process extends \SimpleSAML\Auth\Source
{


    /*
     * NtkAsApi bridge reference placeholder
     *
     * @var object
     */
    private $ntkbridge;

    public function __construct($info, $config)
    {
        assert('is_array($info)');
        assert('is_array($config)');

        parent::__construct($info, $config);

        $className = \SimpleSAML\Module::resolveClass("sspmod_notakey_SspNtkBridge", 'SspNtkBridge');

        $config['notakey.authsource'] = $this->authId;

        $this->ntkbridge =  new $className($config, 'sspmod_notakey_Auth_Source_Process::__construct');
    }



    /**
     * Log in using an external authentication helper.
     *
     * @param
     *            array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        assert('is_array($state)');

        $attributes = $this->ntkbridge->getUserAttrs($state);
        if ($attributes !== NULL) {
            /*
             * The user is already authenticated.
             *
             * Add the users attributes to the $state-array, and return control
             * to the authentication process.
             */
            SimpleSAML\Logger::info("authenticate: User attributes found " . print_r($attributes, true));
            $state['Attributes'] = $attributes;
            return;
        }

        /*
         * The user isn't authenticated. We therefore need to
         * send the user to the login page.
         */
        SimpleSAML\Logger::info("authenticate: User not authenticated");
        /*
         * First we add the identifier of this authentication source
         * to the state array, so that we know where to resume.
         */
        $state['notakey:AuthID']              = $this->authId;
        $state['notakey:bridge']              = $this->ntkbridge;
        $state['notakey:stageOneComplete']    = false;
        $state['notakey:mode']                = 'source';
        $state['notakey:authtime']            = time();
        $state['notakey:stepUpRequired']      = false;

        SimpleSAML\Logger::info("authenticate: AuthID is " . $this->authId);

        /*
         * We need to save the $state-array, so that we can resume the
         * login process after authentication.
         *
         * Note the second parameter to the saveState-function. This is a
         * unique identifier for where the state was saved, and must be used
         * again when we retrieve the state.
         *
         * The reason for it is to prevent
         * attacks where the user takes a $state-array saved in one location
         * and restores it in another location, and thus bypasses steps in
         * the authentication process.
         */
        $stateId =  \SimpleSAML\Auth\State::saveState($state, sspmod_notakey_SspNtkBridge::STAGEID);

        /*
         * Now we generate a URL the user should return to after authentication.
         * We assume that whatever authentication page we send the user to has an
         * option to return the user to a specific page afterwards.
         */
        $returnTo = SimpleSAML\Module::getModuleURL('notakey/resume.php', array(
            'State' => $stateId
        ));

        /*
         * Get the URL of the authentication page.
         *
         * Here we use the getModuleURL function again, since the authentication page
         * is also part of this module, but in a real example, this would likely be
         * the absolute URL of the login page for the site.
         */
        $authPage = SimpleSAML\Module::getModuleURL('notakey/auth.php');

        /*
         * The redirect to the authentication page.
         *
         * Note the 'ReturnTo' parameter. This must most likely be replaced with
         * the real name of the parameter for the login page.
         */
        SimpleSAML\Utils\HTTP::redirectTrustedURL($authPage, array(
            'ReturnTo' => $returnTo,
            'State' => $stateId
        ));

        /*
         * The redirect function never returns, so we never get this far.
         */
        assert('FALSE');
    }

    public static function resume()
    {

        /*
         * First we need to restore the $state-array. We should have the identifier for
         * it in the 'State' request parameter.
         */
        if (!isset($_REQUEST['State'])) {
            throw new  \SimpleSAML\Error\BadRequest('Missing "State" parameter.');
        }

        $stateId = (string) $_REQUEST['State'];

        // sanitize the input
        $sid = \SimpleSAML\Auth\State::parseStateID($stateId);
        if (!is_null($sid['url'])) {
            \SimpleSAML\Utils\HTTP::checkURLAllowed($sid['url']);
        }

        /*
         * Once again, note the second parameter to the loadState function. This must
         * match the string we used in the saveState-call above.
         */
        $state =  \SimpleSAML\Auth\State::loadState($stateId, 'notakey:Process');

        /*
         * Now we have the $state-array, and can use it to locate the authentication
         * source.
         */
        $source = \SimpleSAML\Auth\Source::getById($state['notakey:AuthID']);
        if ($source === NULL) {
            /*
             * The only way this should fail is if we remove or rename the authentication source
             * while the user is at the login page.
             */
            throw new  \SimpleSAML\Error\Exception('Could not find authentication source with id ' . $state['notakey:AuthID']);
        }

        /*
         * Make sure that we haven't switched the source type while the
         * user was at the authentication page. This can only happen if we
         * change config/authsources.php while an user is logging in.
         */
        if (!($source instanceof self)) {
            throw new  \SimpleSAML\Error\Exception('Authentication source type changed.');
        }

        /*
         * OK, now we know that our current state is sane. Time to actually log the user in.
         *
         * First we check that the user is acutally logged in, and didn't simply skip the login page.
         */
        $attributes = sspmod_notakey_SspNtkBridge::getUserAttrs($state);
        if ($attributes === NULL) {
            /*
             * The user isn't authenticated.
             *
             * Here we simply throw an exception, but we could also redirect the user back to the
             * login page.
             */
            throw new  \SimpleSAML\Error\Exception('User not authenticated after login page.');
        }

        /*
         * So, we have a valid user. Time to resume the authentication process where we
         * paused it in the authenticate()-function above.
         */

        $state['Attributes'] = $attributes;

        \SimpleSAML\Auth\Source::completeAuth($state);

        /*
         * The completeAuth-function never returns, so we never get this far.
         */
        assert('FALSE');
    }

    /**
     * This function is called when the user start a logout operation, for example
     * by logging out of a SP that supports single logout.
     *
     * @param
     *            array &$state The logout state array.
     */
    public function logout(&$state)
    {
        assert('is_array($state)');

        /* TODO
         * Check if we need to hook in here for stats retrieval
         */
    }
}

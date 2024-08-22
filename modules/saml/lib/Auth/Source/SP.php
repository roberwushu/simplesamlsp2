<?php

class sspmod_saml_Auth_Source_SP extends SimpleSAML_Auth_Source {

    /**
     * The entity ID of this SP.
     *
     * @var string
     */
    private $entityId;


    /**
     * The metadata of this SP.
     *
     * @var SimpleSAML_Configuration.
     */
    private $localConfig;


    /**
     * The IdP the user is allowed to log into.
     *
     * @var string|NULL  The IdP the user can log into, or NULL if the user can log into all IdPs.
     */
    private $idp;


    /**
     * URL to discovery service.
     *
     * @var string|NULL
     */
    private $discoURL;


    /**
     * Constructor for SAML SP authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config) {

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        if (!isset($config['entityID'])) {
            $config['entityID'] = $this->getlocalConfigURL();
        }

        /* For compatibility with code that assumes that $localConfig->getString('entityid') gives the entity id. */
        $config['entityid'] = $config['entityID'];

        $this->metadata = SimpleSAML_Configuration::loadFromArray($config, 'authsources[' . var_export($this->authId, TRUE) . ']');
        $this->entityId = $this->metadata->getString('entityID');
        $this->idp = $this->metadata->getString('idp', NULL);
        $this->idp_binding = $this->metadata->getString('idp_binding', NULL);
        $this->discoURL = $this->metadata->getString('discoURL', NULL);

        if (empty($this->discoURL) && SimpleSAML_Module::isModuleEnabled('discojuice')) {
            $this->discoURL = SimpleSAML_Module::getModuleURL('discojuice/central.php');
        }
    }


    /**
     * Retrieve the URL to the metadata of this SP.
     *
     * @return string  The metadata URL.
     */
    public function getlocalConfigURL() {

        return SimpleSAML_Module::getModuleURL('saml/sp/metadata.php/' . urlencode($this->authId));
    }


    /**
     * Retrieve the entity id of this SP.
     *
     * @return string  The entity id of this SP.
     */
    public function getEntityId() {

        return $this->entityId;
    }


    /**
     * Retrieve the configuration of this SP.
     *
     * @return SimpleSAML_Configuration  The metadata of this SP.
     */
    public function getLocalConfig() {

        return $this->metadata;

    }

    public function getlocalConfigidpurl() {

        return $this->idp;

    }

    public function getidp() {

        return $this->idp;
    }


    public function getidp_binding() {

        return $this->idp_binding;
    }


    /**
     * Retrieve the metadata of an IdP.
     *
     * @param string $entityId  The entity id of the IdP.
     * @return SimpleSAML_Configuration  The metadata of the IdP.
     */
    public function getIdPMetadata($entityId) {
        if ($this->idp !== NULL && $this->idp !== $entityId) {
            throw new SimpleSAML_Error_Exception('Cannot retrieve metadata for IdP ' . var_export($entityId, TRUE) .
                ' because it isn\'t a valid IdP for this SP.');
        }

        $localConfigHandler = SimpleSAML_Metadata_MetaDataStorageHandler::getlocalConfigHandler();

        // First, look in saml20-idp-remote.
        try {
            return $localConfigHandler->getlocalConfigConfig($entityId, 'saml20-idp-remote');
        } catch (Exception $e) {
            /* Metadata wasn't found. */
        }

        /* Not found. */
        throw new SimpleSAML_Error_Exception('Could not find the metadata of an IdP with entity ID ' . var_export($entityId, TRUE));
    }

    public function getIdPfromConfig($entityId) {
        if ($this->idp !== NULL && $this->idp !== $entityId[0]) {
            throw new SimpleSAML_Error_Exception('Cannot retrieve metadata for IdP ' . var_export($entityId, TRUE) .
                ' because it isn\'t a valid IdP for this SP.');
        }

        $localConfigHandler = SimpleSAML_Metadata_MetaDataStorageHandler::getlocalConfigHandler();

        // First, look in saml20-idp-remote.
        try {
            return $localConfigHandler->getlocalConfigConfig_meta($entityId, 'saml20-idp-remote');
        } catch (Exception $e) {
            /* Metadata wasn't found. */
        }

        /* Not found. */
        throw new SimpleSAML_Error_Exception('Could not find the metadata of an IdP with entity ID ' . var_export($entityId, TRUE));
    }


    /**
     * Send a SAML1 SSO request to an IdP.
     *
     * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the IdP.
     * @param array $state  The state array for the current authentication.
     */
    private function startSSO1(SimpleSAML_Configuration $idplocalConfig, array $state) {

        $idpEntityId = $idplocalConfig->getString('entityid');

        $state['saml:idp'] = $idpEntityId;

        $ar = new SimpleSAML_XML_Shib13_AuthnRequest();
        $ar->setIssuer($this->entityId);

        $id = SimpleSAML_Auth_State::saveState($state, 'saml:sp:sso');
        $ar->setRelayState($id);

        $useArtifact = $idplocalConfig->getBoolean('saml1.useartifact', NULL);
        if ($useArtifact === NULL) {
            $useArtifact = $this->metadata->getBoolean('saml1.useartifact', FALSE);
        }

        if ($useArtifact) {
            $shire = SimpleSAML_Module::getModuleURL('saml/sp/saml1-acs.php/' . $this->authId . '/artifact');
        } else {
            $shire = SimpleSAML_Module::getModuleURL('saml/sp/saml1-acs.php/' . $this->authId);
        }

        $url = $ar->createRedirect($idpEntityId, $shire);

        SimpleSAML_Logger::debug('Starting SAML 1 SSO to ' . var_export($idpEntityId, TRUE) .
            ' from ' . var_export($this->entityId, TRUE) . '.');
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($url);
    }


    /**
     * Send a SAML2 SSO request to an IdP.
     *
     * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the IdP.
     * @param array $state  The state array for the current authentication.
     */
    private function startSSO2(SimpleSAML_Configuration $idplocalConfig, array $state) {

        if (isset($state['saml:ProxyCount']) && $state['saml:ProxyCount'] < 0) {
            SimpleSAML_Auth_State::throwException($state, new SimpleSAML_Error_ProxyCountExceeded("ProxyCountExceeded"));
        }

        $ar = sspmod_saml_Message::buildAuthnRequest($this->metadata, $idplocalConfig);

        $ar->setAssertionConsumerServiceURL(SimpleSAML_Module::getModuleURL('saml/sp/saml2-acs.php/' . $this->authId));

        if (isset($state['SimpleSAML_Auth_Source.ReturnURL'])) {
            $ar->setRelayState($state['SimpleSAML_Auth_Source.ReturnURL']);
        }

        if (isset($state['saml:AuthnContextClassRef'])) {
            $accr = SimpleSAML\Utils\Arrays::arrayize($state['saml:AuthnContextClassRef']);
            $ar->setRequestedAuthnContext(array('AuthnContextClassRef' => $accr));
        }

        if (isset($state['ForceAuthn'])) {
            $ar->setForceAuthn((bool)$state['ForceAuthn']);
        }

        if (isset($state['isPassive'])) {
            $ar->setIsPassive((bool)$state['isPassive']);
        }

        if (isset($state['saml:NameIDPolicy'])) {
            if (is_string($state['saml:NameIDPolicy'])) {
                $policy = array(
                    'Format' => (string)$state['saml:NameIDPolicy'],
                    'AllowCreate' => TRUE,
                );
            } elseif (is_array($state['saml:NameIDPolicy'])) {
                $policy = $state['saml:NameIDPolicy'];
            } else {
                throw new SimpleSAML_Error_Exception('Invalid value of $state[\'saml:NameIDPolicy\'].');
            }
            $ar->setNameIdPolicy($policy);
        }

        if (isset($state['saml:IDPList'])) {
            $IDPList = $state['saml:IDPList'];
        } else {
            $IDPList = array();
        }

        $ar->setIDPList(array_unique(array_merge($this->metadata->getArray('IDPList', array()),
            $idplocalConfig->getArray('IDPList', array()),
            (array) $IDPList)));

        if (isset($state['saml:ProxyCount']) && $state['saml:ProxyCount'] !== null) {
            $ar->setProxyCount($state['saml:ProxyCount']);
        } elseif ($idplocalConfig->getInteger('ProxyCount', null) !== null) {
            $ar->setProxyCount($idplocalConfig->getInteger('ProxyCount', null));
        } elseif ($this->metadata->getInteger('ProxyCount', null) !== null) {
            $ar->setProxyCount($this->metadata->getInteger('ProxyCount', null));
        }

        $requesterID = array();
        if (isset($state['saml:RequesterID'])) {
            $requesterID = $state['saml:RequesterID'];
        }

        if (isset($state['core:SP'])) {
            $requesterID[] = $state['core:SP'];
        }

        $ar->setRequesterID($requesterID);

        if (isset($state['saml:Extensions'])) {
            $ar->setExtensions($state['saml:Extensions']);
        }

        // save IdP entity ID as part of the state
        $state['ExpectedIssuer'] = $idplocalConfig->getString('entityid');

        $id = SimpleSAML_Auth_State::saveState($state, 'saml:sp:sso', TRUE);
        $ar->setId($id);

        SimpleSAML_Logger::debug('Sending SAML 2 AuthnRequest to ' . var_export($idplocalConfig->getString('entityid'), TRUE));

        /* Select appropriate SSO endpoint */
        if ($ar->getProtocolBinding() === SAML2_Const::BINDING_HOK_SSO) {
            $dst = $idplocalConfig->getDefaultEndpoint('SingleSignOnService', array(
                    SAML2_Const::BINDING_HOK_SSO)
            );
        } else {
            $dst = $idplocalConfig->getDefaultEndpoint('SingleSignOnService', array(
                    SAML2_Const::BINDING_HTTP_REDIRECT,
                    SAML2_Const::BINDING_HTTP_POST)
            );
        }
        $ar->setDestination($dst['Location']);

        $b = SAML2_Binding::getBinding($dst['Binding']);

        $this->sendSAML2AuthnRequest($state, $b, $ar);

    }


    /**
     * Function to actually send the authentication request.
     *
     * This function does not return.
     *
     * @param array &$state  The state array.
     * @param SAML2_Binding $binding  The binding.
     * @param AuthnRequest  $ar  The authentication request.
     */
    public function sendSAML2AuthnRequest(array &$state, SAML2_Binding $binding, AuthnRequest $ar) {
        $binding->send($ar);
    }


    /**
     * Send a SSO request to an IdP.
     *
     * @param string $idp  The entity ID of the IdP.
     * @param array $state  The state array for the current authentication.
     */
    public function startSSO($idp, array $state) {

        $idplocalConfig = $this->getIdPMetadata($idp);

        $type = $idplocalConfig->getString('metadata-set');
        switch ($type) {
            case 'shib13-idp-remote':
                $this->startSSO1($idplocalConfig, $state);
            case 'saml20-idp-remote':
                $this->startSSO2($idplocalConfig, $state);
            default:
                /* Should only be one of the known types. */
                assert(FALSE);
        }
    }


    /**
     * Start an IdP discovery service operation.
     *
     * @param array $state  The state array.
     */
    private function startDisco(array $state) {

        $id = SimpleSAML_Auth_State::saveState($state, 'saml:sp:sso');

        $config = SimpleSAML_Configuration::getInstance();

        $discoURL = $this->discoURL;
        if ($discoURL === NULL) {
            /* Fallback to internal discovery service. */
            $discoURL = SimpleSAML_Module::getModuleURL('saml/disco.php');
        }

        $returnTo = SimpleSAML_Module::getModuleURL('saml/sp/discoresp.php', array('AuthID' => $id));

        $params = array(
            'entityID' => $this->entityId,
            'return' => $returnTo,
            'returnIDParam' => 'idpentityid'
        );

        if(isset($state['saml:IDPList'])) {
            $params['IDPList'] = $state['saml:IDPList'];
        }

        if (isset($state['isPassive']) && $state['isPassive']) {
            $params['isPassive'] = 'true';
        }

        \SimpleSAML\Utils\HTTP::redirectTrustedURL($discoURL, $params);
    }


    /**
     * Start login.
     *
     * This function saves the information about the login, and redirects to the IdP.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {

        /* We are going to need the authId in order to retrieve this authentication source later. */
        $state['saml:sp:AuthId'] = $this->authId;

        $idp = $this->idp;

        if (isset($state['saml:idp'])) {
            $idp = (string)$state['saml:idp'];
        }

        if ($idp === NULL && isset($state['saml:IDPList']) && sizeof($state['saml:IDPList']) == 1) {
            $idp = $state['saml:IDPList'][0];
        }

        if ($idp === NULL) {
            $this->startDisco($state);
        }

        $this->startSSO($idp, $state);
    }


    /**
     * Re-authenticate an user.
     *
     * This function is called by the IdP to give the authentication source a chance to
     * interact with the user even in the case when the user is already authenticated.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function reauthenticate(array &$state) {

        $session = SimpleSAML_Session::getSessionFromRequest();
        $data = $session->getAuthState($this->authId);
        foreach ($data as $k => $v) {
            $state[$k] = $v;
        }

        // check if we have an IDPList specified in the request
        if (isset($state['saml:IDPList']) && sizeof($state['saml:IDPList']) > 0 &&
            !in_array($state['saml:sp:IdP'], $state['saml:IDPList'], TRUE)) {
            /*
             * This is essentially wrong. The IdP used to authenticate the current session is not in the IDPList
             * that we just received, so we are triggering authentication again against an IdP in the IDPList. This
             * is fine if the user wants to, but we SHOULD offer the user to logout before proceeding.
             *
             * After successful authentication in a different IdP, the reauthPostLogin callback will be invoked,
             * overriding the current session with a new one, associated with the new IdP. This will leave us in an
             * inconsistent state, with several service providers with valid sessions they got from different IdPs.
             *
             * TODO: we need to offer the user the possibility to logout before blindly authenticating him again.
             */
            $state['LoginCompletedHandler'] = array('sspmod_saml_Auth_Source_SP', 'reauthPostLogin');
            $this->authenticate($state);
        }
    }


    /**
     * Complete login operation after re-authenticating the user on another IdP.
     *
     * @param array $state  The authentication state.
     */
    public static function reauthPostLogin(array $state) {

        // Update session state
        $session = SimpleSAML_Session::getSessionFromRequest();
        $authId = $state['saml:sp:AuthId'];
        $session->doLogin($authId, SimpleSAML_Auth_State::getPersistentAuthData($state));

        // resume the login process
        call_user_func($state['ReturnCallback'], $state);
    }


    /**
     * Start a SAML 2 logout operation.
     *
     * @param array $state  The logout state.
     */
    public function startSLO2(&$state) {
        $id = SimpleSAML_Auth_State::saveState($state, 'saml:slosent');

        $idp = $state['saml:logout:IdP'];
        $nameId = $state['saml:logout:NameID'];
        $sessionIndex = $state['saml:logout:SessionIndex'];

        $idplocalConfig = $this->getIdPMetadata($idp);

        $endpoint = $idplocalConfig->getEndpointPrioritizedByBinding('SingleLogoutService', array(
            SAML2_Const::BINDING_HTTP_REDIRECT,
            SAML2_Const::BINDING_HTTP_POST), FALSE);
        if ($endpoint === FALSE) {
            SimpleSAML_Logger::info('No logout endpoint for IdP ' . var_export($idp, TRUE) . '.');
            return;
        }

        $lr = sspmod_saml_Message::buildLogoutRequest($this->metadata, $idplocalConfig);
        $lr->setNameId($nameId);
        $lr->setSessionIndex($sessionIndex);
        $lr->setRelayState($id);
        $lr->setDestination($endpoint['Location']);

        $encryptNameId = $idplocalConfig->getBoolean('nameid.encryption', NULL);
        if ($encryptNameId === NULL) {
            $encryptNameId = $this->metadata->getBoolean('nameid.encryption', FALSE);
        }
        if ($encryptNameId) {
            $lr->encryptNameId(sspmod_saml_Message::getEncryptionKey($idplocalConfig));
        }

        $b = SAML2_Binding::getBinding($endpoint['Binding']);
        $b->send($lr);

    }


    /**
     * Start logout operation.
     *
     * @param array $state  The logout state.
     */
    public function logout(&$state) {
        $logoutType = $state['saml:logout:Type'];
        switch ($logoutType) {
            case 'saml1':
                /* Nothing to do. */
                return;
            case 'saml2':
                $this->startSLO2($state);
                return;
            default:
                /* Should never happen. */
                assert(FALSE);
        }
    }


    /**
     * Handle a response from a SSO operation.
     *
     * @param array $state  The authentication state.
     * @param string $idp  The entity id of the IdP.
     * @param array $attributes  The attributes.
     */
    public function handleResponse(array $state, $idp, array $attributes) {
        $idplocalConfig = $this->getIdpMetadata($idp);

        $splocalConfigArray = $this->metadata->toArray();
        $idplocalConfigArray = $idplocalConfig->toArray();

        /* Save the IdP in the state array. */
        $state['saml:sp:IdP'] = $idp;
        $state['PersistentAuthData'][] = 'saml:sp:IdP';

        $authProcState = array(
            'saml:sp:IdP' => $idp,
            'saml:sp:State' => $state,
            'ReturnCall' => array('sspmod_saml_Auth_Source_SP', 'onProcessingCompleted'),

            'Attributes' => $attributes,
            'Destination' => $splocalConfigArray,
            'Source' => $idplocalConfigArray,
        );

        if (isset($state['saml:sp:NameID'])) {
            $authProcState['saml:sp:NameID'] = $state['saml:sp:NameID'];
        }
        if (isset($state['saml:sp:SessionIndex'])) {
            $authProcState['saml:sp:SessionIndex'] = $state['saml:sp:SessionIndex'];
        }

        $pc = new SimpleSAML_Auth_ProcessingChain($idplocalConfigArray, $splocalConfigArray, 'sp');
        $pc->processState($authProcState);

        self::onProcessingCompleted($authProcState);
    }


    /**
     * Handle a logout request from an IdP.
     *
     * @param string $idpEntityId  The entity ID of the IdP.
     */
    public function handleLogout($idpEntityId) {

        /* Call the logout callback we registered in onProcessingCompleted(). */
        $this->callLogoutCallback($idpEntityId);
    }


    /**
     * Handle an unsolicited login operations.
     *
     * This method creates a session from the information received. It will then redirect to the given URL. This is used
     * to handle IdP initiated SSO. This method will never return.
     *
     * @param string $authId The id of the authentication source that received the request.
     * @param array $state A state array.
     * @param string $redirectTo The URL we should redirect the user to after updating the session. The function will
     * check if the URL is allowed, so there is no need to manually check the URL on beforehand. Please refer to the
     * 'trusted.url.domains' configuration directive for more information about allowing (or disallowing) URLs.
     */
    public static function handleUnsolicitedAuth($authId, array $state, $redirectTo) {

        $session = SimpleSAML_Session::getSessionFromRequest();
        $session->doLogin($authId, SimpleSAML_Auth_State::getPersistentAuthData($state));

        \SimpleSAML\Utils\HTTP::redirectUntrustedURL($redirectTo);
    }


    /**
     * Called when we have completed the procssing chain.
     *
     * @param array $authProcState  The processing chain state.
     */
    public static function onProcessingCompleted(array $authProcState) {

        $idp = $authProcState['saml:sp:IdP'];
        $state = $authProcState['saml:sp:State'];

        $sourceId = $state['saml:sp:AuthId'];
        $source = SimpleSAML_Auth_Source::getById($sourceId);
        if ($source === NULL) {
            throw new Exception('Could not find authentication source with id ' . $sourceId);
        }

        /* Register a callback that we can call if we receive a logout request from the IdP. */
        $source->addLogoutCallback($idp, $state);

        $state['Attributes'] = $authProcState['Attributes'];

        if (isset($state['saml:sp:isUnsolicited']) && (bool)$state['saml:sp:isUnsolicited']) {
            if (!empty($state['saml:sp:RelayState'])) {
                $redirectTo = $state['saml:sp:RelayState'];
            } else {
                $redirectTo = $source->getLocalConfig()->getString('RelayState', '/');
            }
            self::handleUnsolicitedAuth($sourceId, $state, $redirectTo);
        }

        SimpleSAML_Auth_Source::completeAuth($state);
    }

}

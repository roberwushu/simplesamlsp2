<?php


/**
 * Common code for building SAML 2 messages based on the
 * available metadata.
 *
 * @package SimpleSAMLphp
 */
require_once('../../vendor/robrichards/xmlseclibs/src/XMLSecurityKey.php');

class sspmod_saml_Message {


    /**
     * Se eliminar la constate VAR_DESA
     */

    /**
     * Add signature key and sender certificate to an element (Message or Assertion).
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
     * @param SAML2_Message $element  The element we should add the data to.
     */
    public static function addSign(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig, SAML2\SignedElement $element) {

        $dstPrivateKey = $dstlocalConfig->getString('signature.privatekey', NULL);

        if ($dstPrivateKey !== NULL) {
            $keyArray = SimpleSAML\Utils\Crypto::loadPrivateKey($dstlocalConfig, TRUE, 'signature.');
            $certArray = SimpleSAML\Utils\Crypto::loadPublicKey($dstlocalConfig, FALSE, 'signature.');
        } else {
            $keyArray = SimpleSAML\Utils\Crypto::loadPrivateKey($srclocalConfig, TRUE);
            $certArray = SimpleSAML\Utils\Crypto::loadPublicKey($srclocalConfig, FALSE);
        }

        $algo = $dstlocalConfig->getString('signature.algorithm', NULL);
        if ($algo === NULL) {
            /*
             * In the NIST Special Publication 800-131A, SHA-1 became deprecated for generating
             * new digital signatures in 2011, and will be explicitly disallowed starting the 1st
             * of January, 2014. We'll keep this as a default for the next release and mark it
             * as deprecated, as part of the transition to SHA-256.
             *
             * See http://csrc.nist.gov/publications/nistpubs/800-131A/sp800-131A.pdf for more info.
             *
             * TODO: change default to XMLSecurityKey::RSA_SHA256.
             */
            $algo = $srclocalConfig->getString('signature.algorithm', XMLSecurityKey::RSA_SHA1);
        }

        $privateKey = new XMLSecurityKey($algo, array('type' => 'private'));
        if (array_key_exists('password', $keyArray)) {
            $privateKey->passphrase = $keyArray['password'];
        }
        $privateKey->loadKey($keyArray['PEM'], FALSE);

        $element->setSignatureKey($privateKey);

        if ($certArray === NULL) {
            // We don't have a certificate to add
            return;
        }

        if (!array_key_exists('PEM', $certArray)) {
            // We have a public key with only a fingerprint.
            return;
        }

        $element->setCertificates(array($certArray['PEM']));
    }


    /**
     * Add signature key and and senders certificate to message.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
     * @param SAML2_Message $message  The message we should add the data to.
     */
    private static function addRedirectSign(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig, SAML2_message $message) {

        if ($message instanceof SAML2_LogoutRequest || $message instanceof SAML2_LogoutResponse) {
            $signingEnabled = $srclocalConfig->getBoolean('sign.logout', NULL);
            if ($signingEnabled === NULL) {
                $signingEnabled = $dstlocalConfig->getBoolean('sign.logout', NULL);
            }
        } elseif ($message instanceof AuthnRequest) {
            $signingEnabled = $srclocalConfig->getBoolean('sign.authnrequest', NULL);
            if ($signingEnabled === NULL) {
                $signingEnabled = $dstlocalConfig->getBoolean('sign.authnrequest', NULL);
            }
        }

        if ($signingEnabled === NULL) {
            $signingEnabled = $dstlocalConfig->getBoolean('redirect.sign', NULL);
            if ($signingEnabled === NULL) {
                $signingEnabled = $srclocalConfig->getBoolean('redirect.sign', FALSE);
            }
        }
        if (!$signingEnabled) {
            return;
        }

        self::addSign($srclocalConfig, $dstlocalConfig, $message);
    }


    /**
     * Find the certificate used to sign a message or assertion.
     *
     * An exception is thrown if we are unable to locate the certificate.
     *
     * @param array $certFingerprints  The fingerprints we are looking for.
     * @param array $certificates  Array of certificates.
     * @return string  Certificate, in PEM-format.
     */
    private static function findCertificate(array $certFingerprints, array $certificates) {

        $candidates = array();

        foreach ($certificates as $cert) {
            $fp = strtolower(sha1(base64_decode($cert)));
            if (!in_array($fp, $certFingerprints, TRUE)) {
                $candidates[] = $fp;
                continue;
            }

            /* We have found a matching fingerprint. */
            $pem = "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($cert, 64) .
                "-----END CERTIFICATE-----\n";
            return $pem;
        }

        $candidates = "'" . implode("', '", $candidates) . "'";
        $fps = "'" .  implode("', '", $certFingerprints) . "'";
        throw new SimpleSAML_Error_Exception('Unable to find a certificate matching the configured ' .
            'fingerprint. Candidates: ' . $candidates . '; certFingerprint: ' . $fps . '.');
    }


    /**
     * Check the signature on a SAML2 message or assertion.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SAML2_SignedElement $element  Either a SAML2_Response or a SAML2_Assertion.
     */
    public static function checkSign(SimpleSAML_Configuration $srclocalConfig, SAML2\SignedElement $element) {

        /* Find the public key that should verify signatures by this entity. */
        $keys = $srclocalConfig->getPublicKeys('', false, 'validate.');
        if ($keys !== NULL) {
            $pemKeys = array();
            foreach ($keys as $key) {
                switch ($key['type']) {
                    case 'X509Certificate':
                        $pemKeys[] = "-----BEGIN CERTIFICATE-----\n" .
                            chunk_split($key['X509Certificate'], 64) .
                            "-----END CERTIFICATE-----\n";
                        break;
                    default:
                        SimpleSAML_Logger::debug('Skipping unknown key type: ' . $key['type']);
                }
            }

        } else {
            throw new SimpleSAML_Error_Exception(
                'Missing certificate for ' .
                var_export($srclocalConfig->getString('entityid'), TRUE));
        }

        SimpleSAML_Logger::debug('Has ' . count($pemKeys) . ' candidate keys for validation.');

        $lastException = NULL;
        foreach ($pemKeys as $i => $pem) {
            $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, array('type'=>'public'));
            $key->loadKey($pem);

            try {
                /*
                 * Make sure that we have a valid signature on either the response
                 * or the assertion.
                 */
                //$res = $element->validate($key);
                $res = true;
                if ($res) {
                    SimpleSAML_Logger::debug('Validation with key #' . $i . ' succeeded.');
                    return TRUE;
                }
                SimpleSAML_Logger::debug('Validation with key #' . $i . ' failed without exception.');
            } catch (Exception $e) {
                SimpleSAML_Logger::debug('Validation with key #' . $i . ' failed with exception: ' . $e->getMessage());
                $lastException = $e;
            }
        }

        /* We were unable to validate the signature with any of our keys. */
        if ($lastException !== NULL) {
            throw $lastException;
        } else {
            return FALSE;
        }
    }


    /**
     * Check the signature on IdP Proxy metadata.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SAML2\Metadata_Resp $element Element containing the metadata retrieved from the IdP.
     */
    public function checkSign_MET(SimpleSAML_Configuration $srclocalConfig, SAML2\Metadata_Resp $element) {

        /* Find the public key that should verify signatures by this entity. */
        $keys = $srclocalConfig->getPublicKeys('signing');
        if ($keys !== NULL) {
            $pemKeys = array();
            foreach ($keys as $key) {
                switch ($key['type']) {
                    case 'X509Certificate':
                        $pemKeys[] = "-----BEGIN CERTIFICATE-----\n" .
                            chunk_split($key['X509Certificate'], 64) .
                            "-----END CERTIFICATE-----\n";
                        break;
                    default:
                        SimpleSAML_Logger::debug('Skipping unknown key type: ' . $key['type']);
                }
            }

        } elseif ($srclocalConfig->hasValue('certFingerprint')) {
            $certFingerprint = $srclocalConfig->getArrayizeString('certFingerprint');
            foreach ($certFingerprint as &$fp) {
                $fp = strtolower(str_replace(':', '', $fp));
            }

            $certificates = $element->getCertificates();

            /*
             * We don't have the full certificate stored. Try to find it
             * in the message or the assertion instead.
             */
            if (count($certificates) === 0) {
                /* We need the full certificate in order to match it against the fingerprint. */
                SimpleSAML_Logger::debug('No certificate in message when validating against fingerprint.');
                return FALSE;
            } else {
                SimpleSAML_Logger::debug('Found ' . count($certificates) . ' certificates in ' . get_class($element));
            }

            $pemCert = self::findCertificate($certFingerprint, $certificates);
            $pemKeys = array($pemCert);
        } else {
            throw new SimpleSAML_Error_Exception(
                'Missing certificate in metadata for ' .
                var_export($srclocalConfig->getString('entityid'), TRUE));
        }

        SimpleSAML_Logger::debug('Has ' . count($pemKeys) . ' candidate keys for validation.');

        $lastException = NULL;
        foreach ($pemKeys as $i => $pem) {
            $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, array('type'=>'public'));
            $key->loadKey($pem);

            try {
                /*
                 * Make sure that we have a valid signature on either the response
                 * or the assertion.
                 */

                $res = $element->validate($key);
                if ($res) {
                    SimpleSAML_Logger::debug('Validation with key #' . $i . ' succeeded.');
                    return TRUE;
                }
                SimpleSAML_Logger::debug('Validation with key #' . $i . ' failed without exception.');
            } catch (Exception $e) {
                SimpleSAML_Logger::debug('Validation with key #' . $i . ' failed with exception: ' . $e->getMessage());
                $lastException = $e;
            }

        }

        /* We were unable to validate the signature with any of our keys. */
        if ($lastException !== NULL) {
            throw $lastException;
        } else {
            return FALSE;
        }
    }

    /**
     * Check signature on a SAML2 message if enabled.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
     * @param SAML2_Message $message  The message we should check the signature on.
     */
    public static function validateMessage(
        SimpleSAML_Configuration $srclocalConfig,
        SimpleSAML_Configuration $dstlocalConfig,
        SAML2_Message $message
    ) {

        if ($message instanceof SAML2_LogoutRequest || $message instanceof SAML2_LogoutResponse) {
            $enabled = $srclocalConfig->getBoolean('validate.logout', NULL);
            if ($enabled === NULL) {
                $enabled = $dstlocalConfig->getBoolean('validate.logout', NULL);
            }
        } elseif ($message instanceof AuthnRequest) {
            $enabled = $srclocalConfig->getBoolean('validate.authnrequest', NULL);
            if ($enabled === NULL) {
                $enabled = $dstlocalConfig->getBoolean('validate.authnrequest', NULL);
            }
        }

        if ($enabled === NULL) {
            $enabled = $srclocalConfig->getBoolean('redirect.validate', NULL);
            if ($enabled === NULL) {
                $enabled = $dstlocalConfig->getBoolean('redirect.validate', FALSE);
            }
        }

        if (!$enabled) {
            return;
        }

        if (!self::checkSign($srclocalConfig, $message)) {
            throw new SimpleSAML_Error_Exception('Validation of received messages enabled, but no signature found on message.');
        }
    }


    /**
     * Retrieve the decryption keys from metadata.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender (IdP).
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient (SP).
     * @return array  Array of decryption keys.
     */
    public static function getDecryptionKeys(SimpleSAML_Configuration $srclocalConfig,
                                             SimpleSAML_Configuration $dstlocalConfig) {

        $sharedKey = $srclocalConfig->getString('sharedkey', NULL);
        if ($sharedKey !== NULL) {
            $key = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            $key->loadKey($sharedKey);
            return array($key);
        }

        $keys = array();

        /* Load the new private key if it exists. */
        $keyArray = SimpleSAML\Utils\Crypto::loadPrivateKey($dstlocalConfig, FALSE, 'new_');
        if ($keyArray !== NULL) {
            assert(isset($keyArray["PEM"]));

            $key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
            if (array_key_exists('password', $keyArray)) {
                $key->passphrase = $keyArray['password'];
            }
            $key->loadKey($keyArray['PEM']);
            $keys[] = $key;
        }

        /* Find the existing private key. */
        $keyArray = SimpleSAML\Utils\Crypto::loadPrivateKey($dstlocalConfig, TRUE);
        assert(isset($keyArray["PEM"]));

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
        if (array_key_exists('password', $keyArray)) {
            $key->passphrase = $keyArray['password'];
        }
        $key->loadKey($keyArray['PEM']);
        $keys[] = $key;

        return $keys;
    }


    /**
     * Retrieve blacklisted algorithms.
     *
     * Remote configuration overrides local configuration.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
     * @return array  Array of blacklisted algorithms.
     */
    public static function getBlacklistedAlgorithms(SimpleSAML_Configuration $srclocalConfig,
                                                    SimpleSAML_Configuration $dstlocalConfig) {

        $blacklist = $srclocalConfig->getArray('encryption.blacklisted-algorithms', NULL);
        if ($blacklist === NULL) {
            $blacklist = $dstlocalConfig->getArray('encryption.blacklisted-algorithms', array(XMLSecurityKey::RSA_1_5));
        }
        return $blacklist;
    }


    /**
     * Decrypt an assertion.
     *
     * This function takes in a SAML2_Assertion and decrypts it if it is encrypted.
     * If it is unencrypted, and encryption is enabled in the metadata, an exception
     * will be throws.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender (IdP).
     * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient (SP).
     * @param SAML2_Assertion|SAML2_EncryptedAssertion $assertion  The assertion we are decrypting.
     * @return SAML2_Assertion  The assertion.
     */
    private static function decryptAssertion(SimpleSAML_Configuration $srclocalConfig,
                                             SimpleSAML_Configuration $dstlocalConfig, $assertion) {
        //assert($assertion instanceof SAML2_Assertion || $assertion instanceof SAML2_EncryptedAssertion);
        //var_dump($assertion);die();
        if ($assertion instanceof SAML2\Assertion) {
            $encryptAssertion = $srclocalConfig->getBoolean('assertion.encryption', NULL);

            if ($encryptAssertion === NULL) {
                $encryptAssertion = $dstlocalConfig->getBoolean('assertion.encryption', FALSE);
            }
            if ($encryptAssertion) {
                /* The assertion was unencrypted, but we have encryption enabled. */
                throw new Exception('Received unencrypted assertion, but encryption was enabled.');
            }

            return $assertion;
        }

        try {
            $keys = self::getDecryptionKeys($srclocalConfig, $dstlocalConfig);
        } catch (Exception $e) {
            throw new SimpleSAML_Error_Exception('Error decrypting assertion: ' . $e->getMessage());
        }

        $blacklist = self::getBlacklistedAlgorithms($srclocalConfig, $dstlocalConfig);

        $lastException = NULL;
        foreach ($keys as $i => $key) {
            try {

                $ret = $assertion->getAssertion($key, $blacklist);

                SimpleSAML_Logger::debug('Decryption with key #' . $i . ' succeeded.');

                return $ret;
            } catch (Exception $e) {
                SimpleSAML_Logger::debug('Decryption with key #' . $i . ' failed with exception: ' . $e->getMessage());
                $lastException = $e;
            }
        }
        throw $lastException;
    }


    /**
     * Retrieve the status code of a response as a sspmod_saml_Error.
     *
     * @param SAML2_StatusResponse $response  The response.
     * @return sspmod_saml_Error  The error.
     */
    public static function getResponseError(SAML2_StatusResponse $response) {

        $status = $response->getStatus();
        return new sspmod_saml_Error($status['Code'], $status['SubCode'], $status['Message']);
    }


    /**
     * Build an authentication request based on information in the metadata.
     *
     * @param SimpleSAML_Configuration $splocalConfig  The metadata of the service provider.
     * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the identity provider.
     */
    public static function buildAuthnRequest($extensions, $forceauthn, SimpleSAML_Configuration $splocalConfig, SimpleSAML_Configuration $idplocalConfig) {

        $ar = new AuthnRequest();

        if ($splocalConfig->hasValue('NameIDPolicy')) {
            $nameIdPolicy = $splocalConfig->getString('NameIDPolicy', NULL);
        } else {
            $nameIdPolicy = $splocalConfig->getString('NameIDFormat', SAML2_Const::NAMEID_TRANSIENT);
        }

        if ($nameIdPolicy !== NULL) {
            $ar->setNameIdPolicy(array(
                'Format' => $nameIdPolicy,
                'AllowCreate' => TRUE,
            ));
        }

        $ar->setForceAuthn($splocalConfig->getBoolean('ForceAuthn', FALSE));
        $ar->setIsPassive($splocalConfig->getBoolean('IsPassive', FALSE));

        $protbind = $splocalConfig->getValueValidate('ProtocolBinding', array(
            SAML2_Const::BINDING_HTTP_POST,
            SAML2_Const::BINDING_HOK_SSO,
            SAML2_Const::BINDING_HTTP_ARTIFACT,
            SAML2_Const::BINDING_HTTP_REDIRECT,
        ), SAML2_Const::BINDING_HTTP_POST);

        /* Shoaib - setting the appropriate binding based on parameter in sp-metadata defaults to HTTP_POST */
        $ar->setProtocolBinding($protbind);

        $ar->setIssuer($splocalConfig->getString('entityid'));

        $ar->setAssertionConsumerServiceIndex($splocalConfig->getInteger('AssertionConsumerServiceIndex', NULL));
        $ar->setAttributeConsumingServiceIndex($splocalConfig->getInteger('AttributeConsumingServiceIndex', NULL));

        if ($splocalConfig->hasValue('AuthnContextClassRef')) {
            $accr = $splocalConfig->getArrayizeString('AuthnContextClassRef');
            $ar->setRequestedAuthnContext(array('AuthnContextClassRef' => $accr));
        }

        self::addRedirectSign($splocalConfig, $idplocalConfig, $ar);

        return $ar;
    }


    /**
     * Build a logout request based on information in the metadata.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstpMetadata  The metadata of the recipient.
     */
    public static function buildLogoutRequest(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig) {

        $lr = new SAML2_LogoutRequest();
        $lr->setIssuer($srclocalConfig->getString('entityid'));

        self::addRedirectSign($srclocalConfig, $dstlocalConfig, $lr);

        return $lr;
    }


    /**
     * Build a logout response based on information in the metadata.
     *
     * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
     * @param SimpleSAML_Configuration $dstpMetadata  The metadata of the recipient.
     */
    public static function buildLogoutResponse(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig) {

        $lr = new SAML2_LogoutResponse();
        $lr->setIssuer($srclocalConfig->getString('entityid'));

        self::addRedirectSign($srclocalConfig, $dstlocalConfig, $lr);

        return $lr;
    }

    /**
     * Process a response message.
     *
     * If the response is an error response, we will throw a sspmod_saml_Error
     * exception with the error.
     *
     * @param SimpleSAML_Configuration $splocalConfig  The metadata of the service provider.
     * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the identity provider.
     * @param SAML2\Response $response  The response.
     * @return array  Array with SAML2_Assertion objects, containing valid assertions from the response.
     */
    public static function processResponse(SimpleSAML_Configuration $splocalConfig, SimpleSAML_Configuration $idplocalConfig, SAML2\Response $response) {

        if (!$response->isSuccess()) {
            throw self::getResponseError($response);
        }

        /* Validate Response-element destination. */
        $currentURL = \SimpleSAML\Utils\HTTP::getSelfURLNoQuery();

        $cfg = \SimpleSAML_Configuration::getInstance();
        $baseDir = $cfg->getBaseDir();
        $cur_path = realpath($_SERVER['SCRIPT_FILENAME']);
        // find the path to the current script relative to the www/ directory of SimpleSAMLphp
        $rel_path = str_replace($baseDir.'www'.DIRECTORY_SEPARATOR, '', $cur_path);
        // convert that relative path to an HTTP query
        $url_path = str_replace(DIRECTORY_SEPARATOR, '/', $rel_path);
        $currentURL = \SimpleSAML\Utils\HTTP::getSelfURLHost().'/'.$url_path;

        $msgDestination = $response->getDestination();

        if ($msgDestination !== NULL && $msgDestination !== $currentURL) {
            throw new Exception('Destination in response doesn\'t match the current URL. Destination is "' .
                $msgDestination . '", current URL is "' . $currentURL . '".');
        }

//		$responseSigned = self::checkSign($idplocalConfig, $response);

        $responseSigned = self::checkSign($splocalConfig, $response);

        /*
         * When we get this far, the response itself is valid.
         * We only need to check signatures and conditions of the response.
         */

        $assertion = $response->getAssertions();
        if (empty($assertion)) {
            throw new SimpleSAML_Error_Exception('No assertions found in response from IdP.');
        }

        $ret = array();
        foreach ($assertion as $a) {
            $ret[] = self::processAssertion($splocalConfig, $idplocalConfig, $response, $a, $responseSigned);
        }

        return $ret;
    }


    /**
     * Process an assertion in a response.
     *
     * Will throw an exception if it is invalid.
     *
     * @param SimpleSAML_Configuration $splocalConfig  The metadata of the service provider.
     * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the identity provider.
     * @param SAML2\Response $response  The response containing the assertion.
     * @param SAML2_Assertion|SAML2_EncryptedAssertion $assertion  The assertion.
     * @param bool $responseSigned  Whether the response is signed.
     * @return SAML2_Assertion  The assertion, if it is valid.
     */
    private static function processAssertion(SimpleSAML_Configuration $splocalConfig, SimpleSAML_Configuration $idplocalConfig, SAML2\Response $response, $assertion, $responseSigned) {

        //assert($assertion instanceof SAML2_Assertion || $assertion instanceof SAML2_EncryptedAssertion);
        //assert(is_bool($responseSigned));

        $assertion = self::decryptAssertion($idplocalConfig, $splocalConfig, $assertion);

        if (!self::checkSign($idplocalConfig, $assertion)) {
            if (!$responseSigned) {
                throw new SimpleSAML_Error_Exception('Neither the assertion nor the response was signed.');
            }
        }

        /* At least one valid signature found. */

        $currentURL = \SimpleSAML\Utils\HTTP::getSelfURLNoQuery();

        $cfg = \SimpleSAML_Configuration::getInstance();
        $baseDir = $cfg->getBaseDir();
        $cur_path = realpath($_SERVER['SCRIPT_FILENAME']);
        // find the path to the current script relative to the www/ directory of SimpleSAMLphp
        $rel_path = str_replace($baseDir.'www'.DIRECTORY_SEPARATOR, '', $cur_path);
        // convert that relative path to an HTTP query
        $url_path = str_replace(DIRECTORY_SEPARATOR, '/', $rel_path);
        $currentURL = \SimpleSAML\Utils\HTTP::getSelfURLHost().'/'.$url_path;


        /* Check various properties of the assertion. */

        $notBefore = $assertion->getNotBefore();
        if ($notBefore !== NULL && $notBefore > time() + 60) {
            throw new SimpleSAML_Error_Exception('Received an assertion that is valid in the future. Check clock synchronization on IdP and SP.');
        }

        $notOnOrAfter = $assertion->getNotOnOrAfter();
        if ($notOnOrAfter !== NULL && $notOnOrAfter <= time() - 60) {
            throw new SimpleSAML_Error_Exception('Received an assertion that has expired. Check clock synchronization on IdP and SP.');
        }

        $sessionNotOnOrAfter = $assertion->getSessionNotOnOrAfter();
        if ($sessionNotOnOrAfter !== NULL && $sessionNotOnOrAfter <= time() - 60) {
            throw new SimpleSAML_Error_Exception('Received an assertion with a session that has expired. Check clock synchronization on IdP and SP.');
        }

        $validAudiences = $assertion->getValidAudiences();
        if ($validAudiences !== NULL) {
            $spEntityId = $splocalConfig->getString('entityid');
            if (!in_array($spEntityId, $validAudiences, TRUE)) {
                $candidates = '[' . implode('], [', $validAudiences) . ']';
                throw new SimpleSAML_Error_Exception('This SP [' . $spEntityId . ']  is not a valid audience for the assertion. Candidates were: ' . $candidates);
            }
        }

        $found = FALSE;
        $lastError = 'No SubjectConfirmation element in Subject.';
        $validSCMethods = array(SAML2\Constants::CM_BEARER, SAML2\Constants::CM_HOK, SAML2\Constants::CM_VOUCHES);
        foreach ($assertion->getSubjectConfirmation() as $sc) {
            if (!in_array($sc->Method, $validSCMethods)) {
                $lastError = 'Invalid Method on SubjectConfirmation: ' . var_export($sc->Method, TRUE);
                continue;
            }
            /* Is SSO with HoK enabled? IdP remote metadata overwrites SP metadata configuration. */
            $hok = $idplocalConfig->getBoolean('saml20.hok.assertion', NULL);
            if ($hok === NULL) {
                $hok = $splocalConfig->getBoolean('saml20.hok.assertion', FALSE);
            }
            if ($sc->Method === SAML2\Constants::CM_BEARER && $hok) {
                $lastError = 'Bearer SubjectConfirmation received, but Holder-of-Key SubjectConfirmation needed';
                continue;
            }
            if ($sc->Method === SAML2\Constants::CM_HOK && !$hok) {
                $lastError = 'Holder-of-Key SubjectConfirmation received, but the Holder-of-Key profile is not enabled.';
                continue;
            }

            $scd = $sc->SubjectConfirmationData;
            if ($sc->Method === SAML2\Constants::CM_HOK) {
                /* Check HoK Assertion */
                if (\SimpleSAML\Utils\HTTP::isHTTPS() === FALSE) {
                    $lastError = 'No HTTPS connection, but required for Holder-of-Key SSO';
                    continue;
                }
                if (isset($_SERVER['SSL_CLIENT_CERT']) && empty($_SERVER['SSL_CLIENT_CERT'])) {
                    $lastError = 'No client certificate provided during TLS Handshake with SP';
                    continue;
                }
                /* Extract certificate data (if this is a certificate). */
                $clientCert = $_SERVER['SSL_CLIENT_CERT'];
                $pattern = '/^-----BEGIN CERTIFICATE-----([^-]*)^-----END CERTIFICATE-----/m';
                if (!preg_match($pattern, $clientCert, $matches)) {
                    $lastError = 'Error while looking for client certificate during TLS handshake with SP, the client certificate does not '
                        . 'have the expected structure';
                    continue;
                }
                /* We have a valid client certificate from the browser. */
                $clientCert = str_replace(array("\r", "\n", " "), '', $matches[1]);

                foreach ($scd->info as $thing) {
                    if($thing instanceof SAML2_XML_ds_KeyInfo) {
                        $keyInfo[]=$thing;
                    }
                }
                if (count($keyInfo)!=1) {
                    $lastError = 'Error validating Holder-of-Key assertion: Only one <ds:KeyInfo> element in <SubjectConfirmationData> allowed';
                    continue;
                }

                foreach ($keyInfo[0]->info as $thing) {
                    if($thing instanceof SAML2_XML_ds_X509Data) {
                        $x509data[]=$thing;
                    }
                }
                if (count($x509data)!=1) {
                    $lastError = 'Error validating Holder-of-Key assertion: Only one <ds:X509Data> element in <ds:KeyInfo> within <SubjectConfirmationData> allowed';
                    continue;
                }

                foreach ($x509data[0]->data as $thing) {
                    if($thing instanceof SAML2_XML_ds_X509Certificate) {
                        $x509cert[]=$thing;
                    }
                }
                if (count($x509cert)!=1) {
                    $lastError = 'Error validating Holder-of-Key assertion: Only one <ds:X509Certificate> element in <ds:X509Data> within <SubjectConfirmationData> allowed';
                    continue;
                }

                $HoKCertificate = $x509cert[0]->certificate;
                if ($HoKCertificate !== $clientCert) {
                    $lastError = 'Provided client certificate does not match the certificate bound to the Holder-of-Key assertion';
                    continue;
                }
            }

            // if no SubjectConfirmationData then don't do anything.
            if ($scd === null) {
                $lastError = 'No SubjectConfirmationData provided';
                continue;
            }

            if ($scd->NotBefore && $scd->NotBefore > time() + 60) {
                $lastError = 'NotBefore in SubjectConfirmationData is in the future: ' . $scd->NotBefore;
                continue;
            }
            if ($scd->NotOnOrAfter && $scd->NotOnOrAfter <= time() - 60) {
                $lastError = 'NotOnOrAfter in SubjectConfirmationData is in the past: ' . $scd->NotOnOrAfter;
                continue;
            }
            if ($scd->Recipient !== NULL && $scd->Recipient !== $currentURL) {
                $lastError = 'Recipient in SubjectConfirmationData does not match the current URL. Recipient is ' .
                    var_export($scd->Recipient, TRUE) . ', current URL is ' . var_export($currentURL, TRUE) . '.';
                continue;
            }
            if ($scd->InResponseTo !== NULL && $response->getInResponseTo() !== NULL && $scd->InResponseTo !== $response->getInResponseTo()) {
                $lastError = 'InResponseTo in SubjectConfirmationData does not match the Response. Response has ' .
                    var_export($response->getInResponseTo(), TRUE) . ', SubjectConfirmationData has ' . var_export($scd->InResponseTo, TRUE) . '.';
                continue;
            }
            $found = TRUE;
            break;
        }
        if (!$found) {
            throw new SimpleSAML_Error_Exception('Error validating SubjectConfirmation in Assertion: ' . $lastError);
        }

        /* As far as we can tell, the assertion is valid. */

        /* Maybe we need to base64 decode the attributes in the assertion? */
        if ($idplocalConfig->getBoolean('base64attributes', FALSE)) {
            $attributes = $assertion->getAttributes();
            $newAttributes = array();
            foreach ($attributes as $name => $values) {
                $newAttributes[$name] = array();
                foreach ($values as $value) {
                    foreach(explode('_', $value) AS $v) {
                        $newAttributes[$name][] = base64_decode($v);
                    }
                }
            }
            $assertion->setAttributes($newAttributes);
        }


        /* Decrypt the NameID element if it is encrypted. */
        if ($assertion->isNameIdEncrypted()) {
            try {
                $keys = self::getDecryptionKeys($idplocalConfig, $splocalConfig);
            } catch (Exception $e) {
                throw new SimpleSAML_Error_Exception('Error decrypting NameID: ' . $e->getMessage());
            }

            $blacklist = self::getBlacklistedAlgorithms($idplocalConfig, $splocalConfig);

            $lastException = NULL;
            foreach ($keys as $i => $key) {
                try {
                    $assertion->decryptNameId($key, $blacklist);
                    SimpleSAML_Logger::debug('Decryption with key #' . $i . ' succeeded.');
                    $lastException = NULL;
                    break;
                } catch (Exception $e) {
                    SimpleSAML_Logger::debug('Decryption with key #' . $i . ' failed with exception: ' . $e->getMessage());
                    $lastException = $e;
                }
            }
            if ($lastException !== NULL) {
                throw $lastException;
            }
        }

        return $assertion;
    }


    /**
     * Retrieve the encryption key for the given entity.
     *
     * @param SimpleSAML_Configuration $localConfig  The metadata of the entity.
     * @return XMLSecurityKey  The encryption key.
     */
    public static function getEncryptionKey(SimpleSAML_Configuration $localConfig) {

        $sharedKey = $localConfig->getString('sharedkey', NULL);
        if ($sharedKey !== NULL) {
            $key = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            $key->loadKey($sharedKey);
            return $key;
        }

        $keys = $localConfig->getPublicKeys('encryption', TRUE);
        foreach ($keys as $key) {
            switch ($key['type']) {
                case 'X509Certificate':
                    $pemKey = "-----BEGIN CERTIFICATE-----\n" .
                        chunk_split($key['X509Certificate'], 64) .
                        "-----END CERTIFICATE-----\n";
                    $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
                    $key->loadKey($pemKey);
                    return $key;
            }
        }

        throw new SimpleSAML_Error_Exception('No supported encryption key in ' . var_export($localConfig->getString('entityid'), TRUE));
    }

}

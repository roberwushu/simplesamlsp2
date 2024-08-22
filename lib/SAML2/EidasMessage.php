<?php


/**
 * Common code for building SAML 2 messages based on the
 * available metadata.
 *
 * @package simpleSAMLphp
 * @version $Id$
 */

require_once('../../lib/RobRichards/XMLSecLibs/XMLSecurityKey.php');
class eidas_saml_Message extends sspmod_saml_Message {

	/**
	 * Build an authentication request based on information in the metadata.
	 *
	 * @param SimpleSAML_Configuration $splocalConfig  The metadata of the service provider.
	 * @param SimpleSAML_Configuration $idplocalConfig  The metadata of the identity provider.
	 */
	
	public static function buildAuthnRequest($extensions, $forceauthn, SimpleSAML_Configuration $splocalConfig, SimpleSAML_Configuration $idplocalConfig) {

		$ar = new SAML2\SAML2_EidasAuthnRequest();

		if ($splocalConfig->hasValue('NameIDPolicy')) {
			$nameIdPolicy = $splocalConfig->getString('NameIDPolicy', NULL);
		} else {
			$nameIdPolicy = $splocalConfig->getString('NameIDFormat', SAML2\Constants::NAMEID_TRANSIENT);
		}

		if ($nameIdPolicy !== NULL) {
			$ar->setNameIdPolicy(array(
				'Format' => $nameIdPolicy,
				'AllowCreate' => TRUE,
			));
		}
                /**
                 * Look for the endpoints in the information retrieved from the metadata
                 */
                 
                
                $dst = $idplocalConfig->getDefaultEndpoint('SingleSignOnService', array(SAML2\Constants::BINDING_HTTP_REDIRECT));	
                $dst = $dst['Location'];
                
  
                /**
                 * Start building the message for the authentication request with the retrieved metadata
                 */
		//ok-quitar setissuer
                $ar->setIssuer($splocalConfig->getString('entityid'));
		$ar->setDestination($dst);
		$ar->setForceAuthn($splocalConfig->getBoolean('ForceAuthn', $forceauthn));
		$ar->setIsPassive($splocalConfig->getBoolean('IsPassive', FALSE));

		$protbind = $splocalConfig->getValueValidate('ProtocolBinding', array(
				SAML2\Constants::BINDING_HTTP_POST,
				SAML2\Constants::BINDING_HTTP_ARTIFACT,
				SAML2\Constants::BINDING_HTTP_REDIRECT,
			), SAML2\Constants::BINDING_HTTP_POST);

		/* Setting the appropriate binding based on parameter in sp-metadata defaults to HTTP_POST */
		$ar->setProtocolBinding($protbind);

		if ($splocalConfig->hasValue('AuthnContextClassRef')) {
			$accr = $splocalConfig->getArrayizeString('AuthnContextClassRef');
			$ar->setRequestedAuthnContext(array('AuthnContextClassRef' => $accr));
		}


            if (!empty($extensions)) {
              $ar->setExtensions($extensions);
            }

		self::addRedirectSign($splocalConfig, $idplocalConfig, $ar);
		return $ar;
	}
  
  /**
   * Add signature key and and senders certificate to an element (Message or Assertion).
   *
   * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
   * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
   * @param SAML2_Message $element  The element we should add the data to.
   */
  public static function addSign(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig, SAML2\SignedElement $element) {
    $keyArray = SimpleSAML_Utilities::loadPrivateKey($srclocalConfig, TRUE);
    $certArray = SimpleSAML_Utilities::loadPublicKey($srclocalConfig, FALSE);
    $privateKey = new \XMLSecurityKey(\XMLSecurityKey::RSA_SHA512, array('type' => 'private'));
    if (array_key_exists('password', $keyArray)) {
      $privateKey->passphrase = $keyArray['password'];
    }
    $privateKey->loadKey($keyArray['PEM'], FALSE);

    $element->setSignatureKey($privateKey);

    if ($certArray === NULL) {
      /* We don't have a certificate to add. */
      return;
    }

    if (!array_key_exists('PEM', $certArray)) {
      /* We have a public key with only a fingerprint. */
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
  private static function addRedirectSign(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig, SAML2\SAML2_EidasAuthnRequest $message) 
  {
     
    if ($message instanceof SAML2_LogoutRequest || $message instanceof SAML2_LogoutResponse) {
      $signingEnabled = $srclocalConfig->getBoolean('sign.logout', NULL);
      if ($signingEnabled === NULL) {
        $signingEnabled = $dstlocalConfig->getBoolean('sign.logout', NULL);
      }
    } elseif ($message instanceof SAML2\SAML2_EidasAuthnRequest) {
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
   * Add signature key and and senders certificate to message.
   *
   * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
   * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
   * @param SAML2_Message $message  The message we should add the data to.
   */
  private static function addRedirectSignLogout(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig, SAML2\LogoutRequest $message) 
  {
     
    if ($message instanceof SAML2\LogoutRequest || $message instanceof SAML2\LogoutResponse) {
      $signingEnabled = $srclocalConfig->getBoolean('sign.logout', NULL);
      if ($signingEnabled === NULL) {
        $signingEnabled = $dstlocalConfig->getBoolean('sign.logout', NULL);
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
    * Build a logout request based on information in the metadata.
    *
    * @param SimpleSAML_Configuration $srclocalConfig  The metadata of the sender.
    * @param SimpleSAML_Configuration $dstlocalConfig  The metadata of the recipient.
    */
    public static function buildLogoutRequest(SimpleSAML_Configuration $srclocalConfig, SimpleSAML_Configuration $dstlocalConfig) {

		$lr = new SAML2\LogoutRequest();
		$lr->setIssuer($srclocalConfig->getString('logout.url'));
                $lr->setDestination($srclocalConfig->getString('idp'));
		self::addRedirectSignLogout($srclocalConfig, $dstlocalConfig, $lr);

		return $lr;
    }
}

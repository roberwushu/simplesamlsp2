<?php
namespace SAML2;
require_once('../../vendor/simplesamlphp/saml2/src/SAML2/AuthnRequest.php');

/**
 * Class for SAML 2 authentication request messages.
 *
 * @package simpleSAMLphp
 * @version $Id$
 */
class SAML2_EidasAuthnRequest extends AuthnRequest {
	
	/**
	 * Constructor for SAML 2 authentication request messages.
	 *
	 * @param DOMElement|NULL $xml  The input message.
	 */
	public function __construct(DOMElement $xml = NULL) {
		parent::__construct();
	}

	/**
	 * Convert this authentication request to an XML element.
	 *
	 * @return DOMElement  This authentication request.
	 */
	public function toUnsignedXML() { 
        $root = parent::toUnsignedXML();
        /* Ugly hack to add another namespace declaration to the root element. */
        //$root->setAttributeNS('urn:eu:stork:names:tc:STORK:1.0:protocol', 'storkp:tmp', 'tmp');
        //$root->removeAttributeNS('urn:eu:stork:names:tc:STORK:1.0:protocol', 'tmp');
        //$root->setAttributeNS('urn:eu:stork:names:tc:STORK:1.0:assertion', 'stork:tmp', 'tmp');
        //$root->removeAttributeNS('urn:eu:stork:names:tc:STORK:1.0:assertion', 'tmp');
        $providername=Constants::SPID.';'.Constants::SPAPPLICATION;
        $root->setAttribute('AssertionConsumerServiceURL', Constants::ASSERTION_URL);
        $root->setAttribute('ProviderName', $providername);

	    /*
        $exts = $this->getExtensions();
        if (!empty($exts)) {
          $root->appendChild($exts);
        }*/
        $reqauthcont = $this->document->createElementNS(Constants::SAMLP_NS, 'saml2p:RequestedAuthnContext');
	    $reqauthcont->setAttribute('Comparison', 'minimum');
		
		$loa=array_key_exists('loa', $_POST) ? $_POST['loa'] : 'http://eidas.europa.eu/LoA/low';
        Utils::addString($reqauthcont, Constants::SAML_NS, 'saml2:AuthnContextClassRef', $loa);
        $root->appendChild($reqauthcont);
		
		return $root;
	}

    public function setExtensions($extensions) {
        $this->extensions = $extensions;
    }

    /**
     * Get the Extensions.
     *
     * @param array|NULL $extensions The Extensions.
    */ 
    public function getExtensions() {
		$extension = $this->document->createElementNS(Constants::SAMLP_NS, 'samlp:Extensions');
		/*
		foreach($this->extensions as $key => $value) {
		  if ($key ==="RequestedAttributes") {
			  $attrs = $this->document->createElementNS(Constants::SAMLP_NS, 'storkp:RequestedAttributes');
			foreach($value as $attr) {
			  $attrs->appendChild($attr->toDOM($this->document));
			} 
			$extension->appendChild($attrs);
		  } else if ($key === "VIDP") {
			$vidp = $this->document->createElementNS(Constants::STORKP_NS, 'storkp:VIDPAuthenticationAttributes');
			SAML2_Utils::addString($vidp, Constants::STORKP_NS, 'storkp:CitizenCountryCode', $value['country']);
			$spinfo = $this->document->createElementNS(Constants::STORKP_NS, 'storkp:SPInformation');
			SAML2_Utils::addString($spinfo, Constants::STORKP_NS, 'storkp:SPID', $value['spid']);
			$vidp->appendChild($spinfo);
			$extension->appendChild($vidp);
		  }else {
			$ns = null;
			if (strpos($key, 'storkp:') === 0 ) {
			  $ns = Constants::STORKP_NS;
			} else if (strpos($key, 'stork:') === 0) {
			  $ns = Constants::STORK_NS;
			} else {
			   SimpleSAML_Logger::error("THIS SHOULND'T HAPPEN!!\nCaused by key: ".$key);
			}
			SAML2_Utils::addString($extension, $ns, $key, $value);
		  }
		}*/
		
		SimpleSAML_Logger::debug($extension->ownerDocument->saveXML());
		return $extension;
		//SimpleSAML_Logger::debug($root->ownerDocument->saveXML());
		//return $root;	
    }
}
?>

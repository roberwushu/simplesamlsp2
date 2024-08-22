<?php

/**
 * Class which implements the HTTP-POST binding.
 *
 * @package simpleSAMLphp
 * @version $Id$
 */
class SAML2_EidasHTTPPost extends SAML2\HTTPPost {
  
  public function __construct() { 
  
  }

	/**
	 * Send a SAML 2 message using the HTTP-POST binding.
	 *
	 * Note: This function never returns.
	 *
	 * @param SAML2_Message $message  The message we should send.
	 */
  
  
	public function send(SAML2\SAML2_Message $message) {

		if ($this->destination === NULL) {
			$destination = $message->getDestination();
		} else {
			$destination = $this->destination;
		}

                if ($this->country !== NULL && $this->country !== "") {
                  $destination = $destination /*. '?country=' . $this->country*/;
                }

		$relayState = $message->getRelayState();

		$msgStr = $message->toSignedXML();
		$msgStr = $msgStr->ownerDocument->saveXML($msgStr);

		SimpleSAML_Utilities::debugMessage($msgStr, 'out');

		$msgStr = base64_encode($msgStr);
		$msgStr = htmlspecialchars($msgStr);

		if ($message instanceof SAML2\SAML2_EidasAuthnRequest) {
			$msgType = 'SAMLRequest';
		} else {
			$msgType = 'SAMLResponse';
		}

		$destination = htmlspecialchars($destination);

		if ($relayState !== NULL) {
			$relayState = '<input type="hidden" name="RelayState" value="' . htmlspecialchars($relayState) . '">';
		} else {
			$relayState = '';
		}

		$out = <<<END
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>POST data</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method="post" action="$destination">
<input type="hidden" name="$msgType" value="$msgStr" />
$relayState
<noscript><input type="submit" value="Submit" /></noscript>
</form>
</body>
</html>
END;

		echo($out);
		exit(0);
	}
	
        /**
	 * Send a SAML 2 message using the HTTP-POST binding and the attributes selected by default.
	 *
	 * Note: This function never returns.
	 *
	 * @param SAML2_Message $message  The message we should send.
	 */
    public function sendDefault(SAML2\SAML2_EidasAuthnRequest $message) { 
    
		if ($this->destination === NULL) { 
			$destination = $message->getDestination();                 
		} else { 
			$destination = $this->destination;
		}

            if ($this->country !== NULL && $this->country !== "") {
              $destination = $destination /*. '?country=' . $this->country*/;
            }
       
		$relayState = $message->getRelayState(); 
                
                //This method sign the resulting XML document if the private key for the signature is set.
		$msgStr = $message->toSignedXML();    
		$msgStr = $msgStr->ownerDocument->saveXML($msgStr);

		SimpleSAML_Utilities::debugMessage($msgStr, 'out');

		$msgStr = base64_encode($msgStr);
		$msgStr = htmlspecialchars($msgStr);

		if ($message instanceof SAML2\SAML2_EidasAuthnRequest) {
			$msgType = 'SAMLRequest';
		} else { 
			$msgType = 'SAMLResponse';
		}

		$destination = htmlspecialchars($destination);

		if ($relayState !== NULL) {
			$relayState = '<input type="hidden" name="RelayState" value="' . htmlspecialchars($relayState) . '">';
		} else {
			$relayState = '';
		}
                
                /**
                 * The output is the final SAML Authentication Request
                 */
		$out = <<<END
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>POST data</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method="post" action="$destination">
<input type="hidden" name="$msgType" value="$msgStr" />
$relayState
<noscript><input type="submit" value="Submit" /></noscript>
</form>
</body>
</html>
END;

		echo($out);
		exit(0);
	}

        
                /**
	 * Send a SAML 2 message using the HTTP-POST binding and the attributes selected by default.
	 *
	 * Note: This function never returns.
	 *
	 * @param SAML2_Message $message  The message we should send.
	 */
    public function sendDefaultLogout(SAML2\LogoutRequest $message) { 
    
		if ($this->destination === NULL) { 
			$destination = $message->getDestination();                 
		} else { 
			$destination = $this->destination;
		}

            if ($this->country !== NULL && $this->country !== "") {
              $destination = $destination /*. '?country=' . $this->country*/;
            }
       
		$relayState = $message->getRelayState(); 
                
                //This method sign the resulting XML document if the private key for the signature is set.
		$msgStr = $message->toSignedXML();    
		$msgStr = $msgStr->ownerDocument->saveXML($msgStr);

		SimpleSAML_Utilities::debugMessage($msgStr, 'out');

		$msgStr = base64_encode($msgStr);
		$msgStr = htmlspecialchars($msgStr);

		if ($message instanceof SAML2\LogoutRequest) {
			$msgType = 'logoutRequest';
		}

		$destination = htmlspecialchars($destination);

		if ($relayState !== NULL) {
			$relayState = '<input type="hidden" name="RelayState" value="' . htmlspecialchars($relayState) . '">';
		} else {
			$relayState = '';
		}
                
                /**
                 * The output is the final SAML Authentication Request
                 */
		$out = <<<END
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>POST data</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method="post" action="$destination">
<input type="hidden" name="$msgType" value="$msgStr" />

<input type="hidden" name="country" value="ES"/>

$relayState
<noscript><input type="submit" value="Submit" /></noscript>
</form>
</body>
</html>
END;

		echo($out);
		exit(0);
	}
        
        
        
	/**
	 * Receive a SAML 2 message sent using the HTTP-POST binding.
	 *
	 * Throws an exception if it is unable receive the message.
	 *
	 * @return SAML2_Message  The received message.
	 */
	public function receive() {

		if (array_key_exists('SAMLRequest', $_POST)) {
			$msg = $_POST['SAMLRequest'];
		} elseif (array_key_exists('SAMLResponse', $_POST)) {
			$msg = $_POST['SAMLResponse'];
		} else {
			throw new Exception('Missing SAMLRequest or SAMLResponse parameter.');
		}

		$msg = base64_decode($msg);

		SimpleSAML_Utilities::debugMessage($msg, 'in');

		$document = new DOMDocument();
		$document->loadXML($msg);
		$xml = $document->firstChild;

		$msg = SAML2_Message::fromXML($xml);

		if (array_key_exists('RelayState', $_POST)) {
			$msg->setRelayState($_POST['RelayState']);
		}

		return $msg;
	}

}

?>

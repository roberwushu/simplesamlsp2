<?php

namespace SAML2;

/**
 * Class which implements the HTTP-POST binding.
 *
 * @package SimpleSAMLphp
 */

require_once('../../lib/SAML2/Message.php');
class HTTPPost extends Binding
{
    /**
     * Send a SAML 2 message using the HTTP-POST binding.
     *
     * Note: This function never returns.
     *
     * @param \SAML2\Message $message The message we should send.
     */
    public function send(SAML2_Message $message)
    {
        if ($this->destination === null) {
            $destination = $message->getDestination();
        } else {
            $destination = $this->destination;
        }
        $relayState = $message->getRelayState();

        $msgStr = $message->toSignedXML();      
        $msgStr = $msgStr->ownerDocument->saveXML($msgStr);

        Utils::getContainer()->debugMessage($msgStr, 'out');

        $msgStr = base64_encode($msgStr);

        if ($message instanceof Request) {
            $msgType = 'SAMLRequest';
        } else {
            $msgType = 'SAMLResponse';
        }

        $post = array();
        $post[$msgType] = $msgStr;

        if ($relayState !== null) {
            $post['RelayState'] = $relayState;
        }

        Utils::getContainer()->postRedirect($destination, $post);
    }

    /**
     * Receive a SAML 2 message sent using the HTTP-POST binding.
     *
     * Throws an exception if it is unable receive the message.
     *
     * @return \SAML2\Message The received message.
     * @throws \Exception
     */
    public function receive()
    {
        if (array_key_exists('SAMLRequest', $_POST)) {
            $msg = $_POST['SAMLRequest'];
        } elseif (array_key_exists('SAMLResponse', $_POST)) {
            $msg = $_POST['SAMLResponse'];
        } else {
            throw new \Exception('Missing SAMLRequest or SAMLResponse parameter.');
        }

        $msg = base64_decode($msg);

     //   Utils::getContainer()->debugMessage($msg, 'in');

        $document = DOMDocumentFactory::fromString($msg);
        $xml = $document->firstChild;

        $msg = SAML2_Message::fromXML($xml);

        if (array_key_exists('RelayState', $_POST)) {
            $msg->setRelayState($_POST['RelayState']);
        }

        return $msg;
    }
    
    public function receiveLogout()
    {
        if (array_key_exists('logoutResponse', $_POST)) {
            $msg = $_POST['logoutResponse'];
        }  else {
            throw new \Exception('Missing Logout Response parameter.');
        }

        $msg = base64_decode($msg);

     //   Utils::getContainer()->debugMessage($msg, 'in');

        $document = DOMDocumentFactory::fromString($msg);
        $xml = $document->firstChild;

        $msg = SAML2_Message::fromXML($xml);

        if (array_key_exists('RelayState', $_POST)) {
            $msg->setRelayState($_POST['RelayState']);
        }

        return $msg;
    }
    
    
    
    public function read_metadata()
    {
        if (array_key_exists('SAMLRequest', $_POST)) {
            $msg = $_POST['SAMLRequest'];
        } elseif (array_key_exists('SAMLMetadata', $_POST)) {
            $msg = $_POST['SAMLMetadata'];
        } 

        $document = DOMDocumentFactory::fromString($msg);      
        $xml = $document->firstChild;
        $validUntilmeta=$xml->getAttribute('validUntil');
        $validUntilmeta=strtotime($validUntilmeta);
        $today=time();
        if($validUntilmeta<$today)
        {
           echo "La fecha de validez de los metadatos del nodo eIDAS ha expirado. <br> Inténtelo de nuevo más tarde";
           ?><p>Haga clic <a href="/SP/">aqu&iacute;</a> para ir a la p&aacute;gina principal.</p><?php exit(0);
        }
        $msg = SAML2_Message::fromXML_MET($xml);
        
        if (array_key_exists('RelayState', $_POST)) {
            $msg->setRelayState($_POST['RelayState']);
        }
        return $msg;
    }
}

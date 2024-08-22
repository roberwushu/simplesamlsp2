<?php

namespace SAML2;

/**
 * Class for SAML 2 Response messages.
 *
 * @package SimpleSAMLphp
 */

require_once('../../lib/SAML2/Assertion.php');


class Metadata_Resp 
{
    /**
     * The assertions in this response.
     */
    private $assertions;

    /**
     * Constructor for SAML 2 response messages.
     *
     * @param \DOMElement|null $xml The input message.
     */
    public function __construct(\DOMElement $xml = null)
    { 

        $this->tagName = $xml->localName; 
        $this->id = 'Metadata';   
      //  $this->issueInstant = Temporal::getTime();   
        $this->certificates = array();
        $this->validators = array();
        $this->attrib = array();
        
        if ($xml === null) {
            return;
        }
        $nodes =  $xml->getElementsByTagName('*'); 
        $n=0;
      foreach($nodes as $i=>$node) { 
        if($node->nodeName == 'md:SingleSignOnService') {
            if(($node->getAttribute('Binding'))==='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'){
             $this->idp=$node->getAttribute('Location');
             $this->idp_binding=$node->getAttribute('Binding');
             
            }   
        }
        if($node->nodeName == 'ds:SignatureValue') {
         }
         if($node->nodeName == 'ds:X509Certificate') {
         }
         if($node->nodeName == 'saml2:Attribute') {  
             $this->attrib[$n]['Name'] = $node->getAttribute('FriendlyName');
             $this->attrib[$n]['Uri'] = $node->getAttribute('Name');
             $n++;
            }        
       }
         $this->validateSignature($xml);       
    }
    
    public function validate(\XMLSecurityKey $key)
    {
        if (count($this->validators) === 0) {
            return false;
        }
       
        $exceptions = array();
       
        foreach ($this->validators as $validator) {
            $function = $validator['Function'];
            $data = $validator['Data'];  
           if(is_array($validator['Function']))
               {
                    $function='';
                    foreach($validator['Function'] as $fun)
                        {
                            $function=$function."\/".$fun;
                        }
               }
            try {  
                call_user_func($function, $data, $key); 
                /* We were able to validate the message with this validator. */

                return true;
            } catch (\Exception $e) { 
                $exceptions[] = $e;
            }
        }
        /* No validators were able to validate the message. */
        throw $exceptions[0];
    }
    
    
    public function validateSignature(\DOMElement $xml)
    {   
        try {
            /** @var null|\DOMAttr $signatureMethod */
            $signatureMethod = Utils::xpQuery($xml, './ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm');
 
            $sig = Utils::validateElement($xml); 

            if ($sig !== false) {
                $this->messageContainedSignatureUponConstruction = true;
                $this->certificates = $sig['Certificates'];
                $this->validators[] = array(
                    'Function' => array('\SAML2\Utils', 'validateSignature'),
                    'Data' => $sig,
                );
                $this->signatureMethod = $signatureMethod[0]->value;
            }
        } catch (\Exception $e) {
            // ignore signature validation errors
        } 
    }

    /**
     * Retrieve the assertions in this response.
     *
     * @return \SAML2\Assertion[]|\SAML2\EncryptedAssertion[]
     */
     public function getAssertions()
    {
        return $this->assertions;
    }


    /**
     * Convert the response message to an XML element.
     *
     * @return \DOMElement This response.
     */
    public function toUnsignedXML()
    {
        $root = $this->toUnsignedXML();

        /** @var \SAML2\Assertion|\SAML2\EncryptedAssertion $assertion */
        foreach ($this->assertions as $assertion) {
            $assertion->toXML($root);
        }

        return $root;
    }
}

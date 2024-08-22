<?php

namespace SAML2\XML;

use SAML2\DOMDocumentFactory;
use SAML2\Utils;

/**
 * Serializable class used to hold an XML element.
 *
 * @package SimpleSAMLphp
 */
class Chunk implements \Serializable
{
    /**
     * The localName of the element.
     *
     * @var string
     */
    public $localName;

    /**
     * The namespaceURI of this element.
     *
     * @var string
     */
    public $namespaceURI;

    /**
     * The \DOMElement we contain.
     *
     * @var \DOMElement
     */
    public $xml;

    /**
     * Create a XMLChunk from a copy of the given \DOMElement.
     *
     * @param \DOMElement $xml The element we should copy.
     */
    public function __construct(\DOMElement $xml)
    {
        $this->localName = $xml->localName;
        $this->namespaceURI = $xml->namespaceURI;

        $this->xml = Utils::copyElement($xml);
    }
    
    

    /**
     * Get this \DOMElement.
     *
     * @return \DOMElement This element.
     * @deprecated
     */
    public function getXML()
    {
        assert($this->xml instanceof DOMElement || is_string($this->xmlString));

	//HE añadido este if entero
            
            if ($this->xml === NULL) {
			$doc = new DOMDocument();
			$doc->loadXML($this->xmlString);
			$this->xml = $doc->firstChild;
		}

        return $this->xml;
    }

    /**
     * Append this XML element to a different XML element.
     *
     * @param  \DOMElement $parent The element we should append this element to.
     * @return \DOMElement The new element.
     * 
     */
  
    public function toXML(\DOMElement $parent)
    {
//$this->getXML()
       return Utils::copyElement($this->xml, $parent);
    }

    /**
     * Serialize this XML chunk.
     *
     * @return string The serialized chunk.
     */
    public function serialize()
    {
        return serialize($this->xml->ownerDocument->saveXML($this->xml));
    }

    /**
     * Un-serialize this XML chunk.
     *
     * @param  string          $serialized The serialized chunk.
     */
    public function unserialize($serialized)
    {
        $doc = DOMDocumentFactory::fromString(unserialize($serialized));
        $this->xml = $doc->documentElement;
        $this->localName = $this->xml->localName;
        $this->namespaceURI = $this->xml->namespaceURI;
    }
}

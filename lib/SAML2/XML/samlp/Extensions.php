<?php

namespace SAML2\XML\samlp;

use SAML2\Constants;
use SAML2\Utils;
use SAML2\XML\Chunk;

/**
 * Class for handling SAML2 extensions.
 *
 * @package SimpleSAMLphp
 */
class Extensions
{
    /**
     * Get a list of Extensions in the given element.
     *
     * @param  \DOMElement $parent The element that may contain the samlp:Extensions element.
     * @return array      Array of extensions.
     */
    public static function getList(\DOMElement $parent)
    {
        $ret = array();
        foreach (Utils::xpQuery($parent, './saml_protocol:Extensions/*') as $node) {
            $ret[] = new Chunk($node);
        }

        return $ret;
    }
  
    
    
    
    /**
     * Add a list of Extensions to the given element.
     *
     * @param \DOMElement        $parent     The element we should add the extensions to.
     * @param \SAML2\XML\Chunk[] $extensions List of extension objects.
     */
    public static function addList(\DOMElement $parent, array $extensions)
    {
        if (empty($extensions)) {
            return;
        }
        
        $extElement = $parent->ownerDocument->createElementNS(Constants::NS_SAMLP, 'saml2p:Extensions');       
        $parent->appendChild($extElement);   
        
        foreach ($extensions as $ext) {
            if (gettype($ext)!='array'){               
                $ext->toXML($extElement);
            }
          
            else {
                $dom = \SAML2\DOMDocumentFactory::create();

                    $ce = $dom->createElementNS(Constants::NS_EIDAS, 'eidas:RequestedAttributes', null);
                        foreach ($ext as $ext2) {  
                        $ext2->toXML($ce);
                     }
                
                $ce_chunk =  new \SAML2\XML\Chunk($ce);                
                $ce_chunk->toXML($extElement);  
            }
        }
 
     //    $extensions->toXML($extElement);     
       
    }
  
}

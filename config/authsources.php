<?php

/**
* Se elimina la constante VAR_DESA
*/

$entityIdTemp = 'http://simplesaml2.local:8081/return.php';


$config = array(

    // This is a authentication source which handles admin authentication.
    'admin' => array(
        // The default is to use core:AdminPassword, but it can be replaced with
        // any authentication source.

        'core:AdminPassword',
    ),
	
   '21114293V_E04975701' => array(
		'saml:SP',
		'certificate' => 'sello_kit_de_pruebas_ac_sector_p_blico_.crt',
		'validate.certificate' => 'sello_entidad_sgad_pruebas.cer',
		'privatekey' => 'sello_kit_de_pruebas_ac_sector_p_blico_.pem',
		'privatekey_pass' => 'changeit',
		'name' => array(
			'en' => 'demo-sp-php',
			'pt' => 'demo-sp-php',
                        'es' => 'demo-sp-php',
		),
		'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
		'sign.authnrequest' => TRUE,
                'sign.logout' => TRUE,
                'entityID' => $entityIdTemp,
		'idp' => 'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider',
                'idp_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'logout.url' => 'http://simplesaml2.local:8081/logoutResponse.php',
                'OrganizationName' => array(
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationDisplayName' => array (
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationURL' => array (
                      //  'en' => 'https://se-eidas.redsara.es',
                        'es' => 'https://se-eidas.redsara.es',
                    ),
	),

    '11111111H_E04995902' => array(
        'saml:SP',
        'certificate' => 'sello_kit_de_pruebas_ac_sector_p_blico_.crt',
        'validate.certificate' => 'sello_entidad_sgad_pruebas.cer',
        'privatekey' => 'sello_kit_de_pruebas_ac_sector_p_blico_.pem',
        'privatekey_pass' => 'changeit',
        'name' => array(
            'en' => 'demo-sp-php',
            'pt' => 'demo-sp-php',
            'es' => 'demo-sp-php',
        ),
        'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
        'sign.authnrequest' => TRUE,
        'sign.logout' => TRUE,
        'entityID' => $entityIdTemp,
        'idp' => 'http://localhost:8888/Proxy2/ServiceProvider',
        'idp_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'logout.url' => 'http://simplesaml2.local:8081/logoutResponse.php',
        'OrganizationName' => array(
            //     'en' => 'Eidas SP Node',
            'es' => 'SP nodo Eidas',
        ),
        'OrganizationDisplayName' => array (
            //     'en' => 'Eidas SP Node',
            'es' => 'SP nodo Eidas',
        ),
        'OrganizationURL' => array (
            //  'en' => 'https://se-eidas.redsara.es',
            'es' => 'https://se-eidas.redsara.es',
        ),
    ),
   
	'NIFPRUEBA_DIRPRUEBA' => array(
		'saml:SP',
		'certificate' => 'ANCERTCNCSello_SW.crt',
		'validate.certificate' => 'SELLO_ENTIDAD_SGAD_PRUEBAS.crt',
		'privatekey' => 'ANCERTCNCSello_SW.pem',
		'privatekey_pass' => '1111',
		'name' => array(
			'en' => 'demo-sp-php',
			'pt' => 'demo-sp-php',
                        'es' => 'demo-sp-php',
		),
		'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
		'sign.authnrequest' => TRUE,
                'sign.logout' => TRUE,
                'entityID' => $entityIdTemp,
		'idp' => 'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider',
                'idp_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'logout.url' => 'http://simplesaml2.local:8081/logoutResponse.php',
                'OrganizationName' => array(
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationDisplayName' => array (
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationURL' => array (
                      //  'en' => 'https://se-eidas.redsara.es',
                        'es' => 'https://se-eidas.redsara.es',
                    ),
	),

    // An authentication source which can authenticate against both SAML 2.0
    // and Shibboleth 1.3 IdPs.
    'default-sp' => array(
        'saml:SP',

        // The entity ID of this SP.
        // Can be NULL/unset
        'entityID' => null,

        // The entity ID of the IdP this should SP should contact.
        // Can be NULL/unset, in which case the user will be shown a list of available IdPs.
        'idp' => null,

        // The URL to the discovery service.
        // Can be NULL/unset, in which case a builtin discovery service will be used.
        'discoURL' => null,

       
    ),
    
    
    'SP' => array(
		'saml:SP',
		'certificate' => 'ANCERTCNCSello_SW.crt',
		'validate.certificate' => 'SELLO_ENTIDAD_SGAD_PRUEBAS.crt',
		'privatekey' => 'ANCERTCNCSello_SW.pem',
		'privatekey_pass' => '1111',
		'name' => array(
			'en' => 'demo-sp-php',
			'pt' => 'demo-sp-php',
                        'es' => 'demo-sp-php',
		),
		'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
		'sign.authnrequest' => TRUE,
                'sign.logout' => TRUE,
                'entityID' => $entityIdTemp,
		'idp' => 'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider',
                'idp_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'logout.url' => 'http://simplesaml2.local:8081/logoutResponse.php',
                'OrganizationName' => array(
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationDisplayName' => array (
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationURL' => array (
                      //  'en' => 'https://se-eidas.redsara.es',
                        'es' => 'https://se-eidas.redsara.es',
                    ),
	),
   
    
   'S2833002E_E99999999' => array(
		'saml:SP',
		'certificate' => 'ANCERTCNCSello_SW.crt',
		'validate.certificate' => 'SELLO_ENTIDAD_SGAD_PRUEBAS.crt',
		'privatekey' => 'ANCERTCNCSello_SW.pem',
		'privatekey_pass' => '1111',
		'name' => array(
			'en' => 'demo-sp-php',
			'pt' => 'demo-sp-php',
                        'es' => 'demo-sp-php',
		),
		'attributes.NameFormat' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
		'sign.authnrequest' => TRUE,
                'sign.logout' => TRUE,
                'entityID' => $entityIdTemp,
		'idp' => 'https://se-pasarela.clave.gob.es/Proxy2/ServiceProvider',
                'idp_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                'logout.url' => 'http://simplesaml2.local:8081/logoutResponse.php',
                'OrganizationName' => array(
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationDisplayName' => array (
                    //     'en' => 'Eidas SP Node',
                        'es' => 'SP nodo Eidas',
                    ),
                'OrganizationURL' => array (
                      //  'en' => 'https://se-eidas.redsara.es',
                        'es' => 'https://se-eidas.redsara.es',
                    ),
	),
);

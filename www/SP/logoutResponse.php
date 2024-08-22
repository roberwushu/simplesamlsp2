<?php

/**
 * This SAML 2.0 endpoint can receive incoming LogoutRequests. It will also send LogoutResponses,
 * and LogoutRequests and also receive LogoutResponses. It is implemeting SLO at the SAML 2.0 IdP.
 *
 */

require_once('../../lib/_autoload.php');
require_once('../../lib/SAML2/EidasMessage.php');
require_once('../../modules/saml/lib/Message.php');
require_once('../../lib/SAML2/Constants.php');
require_once('../../lib/SAML2/HTTPPost.php');

SimpleSAML_Logger::info('SAML2.0 - IdP.SingleLogoutService: Accessing SAML 2.0 IdP endpoint SingleLogoutService');

$authSource = SAML2\Constants::SPID;
$as = SimpleSAML_Auth_Source::getById($authSource);
$localConfig = $as->getLocalConfig();

$b = new SAML2\HTTPPost();
$response=$b->receiveLogout();

try {
    $retVal = eidas_saml_Message::checkSign($localConfig, $response);

    if (!$response->isSuccess() || !$retVal) {
        $statsData['error'] = $response->getStatus();
        throw Exception("LogoutResponse is Fail or invalid");
    }
    $relayState = $response->getRelayState();
    header ('location: /SP');
} catch (Exception $e) { // TODO: look for a specific exception
    echo "<h2>Se ha producido un error</h2><br>Por favor, haga clic <a href=\"/SP/\">aqu&iacute;</a> para volver a la p&aacute;gina principal.";
    throw $e; // do not ignore other exceptions!
}
?>
    
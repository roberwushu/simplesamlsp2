<?php
error_reporting(0);
require_once('../../lib/_autoload.php');
require_once('../../vendor/simplesamlphp/saml2/src/SAML2/EidasMessage.php');
require_once('../../modules/saml/lib/Message.php');
require_once('../../lib/SAML2/Constants.php');
require_once('../../vendor/simplesamlphp/saml2/src/SAML2/HTTPPost.php');
require_once('../../lib/SimpleSAML/Auth/Source.php');

/**
 * Here our SP starts processing the SAML Response obtained from the IdP
 * Creating of an instance of a HTTPPost object which extends from the class Binding
 */
$b = new SAML2\HTTPPost();
?>
<html>
<head>
    <title>Service Provider</title>
    <link href="css/estilos.css" rel="stylesheet" type="text/css"/>
</head>

<body>

<div id="contenedor" class="container">
    <div id="borde" class="borde">

        <div id="principal" class="contenido">

            <h1 class="colorAzul" id="TituloBody">PROVEEDOR DE SERVICIOS DE EJEMPLO<br></h1>

            <br/>
            <form id="LogoutPage" name="LogoutPage" action="logout.php" method="POST">
                <input type="hidden" name="default" value="true" /><br>
                <input type="submit" id="LogoutSesion" value="Cerrar sesi&oacute;n" />
            </form>
            <?php
            error_reporting(0);
            //This method receive a SAML 2 message sent using the HTTP-POST binding
            $response = $b->receive();

            $authSource = SAML2\Constants::SPID;
            $as = SimpleSAML_Auth_Source::getById($authSource);

            $splocalConfig = $as->getLocalConfig();

            //Se carga de la configuración la url del IdP Proxy.
            $idp[0]= $as->getidp();
            $idp[1]= $as->getidp_binding();
            //Se carga la información del IdP de la configuración
            $idplocalConfig = $as->getIdPfromConfig($idp);

            //Se continua con la validación de la response
            try {
                $retVal = eidas_saml_Message::processResponse($splocalConfig, $idplocalConfig, $response);

                //The SP validates the signature from the received message. The method checkSign belongs to eidas_saml_Message subclass which extends sspmod_saml_Message
//			  $retVal = eidas_saml_Message::checkSign($localConfig, $response);

                if($retVal) {
                    //Obtener las assertions
                    $assertions = $response->getAssertions();

                    //Obtener las assertions en caso de qe sean un objeto EncryptedAsserton, es decir, descifrar las assertions
                    if ($assertions[0] instanceof SAML2\EncryptedAssertion) {
                        try {

                            $keyArray = SimpleSAML\Utils\Crypto::loadPrivateKey($localConfig, TRUE);
                            assert(isset($keyArray["PEM"]));

                            $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'private'));
                            if (array_key_exists('password', $keyArray)) {
                                $key->passphrase = $keyArray['password'];
                            }
                            $key->loadKey($keyArray['PEM']);

                            $assertions[0] = $assertions[0]->getAssertion($key, array());


                        } catch (sspmod_saml_Error $e) {
                            // the status of the response wasn't "success"
                            $e = $e->toException();
                            SimpleSAML_Auth_State::throwException($state, $e);
                        }

                    }
                    //obtener los atributos
                    $attributes = $assertions[0]->getAttributes();

                    //obtener el status de la saml response
                    $status = $response->getStatus();
                    if('urn:oasis:names:tc:SAML:2.0:status:Success' !== $status['Code']) {
                        // Autenticación Fallida!
                        echo '<b>Authentication failed</b> - '.$status['Message'].'</p>';
                    } else {
                        // Autenticación correcta!
                        echo '<br><h2>Login realizado con &eacute;xito </h2>';

                        echo '<table><tr><td><img id="logoeidas" alt="Eidas" src="./img/logoeidas.JPG"></td><td>';
                        echo '<table class="tabla">';
                        echo '  <TR class="filatit">';
                        echo '    <TD>Atributo</TD>';
                        echo '    <TD>Valores</TD>';
                        echo '  </TR>';

                        $keys = array_keys($attributes);
                        foreach($keys as $key) {
                            echo '<TR class="filaresult">';
                            $keyval = array_search($key, SAML2\Constants::$attrs);
                            $keyx = explode('.', $keyval);
                            echo '<TD>'.$keyx[0].'</TD>';
                            echo '<TD>'.$attributes[$key][0].'</TD>';
                            echo '</TR>';
                        }
                        echo '</table></td></tr></table>';
                    }
                }else {
                    // Validación de firma fallida
                    echo '<h2>Ha ocurrido un error';
                    echo '<p>La validación de la firma ha fallado.</p>';
                }

            } catch(Exception $e) {
                echo '<h2>Ha ocurrido un error';
                echo '<p>Ha ocurrido una excepci&oacute;n en el procesado de la respuesta.</p>';
            }
            ?>

            <p>Por favor, haga clic <a href="/SP/">aqu&iacute;</a> para ir a la p&aacute;gina principal.</p>
        </div>
    </div>
</div>

<?php include 'footer.php'; ?>

</body>
</html>

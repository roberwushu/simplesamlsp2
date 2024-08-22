<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<?PHP
require_once('../../lib/SAML2/Constants.php');
require_once('../../lib/_autoload.php');

/**
 * SPID is the identifier of our Service Provider.
 */
$authSource = SAML2\Constants::SPID;
$assertion_url= SAML2\Constants::ASSERTION_URL;
/**
 * Se crea un objeto de tipo SimpleSAML_Auth_Simple que se encargará de recoger información sobre las fuentes de autenticación
 */
$as = new SimpleSAML_Auth_Simple($authSource);
$as = SimpleSAML_Auth_Source::getById($authSource);
/**
 * getLocalConfig es un método de la clase sspmod_saml_Auth_Source_SP que extiende de SimpleSAML_Auth_Source y se utiliza para recoger los metadatos de nuestro SP
 */
$localConfig = $as->getLocalConfig();
$idp = $as->getLocalConfig()->getString('idp', NULL);
?>
<!-- A continuación se muestra la plantilla html de la pantalla principal y el código javascript que maneja la seleccion de las posibles pestañas y atributos que se presentan -->
<html>
<head>
    <title>Service Provider</title>
    <script type="text/javascript" src="js/script.js"></script>
    <script language="javascript" src="js/jquery-1.2.6.pack.js" type="text/javascript"></script>
    <script language="javascript" src="js/dd.js" type="text/javascript"></script>
    <link href="css/estilos.css" rel="stylesheet" type="text/css" />
</head>

<body>
<div id="contenedor" class="container">

    <div id="borde" class="borde">

        <div id="principal" class="contenido">

            <h1 class="colorAzul" id="TituloBody">PROVEEDOR DE SERVICIOS DE EJEMPLO<br></h1>
            <p>Bienvenido al proveedor de servicios de ejemplo que ilustra el proceso de integración con las plataformas del MINHAFP Cl@ve y eIDAS. A continuación puede enviar una solicitud por defecto haciendo clic en el botón "Iniciar sesión" o puede configurar una petición a medida utilizando el botón "Ver más configuración"</p>

            <p><b>ID DE ESTE PROVEEDOR DE SERVICIOS: <?PHP echo $authSource;?><br>
                    URL DEL SERVICIO: <?PHP echo $idp;?><br>
                    URL DE RETORNO: <?PHP echo $assertion_url;?></b></p>
            <div>
                <div class="tabs">

                    <table border="0" cellpadding="8" cellspacing="3" width="100%">
                        <colgroup>
                            <col style="width: 60%" />
                            <col style="width: auto" />
                            <col style="width: auto" />
                        </colgroup>
                        <tr><td colspan="1"> <div id="HideLogo"><img id="logoeidas" alt="Eidas" src="./img/logoeidas.JPG"></div></td>
                            <td colspan="2">
                                <?php include 'selectAttributes.php'; ?>
                            </td>

                    </table>

                </div>

            </div>
        </div>
    </div>

</body>
</html>

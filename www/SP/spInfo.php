<?php
header("Content-type: text/xml");
require_once('../../lib/SAML2/Constants.php');
?>
<?php
$file = readfile(Constants::SP_VC_FILE); 
echo substr_replace($file,"",0);
?>

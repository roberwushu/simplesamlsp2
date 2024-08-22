<?PHP use SAML2\Constants; ?><!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
	<title>Demo Service Provider</title>
	<script type="text/javascript" src="js/script.js"></script>
	<script language="javascript" src="js/jquery-1.2.6.pack.js" type="text/javascript"></script>
	<script language="javascript" src="js/dd.js" type="text/javascript"></script>
	<link href="css/estilos.css" rel="stylesheet" type="text/css" />
</head>

<body >

<div id="contenedor" class="container">
	<div id="borde" class="borde">
		<div class="contenido">
			<div class="tabs"><!-- Pestañas -->
				<div id="tab1">
					<form id="IndexPage" name="IndexPage" action="login.php" method="POST">
					
					<?php
					require_once('../../lib/SAML2/Constants.php');
					?>
					
					<table border="0" cellpadding="8" cellspacing="3" width="100%">
                        <tr><td colspan="3"><h1 class="colorAzul">Detalles del mensaje:</h1></td></tr>
                        <tr id="altura">
							<td>
								<h2>Level of assurance (LOA):</h2>
							</td>
							<td coldspan="2">
                                <select name="loa">    
								<option value="http://eidas.europa.eu/LoA/low" selected="selected">http://eidas.europa.eu/LoA/low</option>
								<option value="http://eidas.europa.eu/LoA/substantial">http://eidas.europa.eu/LoA/substantial</option>
								<option value="http://eidas.europa.eu/LoA/high">http://eidas.europa.eu/LoA/high</option>
								</select></td>
						</tr>
						<tr><td><h2>Comparison of LOA</h2></td>
							<td coldspan="2"><select name="comparisonofloa"><option value="minimum" selected="selected">minimum</option></select></td>
						</tr>
						<tr><td><input type="hidden" name="SPType" value="public"/><input type="checkbox" name="forceauthn" value="true"/>Forzar autenticación</td></tr>
					</table>
					
					<table border="0" cellpadding="8" cellspacing="3" width="100%">
                        <tr><td colspan="3"><h1 class="colorAzul">Datos de usuario:</h1></td></tr>
						<tr>
							<td colspan="3">
								<table class="tabs">
									<tr>
										<th class="tabcks">&nbsp;</th>
									</tr>
									<tr class="filadiv">
										<td colspan="6">										
											<div class="tabdiv" id="tabdiv-1">
												<table class="attributes">
													<td><h2>Deshabilitar IdPs:</h2></td>											
														<tr>
															<td><input type="checkbox" name="AFirmaIdP" id="AFirmaIdP" value="off"/><label for="AFirmaIdP">@Firma</label></td>
															<td><input type="checkbox" name="GISSIdP" id="GISSIdP" value="off" /><label for="GISSIdP">Clave permanente</label></td>
														</tr>
														<tr>
															<td><input type="checkbox" name="AEATIdP" id="AEATIdP" value="off"/><label for="AEATIdP">PIN 24H</label></td>
															<td><input type="checkbox" name="EIDASIdP" id="EIDASIdP" value="off"/><label for="EIDASIdP">eIDAS</label></td>
														</tr>	
														<tr>
															<td><input type="checkbox" name="CLVMOVILIdP" id="CLVMOVILIdP" value="off"/><label for="CLVMOVILIdP">IDP Móvil</label></td>
														</tr>														
												</table>
											</div>
										</td>
									</tr>
								</table>
							</td>
						</tr>
						<tr>
							<td colspan="3">
								<div id="botonIniSesion"><input type="submit" id="InisesionBot" value="Iniciar sesi&oacute;n" /></div>
							</td>
						</tr>
					</table>

					</form></p>
				</div>
			</div>	
		</div>
	</div>
</div>
<script type="text/javascript">
    document.getElementById("tabck-1").click();
</script>
</body>
</html>

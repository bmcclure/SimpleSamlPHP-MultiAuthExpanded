<?php
if (!array_key_exists('StateId', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['StateId'];

/* Retrieve the authentication state. */
$state = SimpleSAML_Auth_State::loadState($authStateId, 'multiauthexpanded:AssociateAuth');

$session = SimpleSAML_Session::getInstance();

$aaConfig = $state['Attributes']['AssociateAuthConfig'];
$aaReserved = $state['Attributes']['AssociateAuthReserved'];

unset($state['Attributes']['AssociateAuthConfig']);
unset($state['Attributes']['AssociateAuthReserved']);

$associateAuth = new sspmod_multiauthexpanded_Auth_Process_AssociateAuth($aaConfig, $aaReserved);

$associateAuth->verifyRegisteredUser($state);
?>
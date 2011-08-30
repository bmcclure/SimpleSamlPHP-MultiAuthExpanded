<?php
if (!array_key_exists('StateId', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthState parameter.');
}
$authStateId = $_REQUEST['StateId'];

/* Retrieve the authentication state. */
$state = SimpleSAML_Auth_State::loadState($authStateId, 'multiauthexpanded:AssociateAuth');

$session = SimpleSAML_Session::getInstance();
print_r($_SESSION);
exit;

sspmod_multiauthsql_Auth_Process_AssociateAuth::verifyRegisteredUser($state);
?>
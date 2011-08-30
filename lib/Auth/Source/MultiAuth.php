<?php
/**
 * Authentication source which let the user chooses among a list of
 * other authentication sources
 *
 * @author Lorenzo Gil, Yaco Sistemas S.L.
 * @package simpleSAMLphp
 * @version $Id$
 */

class sspmod_multiauthexpanded_Auth_Source_MultiAuth extends SimpleSAML_Auth_Source {

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'sspmod_multiauthexpanded_Auth_Source_MultiAuth.AuthId';

	/**
	 * The string used to identify our states.
	 */
	const STAGEID = 'sspmod_multiauthexpanded_Auth_Source_MultiAuth.StageId';

	/**
	 * The key where the sources is saved in the state.
	 */
	const SOURCESID = 'sspmod_multiauthexpanded_Auth_Source_MultiAuth.SourceId';

	/**
	 * The key where the selected source is saved in the session.
	 */
	const SESSION_SOURCE = 'multiauth:selectedSource';

	private $sources;

	private $connectorName;

	private $connector;

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info	 Information about this authentication source.
	 * @param array $config	 Configuration.
	 */
	public function __construct($info, $config) {
		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		foreach (array('connector') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new SimpleSAML_Error_Exception('Missing required attribute \'' . $param .
					'\' for authentication source.');
			}

			if (!is_string($config[$param])) {
				throw new SimpleSAML_Error_Exception('Expected parameter \'' . $param .
					'\' for processing filter to be a string. Instead it was: ' .
					var_export($config[$param], TRUE));
			}
		}

		$connectorName = $config['connector'].'Connector';
		$this->connectorName = $connectorName;

		require_once(dirname(dirname(dirname(__FILE__))).'/Connector/'.$connectorName.'.php');

		$this->connector = new $connectorName($this->authId, $config);

		$this->sources = $this->connector->fetchAuthSources();
	}

	/**
	 * Prompt the user with a list of authentication sources.
	 *
	 * This method saves the information about the configured sources,
	 * and redirects to a page where the user must select one of these
	 * authentication sources.
	 *
	 * This method never return. The authentication process is finished
	 * in the delegateAuthentication method.
	 *
	 * @param array &$state	 Information about the current authentication.
	 */
	public function authenticate(&$state) {
		$state[self::AUTHID] = $this->authId;
		$state[self::SOURCESID] = $this->sources;

		/* Save the $state array, so that we can restore if after a redirect */
		$id = SimpleSAML_Auth_State::saveState($state, self::STAGEID);

		/* Redirect to the select source page. We include the identifier of the
		saved state array as a parameter to the login form */
		$url = SimpleSAML_Module::getModuleURL('multiauthexpanded/selectsource.php');
		$params = array('AuthState' => $id);

        // Allows the user to specify the auth souce to be used
        if(isset($_GET['source'])) {
            $params['source'] = $_GET['source'];
        }

        SimpleSAML_Utilities::redirect($url, $params);
	}

	/**
	 * Delegate authentication.
	 *
	 * This method is called once the user has choosen one authentication
	 * source. It saves the selected authentication source in the session
	 * to be able to logout properly. Then it calls the authenticate method
	 * on such selected authentication source.
	 *
	 * @param string $authId	Selected authentication source
	 * @param array	 $state	 Information about the current authentication.
	 */
	public static function delegateAuthentication($authId, $state) {
		$as = SimpleSAML_Auth_Source::getById($authId);
		if ($as === NULL) {
			throw new Exception('Invalid authentication source: ' . $authId);
		}

		/* Save the selected authentication source for the logout process. */
		$session = SimpleSAML_Session::getInstance();
		$session->setData(self::SESSION_SOURCE, $state[self::AUTHID], $authId);

		try {
			$as->authenticate($state);
		} catch (SimpleSAML_Error_Exception $e) {
			SimpleSAML_Auth_State::throwException($state, $e);
		} catch (Exception $e) {
			$e = new SimpleSAML_Error_UnserializableException($e);
			SimpleSAML_Auth_State::throwException($state, $e);
		}

		SimpleSAML_Auth_Source::completeAuth($state);
	}

	/**
	 * Log out from this authentication source.
	 *
	 * This method retrieves the authentication source used for this
	 * session and then call the logout method on it.
	 *
	 * @param array &$state	 Information about the current logout operation.
	 */
	public function logout(&$state) {
		/* Get the source that was used to authenticate */
		$session = SimpleSAML_Session::getInstance();
		$authId = $session->getData(self::SESSION_SOURCE, $this->authId);

		$source = SimpleSAML_Auth_Source::getById($authId);
		if ($source === NULL) {
			throw new SimpleSAML_Error_Exception('Invalid authentication source during logout: ' . $source);
		}
		/* Then, do the logout on it */
		$source->logout($state);
	}
}

?>

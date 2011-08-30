<?php
/**
 * Filter to authorize only certain users.
 * See docs directory.
 *
 * @author Ernesto Revilla, Yaco Sistemas SL.
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_multiauthexpanded_Auth_Process_AssociateAuth extends SimpleSAML_Auth_ProcessingFilter {
	const SESSION_SOURCE = 'multiauth:selectedSource';

	const AUTHID = 'sspmod_multiauthexpanded_Auth_Source_MultiAuth.AuthId';

	private $connectorName;

	private $connector;

	private $create_user_url;

	private $populate_attributes = array('authSourceId', 'authSourceValue');

	private $_config;

	private $_reserved;

	/**
	 * Initialize this filter.
	 * Validate configuration parameters.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($config, $reserved) {
		$this->_config = $config;
		$this->_reserved = $reserved;

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($config, $reserved);

		/* Make sure that all required parameters are present. */
		foreach (array('create_user_url') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new SimpleSAML_Error_Exception('Missing required attribute \'' . $param .
					'\' for processing filter.');
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

		$this->connector = new $connectorName(null, $config);

		$this->create_user_url = $config['create_user_url'];

		if (array_key_exists('populate_attributes', $config)) {
			$this->populate_attributes = $config['populate_attributes'];
		}
	}

	/**
	 * Apply filter to validate attributes.
	 *
	 * @param array &$request  The current request
	 */
	public function process(&$state) {
		//$session = SimpleSAML_Session::getInstance();
		//$authId = $session->getAttribute('InternalAuthId');

		//print_r($state);
		//exit;

		//if (empty($authId)) {
		//	throw new SimpleSAML_Error_Exception('Internal AuthId not found in session.');
		//}

		$attributes =& $state['Attributes'];

		$attributes['AssociateAuthConfig'] = $this->_config;
		$attributes['AssociateAuthReserved'] = $this->_reserved;

		$user = $this->associateUserAccount(&$state);

		//print_r($attributes);
		//exit;

		return;
	}

	/**
	 * Attempts to associate the authentication request with an existing user account.
	 * Redirects to external URL to create a new account if need-be.
	 */
	private function associateUserAccount(&$state) {
		$attributes =& $state['Attributes'];

		$session = SimpleSAML_Session::getInstance();

		$authSource = $session->getData(self::SESSION_SOURCE, 'multiauth');

		$attributes['authSourceId'] = array($this->connector->fetchAuthSourceId($authSource));

		$user = $this->connector->fetchUser($state, $authSource);

		if (count($user) == 0) {
			/* Save state and redirect to a page indicating that a user account must exist. */

			$id = SimpleSAML_Auth_State::saveState($state, 'multiauthexpanded:AssociateAuth');

			$returnUrl = SimpleSAML_Module::getModuleURL('multiauthexpanded/register.php');
			$returnUrl = SimpleSAML_Utilities::addURLparameter($returnUrl, array('StateId' => $id));

			SimpleSAML_Utilities::redirect($this->create_user_url, $this->getAttributes($attributes, $returnUrl));
		}

		unset($attributes['AssociateAuthConfig']);
		unset($attributes['AssociateAuthReserved']);

		return $user;
	}

	private function getAttributes(&$attributes, $returnUrl) {
		$submitAttributes = array('returnUrl' => $returnUrl);

		foreach ($this->populate_attributes as $attr) {
			if (isset($attributes[$attr])) {
				$submitAttributes[$attr] = $attributes[$attr];
			}
		}

		return $submitAttributes;
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
	public function verifyRegisteredUser(&$state) {
		$session = SimpleSAML_Session::getInstance();
		$authSource = $session->getData(self::SESSION_SOURCE, 'multiauth');

		$user = $this->connector->fetchUser($state, $authSource);

		if (!isset($user['User']) || !isset($user['User']['id'])) {
			throw new SimpleSAML_Error_Exception('No user record found. Please try to register again.');
		}

		$state['Attributes']['Auth.User'] = $user;

		SimpleSAML_Auth_ProcessingChain::resumeProcessing($state);
	}
}
?>

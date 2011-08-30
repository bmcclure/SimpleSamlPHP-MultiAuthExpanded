<?php
require_once(dirname(__FILE__).'/BaseConnector.php');
class RestConnector extends BaseConnector {
	private $base_url;

	private $headers = array(
		'Accept: application/json',
		'Content-Type: application/json',
	);

	private $data = array();

	private $username = null;

	private $password = null;

	private $method = 'GET';

	private $authsources_json = '/auth_sources/enabled.json';

	private $authsources_id_json = '/auth_sources/view_config/{configName}.json';

	private $user_json = '/users/view_auth/{authSourceId}/{uniqueValue}.json';

	/**
	 * Initialize this filter.
	 * Validate configuration parameters.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($authId, $config) {
		parent::__construct($authId, $config);

		/* Make sure that all required parameters are present. */
		foreach (array('base_url') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new SimpleSAML_Error_Exception('Missing required attribute \'' . $param .
					'\' for authentication source ' . $this->authId);
			}

			if (!is_string($config[$param])) {
				throw new SimpleSAML_Error_Exception('Expected parameter \'' . $param .
					'\' for authentication source ' . $this->authId .
					' to be a string. Instead it was: ' .
					var_export($config[$param], TRUE));
			}
		}

		$this->base_url = $config['base_url'];

		foreach (array('headers', 'data', 'method', 'username', 'password', 'authsources_json', 'authsources_id_json', 'user_json') as $param) {
			if ((array_key_exists($param, $config)) && is_string($config[$param])) {
				$this->$param = $config[$param];
			}
		}
	}

	private function fetchData($path, $replace = array(), $method = null) {
		if (!$method) {
			$method = $this->method;
		}

		foreach ($replace as $key => $val) {
			$path = str_replace('{'.$key.'}', urlencode($val), $path);
		}

		$handle = curl_init($this->base_url . $path);
		curl_setopt($handle, CURLOPT_HTTPHEADER, $this->headers);
		curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);

		switch ($method) {
			case 'GET':
				break;
			case 'POST':
				curl_setopt($handle, CURLOPT_POST, true);
				curl_setopt($handle, CURLOPT_POSTFIELDS, $this->data);
				break;
			case 'PUT':
				curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'PUT');
				curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
				break;
			case 'DELETE':
				curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'DELETE');
				break;
		}

		$response = curl_exec($handle);
		curl_close($handle);

		$array = json_decode($response, true);

		return $array['data'];
	}

	/**
	 * Get an array of available authentication sources using the supplied database query
	 */
	public function fetchAuthSources() {
		$array = $this->fetchData($this->authsources_json);

		return $array['authSources'];
	}

	public function fetchAuthSourceId($authId = null) {
		$authSource = $this->fetchData($this->authsources_id_json, array('configName' => $authId));

		if (empty($authSource['authSource'])) {
			return false;
		}

		return $authSource['authSource']['AuthSource']['id'];
	}

	public function fetchUser(&$request, $authSource) {
		$uniqueVal = $this->fetchUniqueValue($request, $authSource);

		$authSourceId = $this->fetchAuthSourceId($authSource);

		$user = $this->fetchData($this->user_json, array('authSourceId' => $authSourceId, 'uniqueValue' => base64_encode($uniqueVal)));

		if (empty($user['user'])) {
			return false;
		}

		return $user['user'];
	}
}
?>

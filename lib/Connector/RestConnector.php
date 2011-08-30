<?php
require_once(dirname(__FILE__).'/BaseConnector.php');
class RestConnector extends BaseConnector {
	var $authId;

	private $dsn;

	private $username;

	private $password;

	private $authsources_query = 'SELECT * FROM auth_sources WHERE enabled=1';

	private $authsources_users_query = 'SELECT "user_id" FROM auth_sources_users WHERE auth_source_id=:authSourceId AND unique_value=:uniqueValue';

	private $authsources_id_query = 'SELECT id FROM auth_sources WHERE config_name=:authSourceId';

	private $users_query = 'SELECT * FROM users WHERE id=:userId';

	private $unique_attribute_query = 'SELECT unique_attribute FROM auth_sources WHERE config_name=:authSourceId';

	private $unique_value_query = 'SELECT unique_value FROM auth_sources_users WHERE user_id=:userId AND auth_source_id=:authSourceId';

	/**
	 * Initialize this filter.
	 * Validate configuration parameters.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($authId, $config) {
		assert('is_string($authId)');
		assert('is_array($config)');

		/* Make sure that all required parameters are present. */
		foreach (array('dsn', 'username', 'password') as $param) {
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

		$this->authId = $authId;
		$this->dsn = $config['dsn'];
		$this->username = $config['username'];
		$this->password = $config['password'];

		foreach (array('authsources_query', 'authsources_users_query', 'users_query') as $param) {
			if ((array_key_exists($param, $config)) && is_string($config[$param])) {
				$this->$param = $config[$param];
			}
		}
	}

	/**
	 * Create a database connection.
	 *
	 * @return PDO  The database connection.
	 */
	private function connect() {
		try {
			$db = new PDO($this->dsn, $this->username, $this->password);
		} catch (PDOException $e) {
			throw new SimpleSAML_Error_Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
				$this->dsn . '\': '. $e->getMessage());
		}

		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		$driver = explode(':', $this->dsn, 2);
		$driver = strtolower($driver[0]);

		/* Driver specific initialization. */
		switch ($driver) {
		case 'mysql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'utf8'");
			break;
		case 'pgsql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'UTF8'");
			break;
		}

		return $db;
	}

	private function fetchData(&$connection, $query, $replace = array(), $type = "all") {
		try {
			$sth = $connection->prepare($query);
		} catch (PDOException $e) {
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute($replace);
		} catch (PDOException $e) {
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage() . "\n" . 'Query: '.$query."\n".'Parameter count: '.count($replace));
		}

		try {
			switch ($type) {
				case 'single':
					$data = $sth->fetch();
					break;
				case 'column':
					$data = $sth->fetchColumn();
					break;
				case 'all':
				default:
					$data = $sth->fetchAll(PDO::FETCH_ASSOC);
					break;
			}
		} catch (PDOException $e) {
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::info('multiauthsql:' . $this->authId . ': Got ' . count($data) .
			' rows from database');

		return $data;
	}

	/**
	 * Get an array of available authentication sources using the supplied database query
	 */
	public function fetchAuthSources() {
		$db = $this->connect();

		$data = $this->fetchData($db, $this->authsources_query);

		if (count($data) === 0) {
			/* No rows returned - invalid username/password. */
			SimpleSAML_Logger::error('multiauthsql:' . $this->authId .
				': No rows in result set. Probably wrong authsources_query.');
			throw new SimpleSAML_Error_Exception('No auth sources have been defined');
		}

		return $data;
	}

	public function fetchAuthSourceId($authId = null) {
		if (is_null($authId)) {
			$authId = $this->authId;
		}

		$db = $this->connect();

		$data = $this->fetchData(
			$db,
			$this->authsources_id_query,
			array('authSourceId' => $authId),
			"column"
		);

		if (empty($data)) {
			/* No rows returned - invalid username/password. */
			SimpleSAML_Logger::error('multiauthsql:' . $this->authId .
				': No auth source found for the specified id.');
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': No auth source found for the specified id');
		}

		return $data;
	}

	public function fetchUniqueValue(&$request, $authSourceId) {
		$attributes =& $request['Attributes'];

		$db = $this->connect();

		/*$uniqueAttr = $this->fetchData(
			$db,
			$this->unique_attribute_query,
			array('authSourceId' => $this->authId),
			"column"
		);*/

		$uniqueAttr = 'authSourceValue';

		if (!array_key_exists($uniqueAttr, $attributes)) {
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': - Specified attribute ('.$uniqueAttr.') is not in the list of available attributes from the current authsource ('.$this->authId.').');
		}

		return $attributes[$uniqueAttr];
	}

	public function fetchUsers(&$request, $authSource) {
		$db = $this->connect();

		$uniqueVal = $this->fetchUniqueValue($request, $authSource);

		$authSourceId = $this->fetchAuthSourceId($authSource);

		$userId = $this->fetchData(
			$db,
			$this->authsources_users_query,
			array('authSourceId' => $authSourceId, 'uniqueValue' => $uniqueVal),
			"column"
		);

		if (empty($userId)) {
			return array(); // No users exist, no point in moving forward
		}

		$users = $this->fetchData(
			$db,
			$this->users_query,
			array('userId' => $userId),
			"all"
		);

		if (count($users) == 0) {
			throw new SimpleSAML_Error_Exception('multiauthsql:' . $this->authId .
				': - User association exists, but no user record was found. Please contact an administrator with this information.');
		}

		return $users;
	}
}
?>

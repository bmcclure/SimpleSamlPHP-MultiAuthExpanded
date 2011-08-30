<?php
abstract class BaseConnector {
	protected $authId;

	/**
	 * Initialize this filter.
	 * Validate configuration parameters.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($authId, $config) {
		$this->authId = $authId;
	}

	/**
	 * Get an array of available authentication sources using the supplied database query
	 */
	abstract public function fetchAuthSources();

	abstract public function fetchAuthSourceId($authId = null);

	abstract public function fetchUniqueValue(&$request, $authSourceId);

	abstract public function fetchUser(&$request, $authSource);
}
?>

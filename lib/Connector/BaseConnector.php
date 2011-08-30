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

	public function fetchUniqueValue(&$request, $authSourceId) {
		$attributes =& $request['Attributes'];

		$uniqueAttr = 'authSourceValue';

		if (!array_key_exists($uniqueAttr, $attributes)) {
			throw new SimpleSAML_Error_Exception('multiauth:' . $this->authId .
				': - Specified attribute ('.$uniqueAttr.') is not in the list of available attributes from the current authsource ('.$this->authId.').');
		}

		return $attributes[$uniqueAttr][0];
	}

	abstract public function fetchUser(&$request, $authSource);
}
?>

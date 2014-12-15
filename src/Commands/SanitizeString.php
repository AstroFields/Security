<?php

namespace WCM\AstroFields\Security\Commands;

use WCM\AstroFields\Core\Commands;
use WCM\AstroFields\Core\Mediators\EntityInterface;

class SanitizeString implements
	Commands\CommandInterface,
	Commands\ContextAwareInterface
{
	/** @type string */
	protected $context = 'sanitize_{type}_meta_{key}';

	/**
	 * @param string          $key
	 * @param string          $value
	 * @param string          $type
	 * @param EntityInterface $command
	 * @param Array           $data
	 * @return Array | string | null
	 */
	public function update(
		$key = '',
		$value = '',
		$type = '',
		EntityInterface $command = null,
		Array $data = null
		)
	{
		if ( empty( $value ) )
			return $value;

		return is_array( $value )
			? array_map( array( $this, 'sanitize' ), $value )
			: $this->sanitize( $value );
	}

	/**
	 * Sanitize Callback
	 * @param  mixed $value
	 * @return mixed|null
	 */
	public function sanitize( $value )
	{
		return filter_var(
			$value,
			FILTER_SANITIZE_STRING,
			array( 'flags' => FILTER_NULL_ON_FAILURE )
		);
	}

	public function setContext( $context )
	{
		$this->context = $context;

		return $this;
	}

	public function getContext()
	{
		return $this->context;
	}
}
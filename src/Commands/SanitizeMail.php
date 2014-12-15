<?php

namespace WCM\AstroFields\Security\Commands;

use WCM\AstroFields\Core\Commands;
use WCM\AstroFields\Core\Mediators\EntityInterface;

class SanitizeMail implements
	Commands\CommandInterface,
	Commands\ContextAwareInterface
{
	/** @type string */
	protected $context = 'sanitize_{type}_meta_{key}';

	/**
	 * Non-RFC compliant check
	 * Pretty much like WP cores `is_email()` and `validate_email()`
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
	 * Non-RFC 6531 compliant sanitization
	 * For RFC compliance rules, read this answer:
	 * @link http://wordpress.stackexchange.com/a/169368/385
	 * @param  mixed $value
	 * @return mixed|null
	 */
	public function sanitize( $value )
	{
		return filter_var(
			$value,
			FILTER_VALIDATE_EMAIL,
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
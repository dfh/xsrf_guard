<?php

/*
 Copyright 2010, 2011 David Högberg (david@hgbrg.se)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Functionality for guarding against XSRF attacks.
 *
 * This class offers a simple way of protecting forms against XSRF-attacks.
 *
 * Looking around for info on protecting against XSRF in PHP, I found an
 * existing class for XSRF protection, written by David Parrish, available at
 * "Github":https://github.com/dparrish/phpxsrfprotect.
 *
 * This class is pretty similar to above mentioned, but it's a bit more 
 * flexible in that it allows hooking in custom callbacks for token generation 
 * and validation.
 *
 * Basic usage of this class would go something like this:
 *
 *   $xg = new Xsrf_guard();
 *   $xg->key( 'topsecret' ); # your unique, secret key
 *   # $xg->userdata( $uid ); # OPTIONAL: user-specific data for extra protection
 *   # $xg->timeout( 3600 ); # OPTIONAL: timeout. in seconds, default is 900.
 *  
 *   if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
 *     # obviously this is just a demo and not for production 
 *     if ( $xsrf_guard->is_valid( $_POST ) )
 *       echo 'Nice! Your request was valid.';
 *     else
 *       die( 'Uh-oh! Invalid request!!! (' . $xsrf_guard->error() . ')' );
 *   }
 *
 * See the readme file or the demo.php for more info.
 *
 * @author David Högberg <david@hgbrg.se>
 */
class Xsrf_guard
{
	/** Default token generator. */
	public static $default_token_generator =
		array( __CLASS__, 'default_token_generator' );

	/** Default token validator. */
	public static $default_token_validator =
		array( __CLASS__, 'default_token_validator' );

	/** The secret key on which the protection token is based. */
	protected $key = '';

	/** Additional data to add to key before hashing, for increased security. */
	protected $userdata = '';

	/** Maximum age of token. */
	protected $timeout = 900;

	/** Field name that stores the XSRF token. */
	protected $field_name = '__xsrf_guard';

	/** Hash algorithm to use for hashing the token. */
	protected $hash_alg = 'sha256';

	/** Holds error messages, if any. */
	protected $error;

	/** Current timestamp (time()). */
	protected $now;

	/** Holds token generator. */
	protected $token_generator;

	/** Holds token validator. */
	protected $token_validator;

	/**
	 * Creates a new Xsrf_guard.
	 */
	public function __construct()
	{
	}

	/**
	 * Sets/gets key.
	 */
	public function key( $key = null )
	{
		$key and 
			$this->key = $key;

		return $this->key;
	}

	/**
	 * Sets/gets userdata.
	 */
	public function userdata( $userdata = null )
	{
		$userdata and
			$this->userdata = $userdata;

		return $this->userdata;
	}

	/**
	 * Sets/gets timeout.
	 */
	public function timeout( $timeout = null )
	{
		$timeout and 
			$this->timeout = $timeout;

		return $this->timeout;
	}

	/**
	 * Sets/gets field name. Default is '__xsrf_guard'.
	 */
	public function field_name( $field_name = null )
	{
		$field_name and
			$this->field_name = $field_name;

		return $this->field_name;
	}

	/**
	 * Gets current error(s), if any.
	 */
	public function error()
	{
		return $this->error;
	}

	/**
	 * Sets/gets hash algorithm to use for hashing the token.
	 */
	public function hash_alg( $hash_alg = null )
	{
		$hash_alg and
			$this->hash_alg = $hash_alg;

		return $this->hash_alg;
	}

	/**
	 * Sets/gets UNIX timestamp (time()).
	 */
	public function now( $now = null )
	{
		$now and
			$this->now = $now;

		return $this->now;
	}

	/**
	 * Sets/gets callback to use for token generation.
	 */
	public function token_generator( $callback = null )
	{
		$callback and
			$this->token_generator = $callback;

		return $this->token_generator;
	}

	/**
	 * Sets/gets callback to use for token validation.
	 */
	public function token_validator( $callback = null )
	{
		$callback and
			$this->token_validator = $callback;

		return $this->token_validator;
	}

	/**
	 * Generates and returns the current token. If no custom token generator has 
	 * been set, the default one (self::$default_token_generator) will be used.
	 *
	 * The token generator callback will be passed one argument: the instance of
	 * this class.
	 */
	public function token()
	{
		if ( is_callable( $this->token_generator ) )
			$f = $this->token_generator;
		else
			$f = self::$default_token_generator;

		return call_user_func( $f, $this );
	}

	/**
	 * Generates token and returns a field to be inserted into form, for 
	 * convenience.
	 */
	public function xsrf_guard_field()
	{
		return sprintf(
			'<input type="hidden" name="%s" value="%s" />' . "\n",
			$this->field_name(),
			$this->token()
		);
	}

	/**
	 * Validates given token. If no custom token validator has been set, the 
	 * default one (self::$default_token_validator) will be used.
	 *
	 * If given token is an array, the value with the key that matches the field 
	 * name will be used (default '__xsrf_guard'). This makes it possible to send 
	 * in the entire POST or GET array, which could be handy, like so.
	 *
	 * Token validators are expected to throw a Validation_error on validation 
	 * failure, with a message describing the reason of failure.
	 *
	 * The token generator callback will be passed one argument: the instance of
	 * this class.
	 */
	public function validate( $token )
	{
		if ( is_array( $token ) )
			$token = $token[$this->field_name()];

		if ( is_callable( $this->token_validator ) )
			$f = $this->token_validator;
		else
			$f = self::$default_token_validator;

		return call_user_func( $f, $token, $this );
	}	

	/**
	 * Returns true iff the given token is valid. Token may be an array, in which 
	 * case the value for the key that matches the field name will be used. See 
	 * $this->validate() above.
	 *
	 * If validation fails, the current error will be available through 
	 * $this->error().
	 *
	 * This is basically for convenience, as it lets you do something like this:
	 *
	 *   if ( $xsrf_guard->is_valid( $token ) )
	 *     echo "OK!";
	 *   else
	 *     echo "Not OK!"; 
	 */
	public function is_valid( $token )
	{
		try {
			$this->validate( $token );
		} catch ( Validation_error $e ) {
			$this->error = $e->errors();
			return false;
		}

		return true;
	}	

	/**
	 * The default token generator.
	 */
	public static function default_token_generator( $self )
	{
		$now = $self->now();
		if ( !$now )
			$now = time();

		$token = base64_encode(
			hash( $self->hash_alg(), $self->key() . ":" . $now ) .
			":" . $now
		);

		return $token;
	}

	/**
	 * The default token validator. Checks syntax, max age and of course the 
	 * key + userdata hash.
	 */
	public static function default_token_validator( $token, $self )
	{
		$now = $self->now();
		if ( !$now )
			$now = time();

		$token = base64_decode( $token );
		$parts = explode( ':', $token );

		if ( count( $parts ) != 2 )
			throw new Validation_error( 'Invalid token syntax!' );

		list( $hash, $token_time ) = $parts;

		if ( $token_time + $self->timeout() < $now )
			throw new Validation_error( 'Token died of old age and is no good around here anymore!' );

		$ref_hash = hash( $self->hash_alg(), $self->key() . ":$token_time" );
		if ( $hash !== $ref_hash )
			throw new Validation_error( 'Looks like somebody tinkered that token, boy!' );

		return true;
	}
}

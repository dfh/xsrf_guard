Xsrf_guard
==========

PHP class for Cross-Site Request Forgery (XSRF) protection.

## Overview

This class offers a simple way of protecting forms against XSRF-attacks.

Looking around for info on protecting against XSRF in PHP, I found an
existing class for XSRF protection, written by David Parrish, available at
GitHub (https://github.com/dparrish/phpxsrfprotect).

`Xsrf_guard` is pretty similar to above mentioned, but it's a bit more flexible
in that it allows hooking in custom callbacks for token generation and
validation.

See `demo.php` for a small demo.

## Installation and use

Download the source and include it:

```php
<?php

require 'lib/xsrf_guard.php';
```

Basic usage of this class would go something like this:

```php
<?php
$xg = new Xsrf_guard();
$xg->key( 'topsecret' ); # your unique, secret key
# $xg->userdata( $uid ); # OPTIONAL: user-specific data for extra protection
# $xg->timeout( 3600 ); # OPTIONAL: timeout. in seconds, default is 900.

if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
	# obviously this is just a demo and not for production 
	if ( $xsrf_guard->is_valid( $_POST ) )
		echo 'Nice! Your request was valid.';
	else
		die( 'Uh-oh! Invalid request!!! (' . $xsrf_guard->error() . ')' );
}
```

And of course you need to add the XSRF guard field to the form that you wish
to protect. This is easiest done by using the `xsrf_guard_field()` method:

```php
<?php
<form action="" method="post">
	<input type="submit" value="Submit" />
	<?= $xsrf_guard->xsrf_guard_field(); ?>
</form>
```

## Known issues

None, so far.

## License

Copyright (c) 2014 David Högberg.

Licensed under the MIT License. See LICENSE for more information.

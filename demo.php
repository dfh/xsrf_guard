<?php

/**
 * A small demo of the Xsrf_guard.
 */

# obviously we need the Xsrf_guard itself
require dirname( __FILE__ ) . '/lib/xsrf_guard.php';

# set up the Xsrf guard
$xsrf_guard = new Xsrf_guard();

# set a secret key (the protection is based on nobody knowing this key!)
$xsrf_guard->key( 'topsecret' );

# OPTIONAL: add an additional piece of data for increased protection
# (like a user id, for example)
# $xsrf_guard->userdata( $user_id );

# OPTIONAL: set a timeout for the generated token (default is 900 seconds)
# $xsrf_guard->timeout( 3600 ); # valid for one hour
# lets set a super-short timeout for testing (meaning you have to be really
# fast to submit the form before the token expires).
$xsrf_guard->timeout( 3 );

# OPTIONAL: set the name for the form field that will hold the XSRF token data
# (default is '__xsrf_guard')
# $xsrf_guard->field_name( 'custom_field_name' );

$msg = '';
if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
	# obviously this is just a demo and not for production 
	if ( $xsrf_guard->is_valid( $_POST ) )
		$msg = 'Nice! Your request was valid.';
	else
		$msg = 'Uh-oh! Invalid request!!! (' . $xsrf_guard->error() . ')';
}

?>
<html>
<head>
	<title>Xsrf_guard demo</title>
</head>
<body>
	<h1>Try me!</h1>
<p>
<?= $msg; ?>
</p>
	<form action="" method="post">
		<input type="submit" value="Submit" />
		<?= $xsrf_guard->xsrf_guard_field(); ?>
	</form>
</body>
</html>

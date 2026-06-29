<?php
/**
 * PHPUnit bootstrap for the pure (WordPress-free) unit tests.
 *
 * totp.php and crypto.php carry no WordPress dependencies beyond the ABSPATH
 * guard and (in a fallback path) wp_salt(); we define just enough here to load
 * them in isolation. These tests do NOT need the WordPress test framework.
 */

define( 'ABSPATH', __DIR__ . '/' );

// crypto.php derives its key from wp-config salts; provide deterministic ones.
if ( ! defined( 'AUTH_KEY' ) ) {
    define( 'AUTH_KEY', 'test-auth-key-0000000000000000000000' );
}
if ( ! defined( 'SECURE_AUTH_KEY' ) ) {
    define( 'SECURE_AUTH_KEY', 'test-secure-auth-key-1111111111111111' );
}
if ( ! defined( 'AUTH_SALT' ) ) {
    define( 'AUTH_SALT', 'test-auth-salt-2222222222222222222222' );
}
if ( ! function_exists( 'wp_salt' ) ) {
    function wp_salt( $scheme = 'auth' ) { // phpcs:ignore
        return 'test-wp-salt-fallback';
    }
}

require dirname( __DIR__ ) . '/includes/totp.php';
require dirname( __DIR__ ) . '/includes/crypto.php';

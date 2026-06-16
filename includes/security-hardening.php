<?php
/**
 * Zen Login & Authentication – Security Hardening
 *
 * Low-risk, modern hardening against the most common automated attacks on a
 * WordPress login:
 *
 *   1. Username enumeration via ?author=N author scans (guests only).
 *   2. Username enumeration via the REST /wp/v2/users endpoints (guests only).
 *   3. Verbose login errors that confirm a valid username to an attacker
 *      (collapsed to one neutral message, for both wp-login.php and the
 *      plugin's own forms).
 *   4. The XML-RPC brute-force / pingback-amplification surface (opt-in).
 *
 * Each protection is individually toggleable from Settings → Zen Login &
 * Authentication → Security. Enumeration protection and generic login errors
 * default ON (no impact on a normal site); XML-RPC stays OFF by default so
 * Jetpack and the WordPress mobile app keep working unless you choose otherwise.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Option accessors
 * -------------------------------------------------------------------- */

function zenlogau_harden_enumeration_enabled(): bool {
    return (bool) apply_filters( 'zenlogau_harden_enumeration', get_option( 'zenlogau_harden_enum', true ) );
}

function zenlogau_harden_generic_login_errors_enabled(): bool {
    return (bool) apply_filters( 'zenlogau_harden_generic_login_errors', get_option( 'zenlogau_generic_login_errors', true ) );
}

function zenlogau_harden_xmlrpc_disabled(): bool {
    return (bool) apply_filters( 'zenlogau_harden_disable_xmlrpc', get_option( 'zenlogau_disable_xmlrpc', false ) );
}

/* -----------------------------------------------------------------------
 * 1. Block ?author=N author-archive enumeration (guests only)
 *
 * ?author=1 makes WordPress canonical-redirect to /author/<user_login>/,
 * leaking the account's login name. We intercept on template_redirect at
 * priority 0 — before redirect_canonical (priority 10) runs the leaking
 * redirect — and send the scanner to the home page. Pretty author archives
 * (/author/name/) are untouched, so legitimate author pages still work.
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'zenlogau_block_author_enumeration', 0 );

function zenlogau_block_author_enumeration(): void {
    if ( ! zenlogau_harden_enumeration_enabled() || is_user_logged_in() ) {
        return;
    }
    // Read-only inspection of a public navigation param — no state change, so
    // no nonce applies. We only act on the numeric ?author=N enumeration form.
    if ( ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        return;
    }
    $author = sanitize_text_field( wp_unslash( $_GET['author'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    if ( '' !== $author && preg_match( '/^\d+$/', $author ) ) {
        wp_safe_redirect( home_url( '/' ), 302 );
        exit;
    }
}

/* -----------------------------------------------------------------------
 * 2. Remove the REST users endpoints for unauthenticated requests
 *
 * /wp/v2/users and /wp/v2/users/<id> expose author names and slugs to
 * anonymous callers. Logged-in users (the block editor, an editor choosing
 * an author, etc.) keep full access — the routes are only stripped for guests.
 * -------------------------------------------------------------------- */
add_filter( 'rest_endpoints', 'zenlogau_restrict_rest_user_endpoints' );

function zenlogau_restrict_rest_user_endpoints( $endpoints ) {
    if ( ! is_array( $endpoints ) || ! zenlogau_harden_enumeration_enabled() || is_user_logged_in() ) {
        return $endpoints;
    }
    unset( $endpoints['/wp/v2/users'] );
    unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    return $endpoints;
}

/* -----------------------------------------------------------------------
 * 3. Generic login errors — never confirm which half was wrong
 *
 * WordPress's default messages distinguish "unknown username" from "wrong
 * password", confirming valid usernames. We collapse the credential-mismatch
 * errors into one neutral message at the authenticate filter (late), so BOTH
 * wp-login.php and the plugin's own forms — which all route through wp_signon()
 * — show the same thing. Empty-field errors and the plugin's own login-type
 * guidance (distinct error codes) are left untouched.
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'zenlogau_generic_auth_error', 9999, 3 );

function zenlogau_generic_auth_error( $user, $username, $password ) {
    unset( $username, $password );
    if ( ! zenlogau_harden_generic_login_errors_enabled() || ! is_wp_error( $user ) ) {
        return $user;
    }
    // Core codes that reveal account existence. The plugin's login-type errors
    // use distinct codes (zenlogau_login_type_*) and are intentionally excluded.
    $leaky = [ 'invalid_username', 'invalid_email', 'incorrect_password', 'invalidcombo' ];
    if ( array_intersect( $leaky, $user->get_error_codes() ) ) {
        return new WP_Error(
            'zenlogau_invalid_credentials',
            __( 'Invalid login credentials. Please check your details and try again.', 'zen-login-authentication' )
        );
    }
    return $user;
}

/* -----------------------------------------------------------------------
 * 4. XML-RPC lockdown (opt-in, default OFF)
 *
 * xmlrpc.php is a classic brute-force amplifier (system.multicall packs many
 * login attempts into one request) and pingback.ping enables DDoS reflection
 * plus internal port scanning. When enabled we disable XML-RPC auth methods,
 * drop the pingback/multicall methods, and remove the X-Pingback advertisement
 * header. Default OFF — Jetpack and the WordPress mobile app rely on XML-RPC.
 * -------------------------------------------------------------------- */
add_filter( 'xmlrpc_enabled', 'zenlogau_filter_xmlrpc_enabled' );

function zenlogau_filter_xmlrpc_enabled( $enabled ) {
    return zenlogau_harden_xmlrpc_disabled() ? false : $enabled;
}

add_filter( 'xmlrpc_methods', 'zenlogau_filter_xmlrpc_methods' );

function zenlogau_filter_xmlrpc_methods( $methods ) {
    if ( ! is_array( $methods ) || ! zenlogau_harden_xmlrpc_disabled() ) {
        return $methods;
    }
    unset(
        $methods['pingback.ping'],
        $methods['pingback.extensions.getPingbacks'],
        $methods['system.multicall']
    );
    return $methods;
}

add_filter( 'wp_headers', 'zenlogau_filter_pingback_header' );

function zenlogau_filter_pingback_header( $headers ) {
    if ( is_array( $headers ) && zenlogau_harden_xmlrpc_disabled() ) {
        unset( $headers['X-Pingback'] );
    }
    return $headers;
}

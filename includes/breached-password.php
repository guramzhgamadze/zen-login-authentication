<?php
/**
 * Zen Login & Authentication – Breached-password blocking
 *
 * Rejects passwords that appear in the Have I Been Pwned (HIBP) breach corpus
 * when users register, reset, or change their password. Uses HIBP's k-anonymity
 * "range" API: only the first 5 characters of the password's SHA-1 hash ever
 * leave the site, and the "Add-Padding" header hides how many matches a prefix
 * has — the password itself is never transmitted and cannot be derived from the
 * request. The check fails OPEN: if the API is unreachable the password is
 * allowed, so a third-party outage can never lock users out of setting a
 * password.
 *
 * Service: https://haveibeenpwned.com/Passwords (k-anonymity model:
 * https://haveibeenpwned.com/API/v3#PwnedPasswords). Toggle under Settings →
 * Zen Login & Authentication → Security. Default OFF (opt-in) — it's the only
 * feature that contacts an external service during normal use.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

function zenlogau_block_breached_passwords_enabled(): bool {
    // Default OFF (opt-in): this is the plugin's only feature that contacts an
    // external service during normal use, so it stays off until enabled — keeping
    // the "no external calls out of the box" promise. k-anonymity means the
    // password itself is never sent when it IS enabled (see file header).
    return (bool) apply_filters( 'zenlogau_block_breached_passwords', get_option( 'zenlogau_block_breached', false ) );
}

/**
 * The error shown when a chosen password is found in a breach corpus.
 */
function zenlogau_breached_password_error_message(): string {
    return (string) apply_filters(
        'zenlogau_breached_password_message',
        __( 'This password has appeared in a known data breach and is unsafe to use. Please choose a different password.', 'zen-login-authentication' )
    );
}

/**
 * True if $password appears in the HIBP breach corpus.
 *
 * Fails open (returns false) when the feature is off, the password is empty,
 * or the API cannot be reached.
 */
function zenlogau_password_is_breached( string $password ): bool {
    if ( '' === $password || ! zenlogau_block_breached_passwords_enabled() ) {
        return false;
    }

    $hash   = strtoupper( sha1( $password ) );
    $prefix = substr( $hash, 0, 5 );
    $suffix = substr( $hash, 5 );

    $body = zenlogau_hibp_fetch_range( $prefix );
    if ( '' === $body ) {
        return false; // fail open — API unreachable
    }

    // Each line is "HASHSUFFIX:COUNT". Padded (privacy) entries have COUNT 0.
    foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
        $parts = explode( ':', (string) $line, 2 );
        if ( 0 === strcasecmp( trim( $parts[0] ), $suffix ) ) {
            return (int) ( $parts[1] ?? 0 ) > 0;
        }
    }
    return false;
}

/**
 * Fetch (and briefly cache) the HIBP range response for a 5-char hash prefix.
 * Returns the raw body, or '' on any failure.
 */
function zenlogau_hibp_fetch_range( string $prefix ): string {
    $cache_key = 'zenlogau_hibp_' . $prefix;
    $cached    = get_transient( $cache_key );
    if ( is_string( $cached ) ) {
        return $cached;
    }

    $response = wp_remote_get(
        'https://api.pwnedpasswords.com/range/' . rawurlencode( $prefix ),
        [
            'timeout'    => (int) apply_filters( 'zenlogau_hibp_timeout', 4 ),
            'headers'    => [ 'Add-Padding' => 'true' ],
            'user-agent' => 'ZenLoginAuthentication/' . ZENLOGAU_VERSION,
        ]
    );

    if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
        // Cache the failure briefly so a down API doesn't slow every submit.
        set_transient( $cache_key, '', 5 * MINUTE_IN_SECONDS );
        return '';
    }

    $body = (string) wp_remote_retrieve_body( $response );
    set_transient( $cache_key, $body, (int) apply_filters( 'zenlogau_hibp_cache_ttl', 12 * HOUR_IN_SECONDS ) );
    return $body;
}

/* -----------------------------------------------------------------------
 * wp-login.php password reset — block breached passwords there too.
 *
 * The plugin's own register/reset/account handlers call
 * zenlogau_password_is_breached() inline; this covers the native reset form.
 * WordPress validates the reset key before firing validate_password_reset, so
 * reaching this point already implies an authorised reset.
 * -------------------------------------------------------------------- */
add_action( 'validate_password_reset', 'zenlogau_validate_password_reset_breach', 10, 2 );

function zenlogau_validate_password_reset_breach( $errors, $user ): void {
    unset( $user );
    if ( ! ( $errors instanceof WP_Error ) ) {
        return;
    }
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress authorises the reset via the rp_key cookie before this hook fires; we only read the proposed password.
    $pass1 = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a password must not be altered before hashing.
    if ( '' !== $pass1 && zenlogau_password_is_breached( $pass1 ) ) {
        $errors->add( 'breached_password', zenlogau_breached_password_error_message() );
    }
}

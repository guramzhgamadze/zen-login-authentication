<?php
/**
 * WP Frontend Auth – Rate Limiting
 *
 * Uses transients to track failed attempts per IP address.
 * Works on both single-site and multisite.
 *
 * @package WP_Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/**
 * Return the anonymised IP used as the transient key.
 * IPv4: last octet zeroed. IPv6: last 80 bits zeroed.
 *
 * SECURITY (v1.4.18): The client IP is read from REMOTE_ADDR only by default.
 * Forwarded headers such as HTTP_CF_CONNECTING_IP / X-Forwarded-For are trivially
 * spoofable on any server that is not actually behind the proxy that sets them —
 * an attacker could rotate the header on each request to land in a fresh
 * rate-limit bucket and bypass throttling entirely. Sites genuinely behind
 * Cloudflare (or another trusted reverse proxy) can opt the real-client header
 * back in via the 'wpfa_rate_limit_ip_headers' filter — see below.
 *
 * @return string
 */
function wpfa_rate_limit_get_ip(): string {
    $ip = '';

    /**
     * Filter the list of $_SERVER headers checked for the client IP.
     *
     * Default is REMOTE_ADDR only (the connecting socket address, which cannot be
     * forged). If — and only if — your site is behind Cloudflare AND your origin
     * firewall restricts inbound traffic to Cloudflare's IP ranges, you may safely
     * prepend the real-client header:
     *   add_filter( 'wpfa_rate_limit_ip_headers', fn() => [ 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR' ] );
     *
     * @param string[] $headers Ordered list of $_SERVER keys to try.
     */
    $headers = (array) apply_filters( 'wpfa_rate_limit_ip_headers', [ 'REMOTE_ADDR' ] );

    foreach ( $headers as $key ) {
        if ( ! empty( $_SERVER[ $key ] ) ) {
            $ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) )[0] );
            break;
        }
    }

    // Anonymise IPv4 – zero last octet
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
        $parts    = explode( '.', $ip );
        $parts[3] = '0';
        $ip       = implode( '.', $parts );
    }

    // Anonymise IPv6 – keep only first 48 bits
    if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
        $expanded = inet_pton( $ip );
        if ( false !== $expanded ) {
            $bytes = str_split( $expanded );
            for ( $i = 6; $i < 16; $i++ ) {
                $bytes[ $i ] = "\x00";
            }
            $ip = inet_ntop( implode( '', $bytes ) );
        }
    }

    return $ip;
}

/**
 * Transient key for a given action and IP.
 *
 * @param string $action  e.g. 'login' | 'register'
 * @param string $ip
 * @return string
 */
function wpfa_rate_limit_key( $action, $ip = '' ) {
    if ( '' === $ip ) {
        $ip = wpfa_rate_limit_get_ip();
    }
    // Max transient key length is 172 chars; md5 keeps us safe.
    return 'wpfa_rl_' . $action . '_' . md5( $ip );
}

/**
 * Check whether the current IP is locked out for a given action.
 *
 * @param string $action
 * @return bool  true = locked out.
 */
function wpfa_rate_limit_is_locked( $action ) {
    if ( ! wpfa_rate_limit_action_enabled( $action ) ) {
        return false;
    }
    $attempts = (int) get_transient( wpfa_rate_limit_key( $action ) );
    $limit    = wpfa_get_rate_limit_for( $action );

    return $limit > 0 && $attempts >= $limit;
}

/**
 * Per-action enable/disable check.
 *
 * Each action (login, register, lostpassword, resetpass) has its own toggle
 * stored as wpfa_rl_enabled_{action}. Default is true (enabled) for all.
 * When false, wpfa_rate_limit_is_locked() returns false and wpfa_rate_limit_bump()
 * is a no-op for that action — so the form is never blocked on that path.
 *
 * Setting the global wpfa_rate_limit option to 0 still disables everything
 * via wpfa_rate_limit_is_locked()'s `$limit > 0` check (preserved as a
 * master kill-switch).
 *
 * @param string $action
 * @return bool
 */
function wpfa_rate_limit_action_enabled( $action ) {
    return (bool) apply_filters(
        "wpfa_rate_limit_enabled_{$action}",
        (bool) get_option( "wpfa_rl_enabled_{$action}", true )
    );
}

/**
 * Per-action threshold resolver. Returns the override if set (>0), else the global default.
 *
 * @param string $action
 * @return int
 */
function wpfa_get_rate_limit_for( $action ) {
    $override = (int) get_option( "wpfa_rl_max_{$action}", 0 );
    if ( $override > 0 ) {
        return (int) apply_filters( "wpfa_rate_limit_{$action}", $override );
    }
    return wpfa_get_rate_limit();
}

/**
 * Clear the attempt counter (e.g. after a successful login).
 *
 * @param string $action
 */
function wpfa_rate_limit_clear( $action ) {
    $key = wpfa_rate_limit_key( $action );
    delete_transient( $key );
    // FIX (v1.4.14): Also clear the timestamp transient.
    //
    // wpfa_rate_limit_bump() stores a companion _ts transient alongside the
    // counter to track when the lockout window started. Without clearing it
    // here, wpfa_rate_limit_remaining_seconds() returns a stale non-zero
    // value after a successful login — misleading any theme or plugin that
    // calls it to display "try again in X minutes" even though the user is
    // no longer locked out. The orphaned _ts also wastes a database row
    // (or object cache key) until its TTL naturally expires.
    delete_transient( $key . '_ts' );
}

/**
 * Return remaining seconds of the lockout, or 0 if not locked.
 *
 * WordPress does not expose transient TTL natively, so we store a
 * separate timestamp transient alongside the counter.
 *
 * @param string $action
 * @return int
 */
function wpfa_rate_limit_remaining_seconds( $action ) {
    $ts_key   = wpfa_rate_limit_key( $action ) . '_ts';
    $set_at   = (int) get_transient( $ts_key );
    if ( ! $set_at ) {
        return 0;
    }
    $window  = wpfa_get_rate_limit_window() * MINUTE_IN_SECONDS;
    $elapsed = time() - $set_at;
    return max( 0, $window - $elapsed );
}

/**
 * Like wpfa_rate_limit_record() but also stores the timestamp.
 *
 * Call this version from handlers.
 *
 * @param string $action
 * @return int  New attempt count.
 */
function wpfa_rate_limit_bump( $action ) {
    if ( ! wpfa_rate_limit_action_enabled( $action ) ) {
        return 0;
    }
    $key    = wpfa_rate_limit_key( $action );
    $ts_key = $key . '_ts';
    $window = wpfa_get_rate_limit_window() * MINUTE_IN_SECONDS;

    $attempts = (int) get_transient( $key );

    if ( 0 === $attempts ) {
        // First failure in this window – record start time
        set_transient( $ts_key, time(), $window );
    }

    $attempts++;
    set_transient( $key, $attempts, $window );

    do_action( 'wpfa_rate_limit_recorded', $action, $attempts );

    return $attempts;
}

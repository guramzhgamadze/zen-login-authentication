<?php
/**
 * Zen Login & Authentication – Rate Limiting
 *
 * Uses transients to track failed attempts per IP address.
 * Works on both single-site and multisite.
 *
 * @package Frontend_Auth
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
 * back in via the 'zenlogau_rate_limit_ip_headers' filter — see below.
 *
 * @return string
 */
function zenlogau_rate_limit_get_ip(): string {
    $ip = '';

    /**
     * Filter the list of $_SERVER headers checked for the client IP.
     *
     * Default is REMOTE_ADDR only (the connecting socket address, which cannot be
     * forged). If — and only if — your site is behind Cloudflare AND your origin
     * firewall restricts inbound traffic to Cloudflare's IP ranges, you may safely
     * prepend the real-client header:
     *   add_filter( 'zenlogau_rate_limit_ip_headers', fn() => [ 'HTTP_CF_CONNECTING_IP', 'REMOTE_ADDR' ] );
     *
     * @param string[] $headers Ordered list of $_SERVER keys to try.
     */
    $headers = (array) apply_filters( 'zenlogau_rate_limit_ip_headers', [ 'REMOTE_ADDR' ] );

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
function zenlogau_rate_limit_key( $action, $ip = '' ) {
    if ( '' === $ip ) {
        $ip = zenlogau_rate_limit_get_ip();
    }
    // Max transient key length is 172 chars; md5 keeps us safe.
    // nosemgrep: php.lang.security.weak-crypto.weak-crypto -- non-security hash: builds a WordPress transient cache key from the IP, not a security boundary; a collision grants no bypass.
    return 'zenlogau_rl_' . $action . '_' . md5( $ip );
}

/**
 * Check whether the current IP is locked out for a given action.
 *
 * @param string $action
 * @return bool  true = locked out.
 */
function zenlogau_rate_limit_is_locked( $action ) {
    if ( ! zenlogau_rate_limit_action_enabled( $action ) ) {
        return false;
    }
    $attempts = (int) get_transient( zenlogau_rate_limit_key( $action ) );
    $limit    = zenlogau_get_rate_limit_for( $action );

    return $limit > 0 && $attempts >= $limit;
}

/**
 * Per-action enable/disable check.
 *
 * Each action (login, register, lostpassword, resetpass) has its own toggle
 * stored as zenlogau_rl_enabled_{action}. Default is true (enabled) for all.
 * When false, zenlogau_rate_limit_is_locked() returns false and zenlogau_rate_limit_bump()
 * is a no-op for that action — so the form is never blocked on that path.
 *
 * Setting the global zenlogau_rate_limit option to 0 still disables everything
 * via zenlogau_rate_limit_is_locked()'s `$limit > 0` check (preserved as a
 * master kill-switch).
 *
 * @param string $action
 * @return bool
 */
function zenlogau_rate_limit_action_enabled( $action ) {
    return (bool) apply_filters(
        "zenlogau_rate_limit_enabled_{$action}",
        (bool) get_option( "zenlogau_rl_enabled_{$action}", true )
    );
}

/**
 * Per-action threshold resolver. Returns the override if set (>0), else the global default.
 *
 * @param string $action
 * @return int
 */
function zenlogau_get_rate_limit_for( $action ) {
    $override = (int) get_option( "zenlogau_rl_max_{$action}", 0 );
    if ( $override > 0 ) {
        return (int) apply_filters( "zenlogau_rate_limit_{$action}", $override );
    }
    return zenlogau_get_rate_limit();
}

/**
 * Clear the attempt counter (e.g. after a successful login).
 *
 * @param string $action
 */
function zenlogau_rate_limit_clear( $action ) {
    $key = zenlogau_rate_limit_key( $action );
    delete_transient( $key );
    // FIX (v1.4.14): Also clear the timestamp transient.
    //
    // zenlogau_rate_limit_bump() stores a companion _ts transient alongside the
    // counter to track when the lockout window started. Without clearing it
    // here, zenlogau_rate_limit_remaining_seconds() returns a stale non-zero
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
function zenlogau_rate_limit_remaining_seconds( $action ) {
    $ts_key   = zenlogau_rate_limit_key( $action ) . '_ts';
    $set_at   = (int) get_transient( $ts_key );
    if ( ! $set_at ) {
        return 0;
    }
    $window  = zenlogau_get_rate_limit_window() * MINUTE_IN_SECONDS;
    $elapsed = time() - $set_at;
    return max( 0, $window - $elapsed );
}

/**
 * Like zenlogau_rate_limit_record() but also stores the timestamp.
 *
 * Call this version from handlers.
 *
 * @param string $action
 * @return int  New attempt count.
 */
function zenlogau_rate_limit_bump( $action ) {
    if ( ! zenlogau_rate_limit_action_enabled( $action ) ) {
        return 0;
    }
    $key    = zenlogau_rate_limit_key( $action );
    $ts_key = $key . '_ts';
    $window = zenlogau_get_rate_limit_window() * MINUTE_IN_SECONDS;

    $attempts = (int) get_transient( $key );

    if ( 0 === $attempts ) {
        // First failure in this window – record start time
        set_transient( $ts_key, time(), $window );
    }

    $attempts++;
    set_transient( $key, $attempts, $window );

    // Fire once, the moment this IP crosses the threshold for this action, so
    // the activity log records a single "blocked for spamming" lockout event
    // (not one per subsequent blocked attempt).
    $limit = zenlogau_get_rate_limit_for( $action );
    if ( $limit > 0 && $attempts === $limit ) {
        /**
         * Fires when an IP first becomes locked out for an action.
         *
         * @param string $action   The form action (login, register, …).
         * @param string $ip       The anonymised client IP.
         * @param int    $attempts The attempt count at lockout (equals the limit).
         */
        do_action( 'zenlogau_rate_limit_locked', $action, zenlogau_rate_limit_get_ip(), $attempts );
    }

    do_action( 'zenlogau_rate_limit_recorded', $action, $attempts );

    return $attempts;
}

/* =======================================================================
 * Per-account progressive throttle (v2.2.0)
 *
 * The IP limiter above buckets on the client IP, so an attacker who rotates IP
 * addresses can keep guessing a single account's password without ever tripping
 * it. This adds a SECOND, account-keyed defence: after a few failed logins for
 * the same username, each further failed attempt is delayed by a short,
 * progressively longer pause.
 *
 * It is deliberately a DELAY, not a lockout — the real owner is never blocked.
 * A correct password succeeds with no delay and clears the counter, so it cannot
 * be weaponised to lock a victim out (unlike a hard per-account lock). The delay
 * is capped (default 3s) so it slows credential-stuffing without letting an
 * attacker tie up PHP workers. Both ends are filterable; set the option/filter
 * to false to disable entirely.
 * ==================================================================== */

/**
 * Whether the per-account throttle is on. Default: on. Option + filter.
 */
function zenlogau_account_throttle_enabled(): bool {
    return (bool) apply_filters(
        'zenlogau_account_throttle_enabled',
        (bool) get_option( 'zenlogau_account_throttle', true )
    );
}

/**
 * Transient key for an account's recent failed-login counter.
 */
function zenlogau_account_throttle_key( string $username ): string {
    $norm = strtolower( trim( $username ) );
    // nosemgrep: php.lang.security.weak-crypto.weak-crypto -- non-security hash: builds a transient cache key from the username, not a security boundary; a collision only merges two accounts' throttle counters, granting no bypass.
    return 'zenlogau_acct_thr_' . md5( $norm );
}

/**
 * Failed attempts allowed for an account before any delay kicks in.
 */
function zenlogau_account_throttle_free_attempts(): int {
    return max( 0, (int) apply_filters( 'zenlogau_account_throttle_free_attempts', 3 ) );
}

/**
 * Maximum per-attempt delay, in seconds (the cap). Kept small on purpose.
 */
function zenlogau_account_throttle_max_delay(): int {
    return max( 0, (int) apply_filters( 'zenlogau_account_throttle_max_delay', 3 ) );
}

/**
 * Window (seconds) over which an account's failures accumulate.
 */
function zenlogau_account_throttle_window(): int {
    return max( (int) MINUTE_IN_SECONDS, (int) apply_filters( 'zenlogau_account_throttle_window', 15 * MINUTE_IN_SECONDS ) );
}

/**
 * Progressive delay for the Nth failure: 0 while within the free allowance, then
 * 1, 2, 3 … seconds, capped at the max. Linear growth keeps it bounded.
 */
function zenlogau_account_throttle_delay_for( int $count ): int {
    $free = zenlogau_account_throttle_free_attempts();
    if ( $count <= $free ) {
        return 0;
    }
    return (int) min( zenlogau_account_throttle_max_delay(), $count - $free );
}

add_action( 'wp_login_failed', 'zenlogau_account_throttle_on_failed', 5, 1 );

/**
 * Record a failed login for the account and apply the progressive delay. Fires
 * on every failed login path (the plugin's forms, wp-login.php, wp_signon).
 *
 * @param string $username The attempted username/email.
 */
function zenlogau_account_throttle_on_failed( $username ): void {
    $username = (string) $username;
    if ( '' === $username || ! zenlogau_account_throttle_enabled() ) {
        return;
    }

    $key   = zenlogau_account_throttle_key( $username );
    $count = (int) get_transient( $key ) + 1;
    set_transient( $key, $count, zenlogau_account_throttle_window() );

    $delay = zenlogau_account_throttle_delay_for( $count );
    if ( $delay > 0 ) {
        // Bounded pause that only ever delays a FAILURE response; a correct
        // password takes the success path (wp_login) and is never delayed.
        sleep( $delay ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_sleep, Squiz.PHP.DiscouragedFunctions, WordPress.PHP.NoSilencedErrors -- intentional anti-brute-force throttle, capped at a few seconds and only on repeated failures for one account.
    }
}

add_action( 'wp_login', 'zenlogau_account_throttle_clear_on_login', 5, 1 );

/**
 * Clear an account's failure counter after a successful login.
 *
 * @param string $user_login The user that logged in.
 */
function zenlogau_account_throttle_clear_on_login( $user_login ): void {
    if ( zenlogau_account_throttle_enabled() ) {
        delete_transient( zenlogau_account_throttle_key( (string) $user_login ) );
    }
}

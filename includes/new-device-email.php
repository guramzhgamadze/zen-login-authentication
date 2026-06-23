<?php
/**
 * Zen Login & Authentication – New-device login email
 *
 * Sends the account owner an alert the first time their account is signed in
 * from a browser/device the plugin has not seen before. Mirrors the behaviour
 * of Google/GitHub "new sign-in" notifications.
 *
 * Device recognition is cookie-based: a long-lived, randomly generated token is
 * stored in the browser (cookie "zenlogau_device") and its SHA-256 hash is kept
 * in the user's "zenlogau_known_devices" meta. A login whose cookie hash is not
 * in that list is treated as a new device — the alert is sent and the device is
 * remembered. Clearing cookies will (intentionally) re-trigger the alert, which
 * is the standard, expected trade-off for this kind of feature.
 *
 * Everything happens server-side via wp_mail(); no external service is called.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_DEVICE_COOKIE   = 'zenlogau_device';
const ZENLOGAU_DEVICE_META     = 'zenlogau_known_devices';
const ZENLOGAU_DEVICE_LIFETIME = YEAR_IN_SECONDS;

/**
 * Master switch. Default ON — this is a pure security benefit that uses only
 * wp_mail() (no third-party request).
 */
function zenlogau_new_device_email_enabled(): bool {
    return (bool) apply_filters(
        'zenlogau_new_device_email_enabled',
        (bool) get_option( 'zenlogau_new_device_email', true )
    );
}

/**
 * Sanitize the admin's custom email body.
 *
 * Email clients ignore <style>/<head>/<link> and only honour inline styles.
 * Worse, wp_kses_post() strips the <style> TAG but keeps its text, which the
 * mailer then renders as visible CSS wrapped in <p>. So we strip those blocks
 * (content included) and any document-wrapper tags BEFORE running wp_kses_post,
 * leaving only inline-styled body HTML.
 */
function zenlogau_sanitize_email_body( $value ): string {
    $value = is_scalar( $value ) ? (string) $value : '';
    // Drop <head>/<style>/<script> blocks together with their contents
    // (removing <head> first also clears any <style> nested inside it).
    $value = (string) preg_replace( '#<head\b[^>]*>.*?</head>#is', '', $value );
    $value = (string) preg_replace( '#<style\b[^>]*>.*?</style>#is', '', $value );
    $value = (string) preg_replace( '#<script\b[^>]*>.*?</script>#is', '', $value );
    $value = (string) preg_replace( '#<link\b[^>]*>#i', '', $value );
    // Strip document-wrapper tags (the mailer expects a body fragment).
    $value = (string) preg_replace( '#</?(html|body)\b[^>]*>#i', '', $value );
    return wp_kses_post( $value );
}

/* -----------------------------------------------------------------------
 * Hook: runs after a successful, interactive login on every path
 * (plugin forms, wp-login.php, Google sign-in, and after a 2FA challenge).
 * Application-password / REST auth does not fire wp_login, so API tokens
 * never trigger this.
 * -------------------------------------------------------------------- */
add_action( 'wp_login', 'zenlogau_new_device_check', 20, 2 );

/**
 * @param string  $user_login The user that just logged in (unused; $user is authoritative).
 * @param WP_User $user       The authenticated user.
 */
function zenlogau_new_device_check( $user_login, $user = null ): void {
    if ( ! zenlogau_new_device_email_enabled() ) {
        return;
    }
    if ( wp_doing_cron() ) {
        return;
    }
    if ( ! $user instanceof WP_User || ! $user->exists() ) {
        return;
    }

    $devices = zenlogau_get_known_devices( $user->ID );
    $token   = zenlogau_get_device_cookie_token();
    $now     = time();

    if ( '' !== $token ) {
        $hash = zenlogau_device_token_hash( $token );
        if ( isset( $devices[ $hash ] ) ) {
            // Recognised device — just refresh "last seen" and the cookie expiry.
            $devices[ $hash ]['last'] = $now;
            zenlogau_store_known_devices( $user->ID, $devices );
            zenlogau_set_device_cookie( $token );
            return;
        }
    }

    // Unrecognised device: remember it, refresh/issue the cookie, alert the user.
    if ( '' === $token ) {
        $token = zenlogau_generate_device_token();
    }
    $hash = zenlogau_device_token_hash( $token );

    $ip = zenlogau_new_device_client_ip();
    $ua = zenlogau_new_device_user_agent();

    $devices[ $hash ] = [
        'ua'    => $ua,
        'ip'    => $ip,
        'first' => $now,
        'last'  => $now,
    ];
    zenlogau_store_known_devices( $user->ID, $devices );
    zenlogau_set_device_cookie( $token );

    $details = [
        'ip'         => $ip,
        'user_agent' => $ua,
        'time'       => $now,
    ];

    /**
     * Allow the alert to be suppressed for a specific login (e.g. right after
     * registration). Return false to skip the email; the device is still
     * remembered, so it will not alert again.
     *
     * @param bool    $send    Whether to send the alert.
     * @param WP_User $user    The user.
     * @param array   $details Login details (ip, user_agent, time).
     */
    if ( ! apply_filters( 'zenlogau_send_new_device_email', true, $user, $details ) ) {
        do_action( 'zenlogau_new_device_login', $user->ID, $details );
        return;
    }

    zenlogau_send_new_device_email( $user, $details );
    do_action( 'zenlogau_new_device_login', $user->ID, $details );
}

/* -----------------------------------------------------------------------
 * Email
 * -------------------------------------------------------------------- */

function zenlogau_send_new_device_email( WP_User $user, array $details ): void {
    $site_name = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
    $when      = wp_date(
        get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
        (int) $details['time']
    );
    $ip          = '' !== $details['ip'] ? $details['ip'] : __( 'unknown', 'zen-login-authentication' );
    $ua          = '' !== $details['user_agent'] ? $details['user_agent'] : __( 'unknown', 'zen-login-authentication' );
    $account_url = zenlogau_get_action_url( 'account' );

    /* translators: %s: site name. */
    $subject = sprintf( __( '[%s] New sign-in to your account', 'zen-login-authentication' ), $site_name );

    $subject = (string) apply_filters( 'zenlogau_new_device_email_subject', $subject, $user, $details );

    // An administrator can override the body (HTML, inline styles only) from the
    // settings page; placeholder tokens are substituted with escaped values and
    // the template was sanitised with zenlogau_sanitize_email_body() on save.
    // When blank, the styled inline-CSS default below is sent.
    $custom = trim( (string) get_option( 'zenlogau_new_device_email_body', '' ) );
    if ( '' !== $custom ) {
        $html = wpautop( strtr( $custom, [
            '{site_name}'    => esc_html( $site_name ),
            '{display_name}' => esc_html( $user->display_name ),
            '{time}'         => esc_html( $when ),
            '{ip}'           => esc_html( $ip ),
            '{device}'       => esc_html( $ua ),
            '{account_url}'  => esc_url( $account_url ),
        ] ) );
    } else {
        $html = zenlogau_new_device_email_default_html( $user, $site_name, $when, $ip, $ua, $account_url );
    }

    /**
     * Filter the final HTML email body.
     *
     * @param string  $html    Email body HTML.
     * @param WP_User $user    The user.
     * @param array   $details Login details.
     */
    $html    = (string) apply_filters( 'zenlogau_new_device_email_message', $html, $user, $details );
    $headers = [ 'Content-Type: text/html; charset=UTF-8' ];
    wp_mail( $user->user_email, wp_specialchars_decode( $subject, ENT_QUOTES ), $html, $headers );
}

/**
 * The styled, inline-CSS default alert body (HTML email). Table-based for email
 * client compatibility; security-blue header, a details box, and a CTA button.
 * Inline styles only — no <style>/<head>, which mailers and clients strip.
 */
function zenlogau_new_device_email_default_html( WP_User $user, string $site_name, string $when, string $ip, string $ua, string $account_url ): string {
    $e_site = esc_html( $site_name );
    $e_name = esc_html( $user->display_name );
    $e_when = esc_html( $when );
    $e_ip   = esc_html( $ip );
    $e_ua   = esc_html( $ua );
    $e_url  = esc_url( $account_url );

    /* translators: %s: user display name. */
    $greeting = sprintf( esc_html__( 'Hi %s,', 'zen-login-authentication' ), $e_name );
    /* translators: %s: site name (already wrapped in bold). */
    $intro    = sprintf( esc_html__( 'Your account at %s was just signed in to from a device we have not seen before:', 'zen-login-authentication' ), '<strong>' . $e_site . '</strong>' );
    $l_time   = esc_html__( 'Time', 'zen-login-authentication' );
    $l_ip     = esc_html__( 'IP address', 'zen-login-authentication' );
    $l_device = esc_html__( 'Device', 'zen-login-authentication' );
    $reassure = esc_html__( 'If this was you, no action is needed.', 'zen-login-authentication' );
    $cta      = esc_html__( 'Review your account', 'zen-login-authentication' );
    $warn     = esc_html__( "If you don't recognise this sign-in, change your password right away and sign out of other devices from your account page.", 'zen-login-authentication' );

    // Stacked rows (label above value) so long values like the user-agent get
    // the full card width and wrap cleanly on narrow mobile screens, instead of
    // being squeezed into a fixed-width second column (one word per line).
    $row = static function ( string $label, string $value, bool $first ): string {
        $top = $first ? '' : 'border-top:1px solid #eef2f6;';
        return '<tr><td style="padding:12px 18px;' . $top . '">'
            . '<div style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.03em;margin:0 0 3px;">' . $label . '</div>'
            . '<div style="color:#0f172a;font-size:14px;line-height:1.5;word-break:break-word;overflow-wrap:anywhere;">' . $value . '</div>'
            . '</td></tr>';
    };

    $details = '<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;margin:0 0 20px;border-collapse:separate;">'
        . $row( $l_time, $e_when, true )
        . $row( $l_ip, $e_ip, false )
        . $row( $l_device, $e_ua, false )
        . '</table>';

    return '<div style="background:#f1f5f9;padding:24px 12px;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,sans-serif;">'
        . '<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;border-collapse:separate;overflow:hidden;">'
        . '<tr><td style="background:#0369a1;padding:18px 28px;"><span style="color:#ffffff;font-size:16px;font-weight:600;">' . $e_site . '</span></td></tr>'
        . '<tr><td style="padding:28px;color:#0f172a;font-size:15px;line-height:1.6;">'
        . '<p style="margin:0 0 14px;">' . $greeting . '</p>'
        . '<p style="margin:0 0 18px;color:#334155;">' . $intro . '</p>'
        . $details
        . '<p style="margin:0 0 18px;color:#334155;">' . $reassure . '</p>'
        . '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 4px;"><tr><td style="border-radius:10px;background:#0369a1;">'
        . '<a href="' . $e_url . '" style="display:inline-block;padding:11px 24px;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;">' . $cta . '</a>'
        . '</td></tr></table>'
        . '<p style="margin:18px 0 0;color:#64748b;font-size:13px;">' . $warn . '</p>'
        . '</td></tr></table></div>';
}

/* -----------------------------------------------------------------------
 * Known-device storage
 * -------------------------------------------------------------------- */

function zenlogau_get_known_devices( int $user_id ): array {
    $devices = get_user_meta( $user_id, ZENLOGAU_DEVICE_META, true );
    return is_array( $devices ) ? $devices : [];
}

/**
 * Persist the known-device list, pruning the oldest entries so the meta cannot
 * grow without bound.
 */
function zenlogau_store_known_devices( int $user_id, array $devices ): void {
    $limit = (int) apply_filters( 'zenlogau_known_devices_limit', 20 );
    if ( $limit > 0 && count( $devices ) > $limit ) {
        // Keep the most recently seen.
        uasort( $devices, static function ( $a, $b ): int {
            return ( (int) ( $b['last'] ?? 0 ) ) <=> ( (int) ( $a['last'] ?? 0 ) );
        } );
        $devices = array_slice( $devices, 0, $limit, true );
    }
    update_user_meta( $user_id, ZENLOGAU_DEVICE_META, $devices );
}

/* -----------------------------------------------------------------------
 * Cookie + token helpers
 * -------------------------------------------------------------------- */

function zenlogau_generate_device_token(): string {
    return bin2hex( random_bytes( 24 ) );
}

/**
 * Hash a device token before it is stored, so the raw cookie value never lands
 * in the database. Salted with the install's auth salt.
 */
function zenlogau_device_token_hash( string $token ): string {
    return hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
}

function zenlogau_get_device_cookie_token(): string {
    // Read $_COOKIE directly: PHP's default request_order is "GP", so $_REQUEST
    // does NOT contain cookies. No nonce is involved — this is an opaque
    // identification token, not a state-changing action, and the real check is
    // the hash match against the user's stored device list.
    if ( empty( $_COOKIE[ ZENLOGAU_DEVICE_COOKIE ] ) ) {
        return '';
    }
    $raw = wp_unslash( $_COOKIE[ ZENLOGAU_DEVICE_COOKIE ] ); // phpcs:ignore WordPress.Security.NonceVerification.NoNonceVerification -- opaque device id, sanitized to hex below.
    if ( ! is_string( $raw ) ) {
        return '';
    }
    $raw = preg_replace( '/[^a-f0-9]/', '', strtolower( $raw ) );
    return is_string( $raw ) ? $raw : '';
}

function zenlogau_set_device_cookie( string $token ): void {
    if ( headers_sent() ) {
        return;
    }
    $expire = time() + ZENLOGAU_DEVICE_LIFETIME;
    setcookie(
        ZENLOGAU_DEVICE_COOKIE,
        $token,
        [
            'expires'  => $expire,
            'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
            'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
    // Make it readable within this same request too.
    $_COOKIE[ ZENLOGAU_DEVICE_COOKIE ] = $token;
}

/* -----------------------------------------------------------------------
 * Request metadata (full IP — unlike the anonymised rate-limit getter,
 * the account owner needs to see the actual address)
 * -------------------------------------------------------------------- */

function zenlogau_new_device_client_ip(): string {
    // Same trust policy as rate limiting: REMOTE_ADDR only, unless the site
    // opts forwarded headers in for a genuine reverse-proxy setup.
    $headers = (array) apply_filters( 'zenlogau_rate_limit_ip_headers', [ 'REMOTE_ADDR' ] );
    foreach ( $headers as $key ) {
        if ( empty( $_SERVER[ $key ] ) ) {
            continue;
        }
        $candidate = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) )[0] );
        if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
            return $candidate;
        }
    }
    return '';
}

function zenlogau_new_device_user_agent(): string {
    if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
        return '';
    }
    $ua = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
    // UA strings are ASCII; a byte-wise cut at 255 is safe and avoids a hard
    // mbstring dependency.
    return substr( $ua, 0, 255 );
}

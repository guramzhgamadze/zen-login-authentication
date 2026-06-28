<?php
/**
 * Zen Login & Authentication – Two-Factor Authentication (TOTP)
 *
 * Opt-in, per-user app-based 2FA managed from the frontend Account page. Builds
 * on the verified RFC 6238 core in includes/totp.php.
 *
 * Security model:
 *  - The shared secret is stored ENCRYPTED at rest (includes/crypto.php).
 *  - Recovery codes are stored HASHED (sha256) and are single-use.
 *  - The login challenge never sets an auth cookie until the second factor is
 *    verified. After a correct password, the half-authenticated user is held in
 *    a short-lived, single-use server-side token (transient, 10 min) — NOT a
 *    cookie — and a TOTP-or-recovery-code step must pass before wp_set_auth_cookie.
 *    Enforced on the `authenticate` filter (priority 100), so no login path
 *    (the plugin's forms, AJAX, or wp-login.php) can complete without it.
 *
 * Scope: Google sign-in is exempt (it is its own verified flow and bypasses
 * wp_signon/authenticate). 2FA applies to password logins.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_2FA_RECOVERY_COUNT = 10;
const ZENLOGAU_2FA_LOGIN_TTL      = 600; // seconds a pending-login token lives

/* -----------------------------------------------------------------------
 * Feature toggle
 * -------------------------------------------------------------------- */

function zenlogau_2fa_feature_enabled(): bool {
    return (bool) apply_filters( 'zenlogau_2fa_feature_enabled', get_option( 'zenlogau_2fa_feature', true ) );
}

/* -----------------------------------------------------------------------
 * Enrollment QR assets — bundled qrcode-generator (MIT, no external calls)
 * -------------------------------------------------------------------- */
add_action( 'init', 'zenlogau_2fa_register_assets' );

function zenlogau_2fa_register_assets(): void {
    // The QR library is heavy and only needed during enrollment, so the main
    // 2FA script does not hard-depend on it — it renders the QR only if the lib
    // is present (enrollment enqueues both), and handles copy/download otherwise.
    wp_register_script( 'zenlogau-qrcode', ZENLOGAU_URL . 'assets/scripts/qrcode.js', [], '1.4.4', [ 'in_footer' => true ] );
    wp_register_script( 'zenlogau-2fa', ZENLOGAU_URL . 'assets/scripts/zenlogau-2fa.js', [], ZENLOGAU_VERSION, [ 'in_footer' => true ] );
}

/* -----------------------------------------------------------------------
 * Per-user state (user meta)
 * -------------------------------------------------------------------- */

function zenlogau_2fa_user_enabled( int $user_id ): bool {
    return '1' === (string) get_user_meta( $user_id, 'zenlogau_2fa_enabled', true )
        && '' !== zenlogau_2fa_get_secret( $user_id );
}

function zenlogau_2fa_get_secret( int $user_id ): string {
    return zenlogau_2fa_read_secret_meta( $user_id, 'zenlogau_2fa_secret' );
}

function zenlogau_2fa_get_pending_secret( int $user_id ): string {
    return zenlogau_2fa_read_secret_meta( $user_id, 'zenlogau_2fa_pending_secret' );
}

function zenlogau_2fa_read_secret_meta( int $user_id, string $key ): string {
    $stored = (string) get_user_meta( $user_id, $key, true );
    if ( '' === $stored ) {
        return '';
    }
    return zenlogau_crypto_is_encrypted( $stored ) ? zenlogau_crypto_decrypt( $stored ) : $stored;
}

function zenlogau_2fa_store_secret( int $user_id, string $secret_base32, bool $pending ): void {
    $key = $pending ? 'zenlogau_2fa_pending_secret' : 'zenlogau_2fa_secret';
    update_user_meta( $user_id, $key, zenlogau_crypto_encrypt( $secret_base32 ) );
}

function zenlogau_2fa_disable_user( int $user_id ): void {
    delete_user_meta( $user_id, 'zenlogau_2fa_secret' );
    delete_user_meta( $user_id, 'zenlogau_2fa_pending_secret' );
    delete_user_meta( $user_id, 'zenlogau_2fa_enabled' );
    delete_user_meta( $user_id, 'zenlogau_2fa_recovery' );
    delete_user_meta( $user_id, 'zenlogau_2fa_last_step' );
    do_action( 'zenlogau_2fa_disabled', $user_id );
}

/* -----------------------------------------------------------------------
 * Recovery codes (stored hashed, single-use)
 * -------------------------------------------------------------------- */

function zenlogau_2fa_generate_recovery_codes( int $user_id, int $count = ZENLOGAU_2FA_RECOVERY_COUNT ): array {
    $codes  = [];
    $hashes = [];
    for ( $i = 0; $i < $count; $i++ ) {
        $code     = zenlogau_2fa_random_recovery_code();
        $codes[]  = $code;
        $hashes[] = hash( 'sha256', $code );
    }
    update_user_meta( $user_id, 'zenlogau_2fa_recovery', $hashes );
    return $codes; // plaintext — shown to the user exactly once
}

function zenlogau_2fa_random_recovery_code(): string {
    // Crockford-style alphabet (no 0/O/1/I/L) in two groups of five.
    $alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    $max      = strlen( $alphabet ) - 1;
    $out      = '';
    for ( $i = 0; $i < 10; $i++ ) {
        $out .= $alphabet[ random_int( 0, $max ) ];
    }
    return substr( $out, 0, 5 ) . '-' . substr( $out, 5, 5 );
}

function zenlogau_2fa_recovery_count( int $user_id ): int {
    return count( (array) get_user_meta( $user_id, 'zenlogau_2fa_recovery', true ) );
}

function zenlogau_2fa_consume_recovery_code( int $user_id, string $code ): bool {
    $code   = strtoupper( trim( $code ) );
    if ( '' === $code ) {
        return false;
    }
    $hashes = (array) get_user_meta( $user_id, 'zenlogau_2fa_recovery', true );
    $idx    = array_search( hash( 'sha256', $code ), $hashes, true );
    if ( false === $idx ) {
        return false;
    }
    unset( $hashes[ $idx ] );
    update_user_meta( $user_id, 'zenlogau_2fa_recovery', array_values( $hashes ) );
    return true;
}

/**
 * Verify a submitted value as either the current TOTP code or an unused
 * recovery code. Recovery codes are consumed on success.
 */
function zenlogau_2fa_verify_input( int $user_id, string $input ): bool {
    $input  = trim( $input );
    $secret = zenlogau_2fa_get_secret( $user_id );
    if ( '' !== $secret && zenlogau_2fa_totp_verify_no_replay( $user_id, $secret, $input ) ) {
        return true;
    }
    return zenlogau_2fa_consume_recovery_code( $user_id, $input );
}

/**
 * Verify a TOTP code AND prevent replay: each time-step can be used only once.
 * The last accepted step is stored per user; a code at or before it is rejected
 * even while still inside the ±1 clock-skew window (RFC 6238 §5.2). The pure
 * window logic lives here (not in totp.php) so totp.php stays WordPress-free.
 */
function zenlogau_2fa_totp_verify_no_replay( int $user_id, string $secret, string $code, int $window = 1 ): bool {
    $code = (string) preg_replace( '/\D/', '', $code );
    if ( strlen( $code ) !== ZENLOGAU_TOTP_DIGITS ) {
        return false;
    }
    $current_step = intdiv( time(), ZENLOGAU_TOTP_PERIOD );
    $last_step    = (int) get_user_meta( $user_id, 'zenlogau_2fa_last_step', true );
    for ( $i = -$window; $i <= $window; $i++ ) {
        $step = $current_step + $i;
        if ( $step <= $last_step ) {
            continue; // already consumed — reject the replay
        }
        $candidate = zenlogau_totp_code( $secret, $step * ZENLOGAU_TOTP_PERIOD );
        if ( hash_equals( $candidate, $code ) ) {
            update_user_meta( $user_id, 'zenlogau_2fa_last_step', $step );
            return true;
        }
    }
    return false;
}

/* -----------------------------------------------------------------------
 * Pending-login token (the half-authenticated holding state)
 * -------------------------------------------------------------------- */

function zenlogau_2fa_create_pending_login( int $user_id, bool $remember, string $redirect ): string {
    $token = bin2hex( random_bytes( 20 ) );
    set_transient(
        'zenlogau_2fa_login_' . $token,
        [ 'uid' => $user_id, 'remember' => $remember, 'redirect' => $redirect ],
        ZENLOGAU_2FA_LOGIN_TTL
    );
    return $token;
}

function zenlogau_2fa_get_pending_login( string $token ) {
    $token = preg_replace( '/[^a-f0-9]/', '', $token );
    if ( '' === $token ) {
        return false;
    }
    $data = get_transient( 'zenlogau_2fa_login_' . $token );
    return is_array( $data ) ? $data : false;
}

function zenlogau_2fa_clear_pending_login( string $token ): void {
    $token = preg_replace( '/[^a-f0-9]/', '', $token );
    if ( '' !== $token ) {
        delete_transient( 'zenlogau_2fa_login_' . $token );
    }
}

/* -----------------------------------------------------------------------
 * Login enforcement — hold the login until the second factor is verified
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'zenlogau_2fa_authenticate_guard', 100, 3 );

function zenlogau_2fa_authenticate_guard( $user, $username, $password ) {
    unset( $username, $password );
    if ( ! zenlogau_2fa_feature_enabled() || ! ( $user instanceof WP_User ) ) {
        return $user; // only act once a password has fully validated
    }
    // Never intercept non-interactive auth: REST / XML-RPC application passwords
    // are designed to bypass interactive 2FA, and cron/CLI have no second factor.
    if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST )
        || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
        || did_action( 'application_password_did_authenticate' )
        || wp_doing_cron()
        || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
        return $user;
    }
    if ( ! zenlogau_2fa_user_enabled( (int) $user->ID ) || ! zenlogau_is_post_request() ) {
        return $user;
    }

    $remember = '' !== (string) zenlogau_get_request_value( 'rememberme', 'post' );
    $redirect = (string) zenlogau_get_request_value( 'redirect_to' );
    $token    = zenlogau_2fa_create_pending_login( (int) $user->ID, $remember, $redirect );

    // The plugin's own login form: hand the token back as an error so the login
    // handler can redirect to the themed challenge (it intercepts this code).
    if ( 'login' === sanitize_key( zenlogau_get_request_value( 'zenlogau_action', 'post' ) ) ) {
        return new WP_Error(
            'zenlogau_2fa_required',
            __( 'Enter your authentication code to finish signing in.', 'zen-login-authentication' ),
            [ 'token' => $token ]
        );
    }

    // wp-login.php / any other wp_signon path: send them to the themed challenge.
    wp_safe_redirect( add_query_arg( 'zenlogau_2fa', $token, zenlogau_get_action_url( 'login' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Swap the login form for the challenge form when a pending token is present
 * -------------------------------------------------------------------- */
add_filter( 'zenlogau_form_html', 'zenlogau_2fa_maybe_swap_login_form', 10, 3 );

function zenlogau_2fa_maybe_swap_login_form( $html, $name, $form ) {
    unset( $form );
    if ( 'login' !== $name || ! zenlogau_2fa_feature_enabled() ) {
        return $html;
    }
    $token = (string) zenlogau_get_request_value( 'zenlogau_2fa', 'get' );
    if ( false === zenlogau_2fa_get_pending_login( $token ) ) {
        return $html; // no/expired token — show the normal login form
    }
    $error = '' !== (string) zenlogau_get_request_value( 'zenlogau_2fa_error', 'get' );
    return zenlogau_2fa_challenge_form_html( $token, $error );
}

function zenlogau_2fa_challenge_form_html( string $token, bool $error ): string {
    $token = preg_replace( '/[^a-f0-9]/', '', $token );
    ob_start();
    echo '<div class="fauth fauth-form fauth-form-login fauth-2fa-challenge">';
    if ( $error ) {
        echo '<ul class="fauth-errors" role="alert"><li class="fauth-error">'
            . esc_html__( 'That code was not correct. Please try again.', 'zen-login-authentication' )
            . '</li></ul>';
    }
    echo '<form method="post" action="' . esc_url( zenlogau_get_action_url( 'login' ) ) . '" class="fauth-inner-form" novalidate>';
    wp_nonce_field( 'zenlogau_2fa_verify', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="verify">';
    echo '<input type="hidden" name="zenlogau_2fa_token" value="' . esc_attr( $token ) . '">';
    echo '<p class="fauth-field-wrap fauth-field-2fa-code">';
    echo '<label class="fauth-label" for="zenlogau-2fa-code">' . esc_html__( 'Authentication code', 'zen-login-authentication' ) . '</label>';
    echo '<input type="text" id="zenlogau-2fa-code" name="zenlogau_2fa_code" class="fauth-field" inputmode="numeric" autocomplete="one-time-code" autofocus pattern="[0-9A-Za-z\-]*" required>';
    echo '<span class="fauth-description">' . esc_html__( 'Open your authenticator app and enter the 6-digit code, or use a recovery code.', 'zen-login-authentication' ) . '</span>';
    echo '</p>';
    echo '<p class="fauth-submit"><button type="submit" class="fauth-button fauth-submit-button">' . esc_html__( 'Verify', 'zen-login-authentication' ) . '</button></p>';
    echo '</form>';
    echo '</div>';
    return (string) ob_get_clean();
}

/* -----------------------------------------------------------------------
 * Request router for all 2FA POST actions
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'zenlogau_2fa_route', 1 );

function zenlogau_2fa_route(): void {
    if ( ! zenlogau_2fa_feature_enabled() || ! zenlogau_is_post_request() ) {
        return;
    }
    $action = sanitize_key( zenlogau_get_request_value( 'zenlogau_2fa_action', 'post' ) );
    if ( '' === $action ) {
        return;
    }
    $nonce = sanitize_key( zenlogau_get_request_value( 'zenlogau_2fa_nonce', 'post' ) );

    if ( 'verify' === $action ) {
        if ( ! wp_verify_nonce( $nonce, 'zenlogau_2fa_verify' ) ) {
            zenlogau_2fa_fail_or_die( __( 'Your session expired. Please log in again.', 'zen-login-authentication' ) );
        }
        zenlogau_2fa_handle_verify();
        return;
    }

    // Account-management actions: require a logged-in user and a matching nonce.
    if ( ! is_user_logged_in() || ! wp_verify_nonce( $nonce, 'zenlogau_2fa_' . $action ) ) {
        return;
    }
    switch ( $action ) {
        case 'setup':
            zenlogau_2fa_handle_setup();
            break;
        case 'activate':
            zenlogau_2fa_handle_activate();
            break;
        case 'cancel':
            zenlogau_2fa_handle_cancel();
            break;
        case 'disable':
            zenlogau_2fa_handle_disable();
            break;
        case 'regen':
            zenlogau_2fa_handle_regen();
            break;
    }
}

/**
 * The login challenge: verify the second factor and complete the login.
 */
function zenlogau_2fa_handle_verify(): void {
    $is_ajax = zenlogau_is_ajax_request();
    $token   = (string) zenlogau_get_request_value( 'zenlogau_2fa_token', 'post' );
    $pending = zenlogau_2fa_get_pending_login( $token );

    if ( false === $pending ) {
        $msg = __( 'Your sign-in session expired. Please log in again.', 'zen-login-authentication' );
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ $msg ], 'redirect' => zenlogau_get_action_url( 'login' ) ] );
        }
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }

    $uid = (int) $pending['uid'];

    // Throttle code attempts on the shared login bucket.
    if ( zenlogau_rate_limit_is_locked( 'login' ) ) {
        $msg = __( 'Too many attempts. Please wait a few minutes and try again.', 'zen-login-authentication' );
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ $msg ] ] );
        }
        wp_safe_redirect( add_query_arg( [ 'zenlogau_2fa' => $token, 'zenlogau_2fa_error' => '1' ], zenlogau_get_action_url( 'login' ) ) );
        exit;
    }

    $code = (string) zenlogau_get_request_value( 'zenlogau_2fa_code', 'post' );

    if ( ! zenlogau_2fa_verify_input( $uid, $code ) ) {
        zenlogau_rate_limit_bump( 'login' );
        $user_obj = get_userdata( $uid );
        do_action( 'zenlogau_login_failed', $user_obj ? $user_obj->user_login : '' );
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ __( 'That code was not correct. Please try again.', 'zen-login-authentication' ) ] ] );
        }
        wp_safe_redirect( add_query_arg( [ 'zenlogau_2fa' => $token, 'zenlogau_2fa_error' => '1' ], zenlogau_get_action_url( 'login' ) ) );
        exit;
    }

    // Success — complete the login now (the cookie was never set before this).
    zenlogau_rate_limit_clear( 'login' );
    zenlogau_2fa_clear_pending_login( $token );

    $user = get_user_by( 'id', $uid );
    if ( ! $user instanceof WP_User ) {
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }

    wp_set_auth_cookie( $uid, (bool) $pending['remember'] );
    wp_set_current_user( $uid );
    // Fire the standard hook so integrations and the activity log see the login.
    do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing WordPress core's own wp_login hook.
    do_action( 'zenlogau_login_success', $user );

    $redirect = zenlogau_resolve_login_redirect( $user, (string) $pending['redirect'] );
    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [ 'redirect' => $redirect ] );
    }
    wp_safe_redirect( $redirect );
    exit;
}

/* -----------------------------------------------------------------------
 * Enrollment handlers (account page) — all PRG back to the form's page
 * -------------------------------------------------------------------- */

function zenlogau_2fa_account_redirect( array $args = [] ): void {
    $base = zenlogau_validate_redirect( (string) wp_get_referer() );
    if ( '' === $base ) {
        $base = zenlogau_get_action_url( 'account' );
    }
    $base = remove_query_arg( [ 'zenlogau_2fa_activated', 'zenlogau_2fa_disabled', 'zenlogau_2fa_setup_error', 'zenlogau_2fa_disable_error', 'zenlogau_2fa_codes' ], $base );
    wp_safe_redirect( $args ? add_query_arg( $args, $base ) : $base );
    exit;
}

function zenlogau_2fa_handle_setup(): void {
    $uid = get_current_user_id();
    if ( ! zenlogau_2fa_user_enabled( $uid ) ) {
        zenlogau_2fa_store_secret( $uid, zenlogau_totp_generate_secret(), true );
    }
    zenlogau_2fa_account_redirect();
}

function zenlogau_2fa_handle_cancel(): void {
    delete_user_meta( get_current_user_id(), 'zenlogau_2fa_pending_secret' );
    zenlogau_2fa_account_redirect();
}

function zenlogau_2fa_handle_activate(): void {
    $uid     = get_current_user_id();
    $pending = zenlogau_2fa_get_pending_secret( $uid );
    if ( '' === $pending ) {
        zenlogau_2fa_account_redirect();
    }
    $code = (string) zenlogau_get_request_value( 'zenlogau_2fa_code', 'post' );
    if ( ! zenlogau_totp_verify( $pending, $code ) ) {
        zenlogau_2fa_account_redirect( [ 'zenlogau_2fa_setup_error' => '1' ] );
    }
    // Promote the pending secret to active and turn 2FA on.
    zenlogau_2fa_store_secret( $uid, $pending, false );
    delete_user_meta( $uid, 'zenlogau_2fa_pending_secret' );
    update_user_meta( $uid, 'zenlogau_2fa_enabled', '1' );
    $codes = zenlogau_2fa_generate_recovery_codes( $uid );
    set_transient( 'zenlogau_2fa_codes_' . $uid, $codes, 5 * MINUTE_IN_SECONDS );
    do_action( 'zenlogau_2fa_enabled', $uid );
    zenlogau_2fa_account_redirect( [ 'zenlogau_2fa_activated' => '1' ] );
}

function zenlogau_2fa_handle_disable(): void {
    $uid = get_current_user_id();
    // Require a current authenticator (or recovery) code before turning 2FA off,
    // so a valid nonce alone — e.g. on a briefly unlocked browser — cannot
    // disable the account's second factor.
    $code = (string) zenlogau_get_request_value( 'zenlogau_2fa_code', 'post' );
    if ( '' === $code || ! zenlogau_2fa_verify_input( $uid, $code ) ) {
        zenlogau_2fa_account_redirect( [ 'zenlogau_2fa_disable_error' => '1' ] );
    }
    zenlogau_2fa_disable_user( $uid );
    zenlogau_2fa_account_redirect( [ 'zenlogau_2fa_disabled' => '1' ] );
}

function zenlogau_2fa_handle_regen(): void {
    $uid = get_current_user_id();
    if ( zenlogau_2fa_user_enabled( $uid ) ) {
        $codes = zenlogau_2fa_generate_recovery_codes( $uid );
        set_transient( 'zenlogau_2fa_codes_' . $uid, $codes, 5 * MINUTE_IN_SECONDS );
    }
    zenlogau_2fa_account_redirect( [ 'zenlogau_2fa_codes' => '1' ] );
}

/**
 * Non-AJAX nonce failure: a clear 403 page (matches the main router's style).
 */
function zenlogau_2fa_fail_or_die( string $message ): void {
    if ( zenlogau_is_ajax_request() ) {
        zenlogau_send_ajax_error( [ 'errors' => [ $message ] ] );
    }
    wp_die( esc_html( $message ), esc_html__( 'Security Error', 'zen-login-authentication' ), [ 'response' => 403 ] );
}

/* -----------------------------------------------------------------------
 * Account-page management panel (rendered after the Account form)
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_after_form_account', 'zenlogau_2fa_render_account_panel' );

function zenlogau_2fa_render_account_panel(): void {
    if ( ! zenlogau_2fa_feature_enabled() || ! is_user_logged_in() ) {
        return;
    }
    $uid = get_current_user_id();

    echo '<div class="fauth fauth-2fa">';
    echo '<h3 class="fauth-2fa-title">' . esc_html__( 'Two-Factor Authentication', 'zen-login-authentication' ) . '</h3>';

    if ( zenlogau_2fa_user_enabled( $uid ) ) {
        zenlogau_2fa_render_enabled_state( $uid );
    } elseif ( '' !== zenlogau_2fa_get_pending_secret( $uid ) ) {
        zenlogau_2fa_render_enrolling_state( $uid );
    } else {
        zenlogau_2fa_render_disabled_state();
    }

    echo '</div>';
}

function zenlogau_2fa_render_disabled_state(): void {
    echo '<p class="fauth-2fa-status fauth-2fa-off">' . esc_html__( 'Two-factor authentication is off. Add a second step at login using an authenticator app.', 'zen-login-authentication' ) . '</p>';
    echo '<form method="post" action="">';
    wp_nonce_field( 'zenlogau_2fa_setup', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="setup">';
    echo '<p class="fauth-submit"><button type="submit" class="fauth-button fauth-submit-button">' . esc_html__( 'Set up two-factor authentication', 'zen-login-authentication' ) . '</button></p>';
    echo '</form>';
}

function zenlogau_2fa_render_enrolling_state( int $uid ): void {
    $secret = zenlogau_2fa_get_pending_secret( $uid );
    $user   = wp_get_current_user();
    $uri    = zenlogau_totp_provisioning_uri( $secret, $user->user_email ?: $user->user_login, zenlogau_2fa_issuer() );

    if ( '' !== (string) zenlogau_get_request_value( 'zenlogau_2fa_setup_error', 'get' ) ) {
        echo '<ul class="fauth-errors" role="alert"><li class="fauth-error">'
            . esc_html__( 'That code was not correct. Check your app and try again.', 'zen-login-authentication' )
            . '</li></ul>';
    }

    echo '<ol class="fauth-2fa-steps">';
    echo '<li>' . esc_html__( 'Open your authenticator app (Google Authenticator, Authy, 1Password, etc.).', 'zen-login-authentication' ) . '</li>';
    echo '<li>' . esc_html__( 'Scan the QR code, or enter this setup key manually:', 'zen-login-authentication' ) . '</li>';
    echo '</ol>';

    // Render the QR locally from the otpauth URI (bundled qrcode-generator).
    // The manual key below is the fallback if JS/QR rendering is unavailable.
    wp_enqueue_script( 'zenlogau-qrcode' );
    wp_enqueue_script( 'zenlogau-2fa' );
    echo '<div class="fauth-2fa-qr" data-otpauth="' . esc_attr( $uri ) . '"></div>';

    echo '<p class="fauth-2fa-key"><code>' . esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ) . '</code></p>';

    echo '<form method="post" action="">';
    wp_nonce_field( 'zenlogau_2fa_activate', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="activate">';
    echo '<p class="fauth-field-wrap">';
    echo '<label class="fauth-label" for="zenlogau-2fa-confirm">' . esc_html__( 'Enter the 6-digit code from your app to confirm', 'zen-login-authentication' ) . '</label>';
    echo '<input type="text" id="zenlogau-2fa-confirm" name="zenlogau_2fa_code" class="fauth-field" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" required>';
    echo '</p>';
    echo '<p class="fauth-submit"><button type="submit" class="fauth-button fauth-submit-button">' . esc_html__( 'Verify and turn on', 'zen-login-authentication' ) . '</button></p>';
    echo '</form>';

    echo '<form method="post" action="" class="fauth-2fa-cancel">';
    wp_nonce_field( 'zenlogau_2fa_cancel', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="cancel">';
    echo '<button type="submit" class="fauth-link-button">' . esc_html__( 'Cancel', 'zen-login-authentication' ) . '</button>';
    echo '</form>';
}

function zenlogau_2fa_render_enabled_state( int $uid ): void {
    echo '<p class="fauth-2fa-status fauth-2fa-on">' . esc_html__( 'Two-factor authentication is ON for your account.', 'zen-login-authentication' ) . '</p>';

    if ( '' !== (string) zenlogau_get_request_value( 'zenlogau_2fa_disable_error', 'get' ) ) {
        echo '<ul class="fauth-errors" role="alert"><li class="fauth-error">'
            . esc_html__( 'That code was not correct, so two-factor authentication is still on. Please try again.', 'zen-login-authentication' )
            . '</li></ul>';
    }

    // Show freshly generated recovery codes once (after activation or regen).
    $codes = get_transient( 'zenlogau_2fa_codes_' . $uid );
    if ( is_array( $codes ) && $codes ) {
        delete_transient( 'zenlogau_2fa_codes_' . $uid );
        wp_enqueue_script( 'zenlogau-2fa' );
        $site = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
        echo '<div class="fauth-2fa-codes">';
        echo '<p><strong>' . esc_html__( 'Save your recovery codes', 'zen-login-authentication' ) . '</strong> — ' . esc_html__( 'each can be used once if you lose access to your app. They are shown only now, so copy or download them.', 'zen-login-authentication' ) . '</p>';
        echo '<ul class="fauth-2fa-code-list">';
        foreach ( $codes as $code ) {
            echo '<li><code>' . esc_html( (string) $code ) . '</code></li>';
        }
        echo '</ul>';
        echo '</div>'; // close .fauth-2fa-codes — the action buttons live OUTSIDE the codes box
        echo '<div class="fauth-2fa-code-actions">';
        echo '<button type="button" class="fauth-2fa-code-btn fauth-2fa-copy" data-done="' . esc_attr__( 'Copied!', 'zen-login-authentication' ) . '">' . esc_html__( 'Copy codes', 'zen-login-authentication' ) . '</button>';
        echo '<button type="button" class="fauth-2fa-code-btn fauth-2fa-download" data-filename="' . esc_attr( 'recovery-codes-' . sanitize_title( $site ) . '.txt' ) . '" data-heading="' . esc_attr( sprintf( /* translators: %s: site name */ __( 'Two-factor recovery codes for %s', 'zen-login-authentication' ), $site ) ) . '">' . esc_html__( 'Download', 'zen-login-authentication' ) . '</button>';
        echo '</div>';
    } else {
        $remaining = zenlogau_2fa_recovery_count( $uid );
        echo '<p class="fauth-2fa-recovery-count">' . esc_html(
            sprintf(
                /* translators: %d: number of unused recovery codes remaining. */
                _n( '%d recovery code remaining.', '%d recovery codes remaining.', $remaining, 'zen-login-authentication' ),
                $remaining
            )
        ) . '</p>';
    }

    echo '<div class="fauth-2fa-actions">';

    echo '<form method="post" action="">';
    wp_nonce_field( 'zenlogau_2fa_regen', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="regen">';
    echo '<p class="fauth-submit"><button type="submit" class="fauth-button fauth-submit-button fauth-button-secondary">' . esc_html__( 'Regenerate recovery codes', 'zen-login-authentication' ) . '</button></p>';
    echo '</form>';

    echo '<form method="post" action="" class="fauth-2fa-disable-form">';
    wp_nonce_field( 'zenlogau_2fa_disable', 'zenlogau_2fa_nonce', false );
    echo '<input type="hidden" name="zenlogau_2fa_action" value="disable">';
    echo '<p class="fauth-field-wrap">';
    echo '<label class="fauth-label" for="zenlogau-2fa-disable-code">' . esc_html__( 'Enter a current code to turn off two-factor authentication', 'zen-login-authentication' ) . '</label>';
    echo '<input type="text" id="zenlogau-2fa-disable-code" name="zenlogau_2fa_code" class="fauth-field" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9A-Za-z\-]*" required>';
    echo '<span class="fauth-description">' . esc_html__( 'Use your authenticator code, or a recovery code if you have lost your device.', 'zen-login-authentication' ) . '</span>';
    echo '</p>';
    echo '<p class="fauth-submit"><button type="submit" class="fauth-link-button fauth-2fa-disable">' . esc_html__( 'Turn off two-factor authentication', 'zen-login-authentication' ) . '</button></p>';
    echo '</form>';

    echo '</div>';
}

/**
 * Issuer label shown in the authenticator app (the site name by default).
 */
function zenlogau_2fa_issuer(): string {
    return (string) apply_filters( 'zenlogau_2fa_issuer', wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ) );
}

/* -----------------------------------------------------------------------
 * Clean up 2FA data when a user is deleted
 * -------------------------------------------------------------------- */
add_action( 'deleted_user', 'zenlogau_2fa_disable_user' );

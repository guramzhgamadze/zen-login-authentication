<?php
/**
 * Frontend Auth – Sign in with Google
 *
 * Server-side OpenID Connect authorization-code flow. No Google JavaScript is
 * loaded on any page and no third-party PHP libraries are used: the button is
 * a plain link to a start endpoint, which redirects to Google's consent screen;
 * Google redirects back to a callback endpoint, which exchanges the one-time
 * code for an ID token over TLS via wp_remote_post().
 *
 * Both endpoints live on admin-post.php — deliberately NOT on rewrite rules,
 * so the flow can never break from unflushed permalinks, and the button URL
 * contains no nonce or per-request state, so cached pages can never serve a
 * stale (broken) sign-in link. The CSRF state token is generated at click
 * time, stored server-side in a transient, AND bound to the browser via a
 * short-lived cookie (blocks OAuth login-CSRF / state fixation).
 *
 * Because the ID token is received directly from Google's token endpoint over
 * TLS (server-to-server), per OpenID Connect Core §3.1.3.7 the TLS server
 * identity validates the token's origin and a local signature check may be
 * skipped. The claims are still validated: iss, aud (client ID), exp, and
 * email_verified.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Option accessors
 * -------------------------------------------------------------------- */

function wpfa_google_enabled(): bool {
    return (bool) apply_filters( 'wpfa_google_enabled', get_option( 'wpfa_google_enabled', false ) );
}

function wpfa_google_client_id(): string {
    if ( defined( 'WPFA_GOOGLE_CLIENT_ID' ) && '' !== constant( 'WPFA_GOOGLE_CLIENT_ID' ) ) {
        return (string) constant( 'WPFA_GOOGLE_CLIENT_ID' );
    }
    return trim( (string) get_option( 'wpfa_google_client_id', '' ) );
}

/**
 * The OAuth client secret. Resolution order:
 *  1. the WPFA_GOOGLE_CLIENT_SECRET constant (wp-config.php — never in the DB),
 *  2. the stored option, encrypted at rest (see includes/crypto.php).
 *
 * A plaintext value saved before the 1.5.0 storage hardening is re-encrypted
 * in place on first read. Note: rotating the wp-config.php salts invalidates
 * the ciphertext — the feature then reads as unconfigured until the secret is
 * re-entered.
 */
function wpfa_google_client_secret(): string {
    if ( defined( 'WPFA_GOOGLE_CLIENT_SECRET' ) && '' !== constant( 'WPFA_GOOGLE_CLIENT_SECRET' ) ) {
        return (string) constant( 'WPFA_GOOGLE_CLIENT_SECRET' );
    }
    $stored = trim( (string) get_option( 'wpfa_google_client_secret', '' ) );
    if ( '' === $stored ) {
        return '';
    }
    if ( wpfa_crypto_is_encrypted( $stored ) ) {
        return wpfa_crypto_decrypt( $stored );
    }
    // Legacy plaintext — one-time in-place migration to the encrypted format.
    $encrypted = wpfa_crypto_encrypt( $stored );
    if ( $encrypted !== $stored ) {
        update_option( 'wpfa_google_client_secret', $encrypted, false );
    }
    return $stored;
}

/**
 * Sanitizer for the client-secret setting. An empty submission keeps the
 * stored value (the settings field never re-displays the secret); a new value
 * is encrypted. The is-encrypted guard makes the callback idempotent — WP runs
 * sanitization twice when an option is saved for the first time
 * (update_option → add_option both sanitize).
 */
function wpfa_sanitize_google_secret( $value ): string {
    $value = trim( sanitize_text_field( (string) $value ) );
    if ( '' === $value ) {
        return (string) get_option( 'wpfa_google_client_secret', '' );
    }
    if ( wpfa_crypto_is_encrypted( $value ) ) {
        return $value;
    }
    return wpfa_crypto_encrypt( $value );
}

/**
 * Whether a first-time Google sign-in may create a new account.
 * Independent of users_can_register — Google sign-ups are vetted by Google
 * (verified email), so sites can allow them while keeping open registration off.
 */
function wpfa_google_allow_registration(): bool {
    return (bool) apply_filters( 'wpfa_google_allow_registration', get_option( 'wpfa_google_allow_registration', true ) );
}

function wpfa_google_is_configured(): bool {
    return wpfa_google_enabled() && '' !== wpfa_google_client_id() && '' !== wpfa_google_client_secret();
}

/**
 * The exact redirect URI registered in Google Cloud Console.
 * Must match byte-for-byte at the authorize AND token-exchange steps.
 */
function wpfa_google_callback_url(): string {
    return admin_url( 'admin-post.php?action=wpfa_google_auth' );
}

/* -----------------------------------------------------------------------
 * Flow start — generates state at CLICK time (cache-safe), then sends the
 * user to Google's consent screen.
 * -------------------------------------------------------------------- */

add_action( 'admin_post_nopriv_wpfa_google_start', 'wpfa_google_start' );
add_action( 'admin_post_wpfa_google_start',        'wpfa_google_start' );

function wpfa_google_start(): void {
    if ( ! wpfa_google_is_configured() ) {
        wp_safe_redirect( wpfa_get_action_url( 'login' ) );
        exit;
    }
    if ( wpfa_rate_limit_is_locked( 'login' ) ) {
        wpfa_google_bounce( 'locked' );
    }

    $redirect_to = wpfa_get_request_value( 'redirect_to', 'get' );
    $redirect_to = $redirect_to ? wpfa_validate_redirect( $redirect_to ) : '';

    $state = wp_generate_password( 32, false, false );
    set_transient( 'wpfa_gstate_' . $state, [ 'redirect_to' => $redirect_to ], 10 * MINUTE_IN_SECONDS );

    // Bind the state to this browser. SameSite=Lax still sends the cookie on
    // the top-level GET redirect back from Google.
    setcookie( 'wpfa_g_state', $state, [
        'expires'  => time() + 10 * MINUTE_IN_SECONDS,
        'path'     => '/',
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ] );

    $auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query( [
        'client_id'     => wpfa_google_client_id(),
        'redirect_uri'  => wpfa_google_callback_url(),
        'response_type' => 'code',
        'scope'         => 'openid email profile',
        'state'         => $state,
        'prompt'        => 'select_account',
    ] );

    // Intentional external redirect to Google's OAuth endpoint.
    wp_redirect( $auth_url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
    exit;
}

/* -----------------------------------------------------------------------
 * Callback — validates state, exchanges the code, signs the user in.
 * -------------------------------------------------------------------- */

add_action( 'admin_post_nopriv_wpfa_google_auth', 'wpfa_google_auth' );
add_action( 'admin_post_wpfa_google_auth',        'wpfa_google_auth' );

function wpfa_google_auth(): void {
    if ( ! wpfa_google_is_configured() ) {
        wp_safe_redirect( wpfa_get_action_url( 'login' ) );
        exit;
    }
    if ( wpfa_rate_limit_is_locked( 'login' ) ) {
        wpfa_google_bounce( 'locked' );
    }

    // User clicked "Cancel" on Google's consent screen.
    if ( '' !== wpfa_get_request_value( 'error', 'get' ) ) {
        wpfa_google_bounce( 'denied' );
    }

    $state = sanitize_text_field( wpfa_get_request_value( 'state', 'get' ) );
    $code  = wpfa_get_request_value( 'code', 'get' );

    $cookie = isset( $_COOKIE['wpfa_g_state'] ) && is_string( $_COOKIE['wpfa_g_state'] )
        ? sanitize_text_field( wp_unslash( $_COOKIE['wpfa_g_state'] ) )
        : '';
    // Always clear the binding cookie — it is single-use.
    setcookie( 'wpfa_g_state', '', [
        'expires'  => time() - HOUR_IN_SECONDS,
        'path'     => '/',
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ] );

    if ( '' === $state || '' === $code || '' === $cookie || ! hash_equals( $cookie, $state ) ) {
        wpfa_rate_limit_bump( 'login' );
        wpfa_google_bounce( 'state' );
    }

    $stored = get_transient( 'wpfa_gstate_' . $state );
    delete_transient( 'wpfa_gstate_' . $state ); // single-use
    if ( ! is_array( $stored ) ) {
        wpfa_rate_limit_bump( 'login' );
        wpfa_google_bounce( 'state' );
    }

    $claims = wpfa_google_exchange_code( $code );
    if ( is_wp_error( $claims ) ) {
        wpfa_rate_limit_bump( 'login' );
        wpfa_google_bounce( 'wpfa_google_email' === $claims->get_error_code() ? 'email' : 'failed' );
    }

    $user = wpfa_google_find_or_create_user( $claims );
    if ( is_wp_error( $user ) ) {
        wpfa_google_bounce( 'registration_closed' === $user->get_error_code() ? 'registration' : 'failed' );
    }

    wpfa_rate_limit_clear( 'login' );

    $remember = (bool) apply_filters( 'wpfa_google_remember', true, $user );
    wp_set_auth_cookie( $user->ID, $remember );

    /** This action is documented in wp-includes/user.php */
    do_action( 'wp_login', $user->user_login, $user );
    do_action( 'wpfa_login_success', $user );
    do_action( 'wpfa_google_login_success', $user );

    $requested   = (string) ( $stored['redirect_to'] ?? '' );
    // Runs through 'login_redirect', so the subscriber containment from
    // wpfa_subscriber_login_redirect() applies exactly like password logins.
    $redirect_to = (string) apply_filters( 'login_redirect', '' !== $requested ? $requested : home_url(), $requested, $user );

    wp_safe_redirect( '' !== $redirect_to ? $redirect_to : home_url() );
    exit;
}

/**
 * Redirect back to the login page with a short error code the form renders.
 *
 * @return never
 */
function wpfa_google_bounce( string $code ): void {
    wp_safe_redirect( add_query_arg( 'wpfa_google_error', rawurlencode( $code ), wpfa_get_action_url( 'login' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Token exchange + claim validation
 * -------------------------------------------------------------------- */

/**
 * Exchange the one-time authorization code for an ID token and return its
 * validated claims, or a WP_Error.
 *
 * @return array|WP_Error
 */
function wpfa_google_exchange_code( string $code ) {
    $response = wp_remote_post( 'https://oauth2.googleapis.com/token', [
        'timeout' => 15,
        'body'    => [
            'code'          => $code,
            'client_id'     => wpfa_google_client_id(),
            'client_secret' => wpfa_google_client_secret(),
            'redirect_uri'  => wpfa_google_callback_url(),
            'grant_type'    => 'authorization_code',
        ],
    ] );

    if ( is_wp_error( $response ) ) {
        return new WP_Error( 'wpfa_google_http', 'Token endpoint unreachable.' );
    }

    $body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
    if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) || ! is_array( $body ) ) {
        return new WP_Error( 'wpfa_google_exchange', 'Code exchange failed.' );
    }

    $id_token = isset( $body['id_token'] ) && is_string( $body['id_token'] ) ? $body['id_token'] : '';
    $parts    = explode( '.', $id_token );
    if ( 3 !== count( $parts ) ) {
        return new WP_Error( 'wpfa_google_token', 'Malformed ID token.' );
    }

    // Standard JWT payload decoding (base64url). Signature verification is not
    // required here: the token arrived directly from Google's token endpoint
    // over TLS (OIDC Core §3.1.3.7) — claims are validated below instead.
    $claims = json_decode( (string) base64_decode( strtr( $parts[1], '-_', '+/' ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    if ( ! is_array( $claims ) ) {
        return new WP_Error( 'wpfa_google_token', 'Unreadable ID token.' );
    }

    $iss = (string) ( $claims['iss'] ?? '' );
    if ( ! in_array( $iss, [ 'https://accounts.google.com', 'accounts.google.com' ], true ) ) {
        return new WP_Error( 'wpfa_google_iss', 'Unexpected token issuer.' );
    }
    if ( ! hash_equals( wpfa_google_client_id(), (string) ( $claims['aud'] ?? '' ) ) ) {
        return new WP_Error( 'wpfa_google_aud', 'Token issued for a different client.' );
    }
    if ( (int) ( $claims['exp'] ?? 0 ) < time() ) {
        return new WP_Error( 'wpfa_google_exp', 'Token expired.' );
    }
    if ( '' === (string) ( $claims['sub'] ?? '' ) ) {
        return new WP_Error( 'wpfa_google_sub', 'Missing subject.' );
    }

    $email    = sanitize_email( (string) ( $claims['email'] ?? '' ) );
    $verified = $claims['email_verified'] ?? false; // Google sends bool true or string "true".
    if ( '' === $email || ! ( true === $verified || 'true' === $verified ) ) {
        return new WP_Error( 'wpfa_google_email', 'Email missing or unverified.' );
    }
    $claims['email'] = $email;

    return $claims;
}

/* -----------------------------------------------------------------------
 * User provisioning
 * -------------------------------------------------------------------- */

/**
 * Resolve the WP user for a set of validated Google claims:
 *  1. by stored Google account ID (wpfa_google_sub user meta),
 *  2. by verified email — links the existing account,
 *  3. otherwise create a new account (if allowed).
 *
 * @return WP_User|WP_Error
 */
function wpfa_google_find_or_create_user( array $claims ) {
    $sub   = (string) $claims['sub'];
    $email = (string) $claims['email'];

    $existing = get_users( [
        'meta_key'   => 'wpfa_google_sub', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
        'meta_value' => $sub,              // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
        'number'     => 1,
    ] );
    if ( ! empty( $existing ) && $existing[0] instanceof WP_User ) {
        return $existing[0];
    }

    $user = get_user_by( 'email', $email );
    if ( $user instanceof WP_User ) {
        update_user_meta( $user->ID, 'wpfa_google_sub', $sub );
        return $user;
    }

    if ( ! wpfa_google_allow_registration() ) {
        return new WP_Error( 'registration_closed', 'No matching account and Google registration is disabled.' );
    }

    // Username from the email local part, made unique.
    $local = strstr( $email, '@', true );
    $base  = sanitize_user( is_string( $local ) ? $local : 'user', true );
    if ( '' === $base ) {
        $base = 'user';
    }
    $login = $base;
    $i     = 1;
    while ( username_exists( $login ) ) {
        $login = $base . $i;
        $i++;
    }

    $display = sanitize_text_field( (string) ( $claims['name'] ?? '' ) );

    $user_id = wp_insert_user( [
        'user_login'   => $login,
        'user_email'   => $email,
        'user_pass'    => wp_generate_password( 24 ),
        'display_name' => '' !== $display ? $display : $login,
        'first_name'   => sanitize_text_field( (string) ( $claims['given_name'] ?? '' ) ),
        'last_name'    => sanitize_text_field( (string) ( $claims['family_name'] ?? '' ) ),
        'role'         => get_option( 'default_role', 'subscriber' ),
    ] );
    if ( $user_id instanceof WP_Error ) {
        return $user_id;
    }

    update_user_meta( $user_id, 'wpfa_google_sub', $sub );

    // Same front-end toolbar default as form registrations (see wpfa_handle_register).
    if ( apply_filters( 'wpfa_hide_admin_bar_on_register', true, $user_id ) ) {
        update_user_meta( $user_id, 'show_admin_bar_front', 'false' );
    }

    // Notify the admin only — the user already has access and no password email
    // makes sense for a Google account. Filter to 'both', 'user', or 'none'.
    $notify = (string) apply_filters( 'wpfa_google_new_user_notification', 'admin', $user_id );
    if ( 'none' !== $notify ) {
        wp_new_user_notification( $user_id, null, $notify );
    }

    do_action( 'wpfa_registration_success', $user_id );
    do_action( 'wpfa_google_user_created', $user_id, $claims );

    $user = get_user_by( 'id', $user_id );
    return $user instanceof WP_User ? $user : new WP_Error( 'wpfa_google_user', 'User creation failed.' );
}

/* -----------------------------------------------------------------------
 * Button rendering — hooked below the login and registration forms.
 * -------------------------------------------------------------------- */

/** Official multicolour Google "G" mark (18×18). */
function wpfa_google_button_svg(): string {
    return '<svg class="wpfa-google-icon" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" focusable="false">'
        . '<path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92a8.78 8.78 0 0 0 2.68-6.62z"/>'
        . '<path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.33A9 9 0 0 0 9 18z"/>'
        . '<path fill="#FBBC05" d="M3.97 10.71A5.41 5.41 0 0 1 3.68 9c0-.59.1-1.17.28-1.71V4.96H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.04l3.01-2.33z"/>'
        . '<path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.59A9 9 0 0 0 .96 4.96l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/>'
        . '</svg>';
}

/**
 * Divider + "Continue with Google" button HTML, or '' when not configured.
 * The link is static (state is generated at click time on the start endpoint),
 * so it is safe to cache.
 */
function wpfa_google_button_html(): string {
    if ( ! wpfa_google_is_configured() ) {
        return '';
    }

    $url = add_query_arg( 'action', 'wpfa_google_start', admin_url( 'admin-post.php' ) );

    $redirect_to = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification
        ? wpfa_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
        : '';
    $redirect_to = (string) apply_filters( 'wpfa_google_redirect_to', $redirect_to );
    if ( '' !== $redirect_to ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
    }

    $text = (string) apply_filters( 'wpfa_google_button_text', __( 'Continue with Google', 'frontend-auth' ) );

    return '<div class="wpfa-sso">'
        . '<div class="wpfa-sso-divider" aria-hidden="true"><span>' . esc_html__( 'or', 'frontend-auth' ) . '</span></div>'
        . '<a class="wpfa-google-btn" href="' . esc_url( $url ) . '">' . wpfa_google_button_svg()
        . '<span>' . esc_html( $text ) . '</span></a>'
        . '</div>';
}

add_action( 'wpfa_after_form_login',    'wpfa_google_render_button' );
add_action( 'wpfa_after_form_register', 'wpfa_google_render_button' );

function wpfa_google_render_button( $form ): void {
    $name = $form instanceof WPFA_Form ? $form->get_name() : '';
    if ( ! apply_filters( 'wpfa_show_google_button', true, $name ) ) {
        return;
    }
    echo wpfa_google_button_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped during construction
}

/* -----------------------------------------------------------------------
 * Error feedback on the login form (after a bounced callback)
 * -------------------------------------------------------------------- */

add_action( 'wpfa_before_form_login', 'wpfa_google_maybe_show_error' );

function wpfa_google_maybe_show_error( $form ): void {
    if ( ! $form instanceof WPFA_Form ) {
        return;
    }
    $code = isset( $_GET['wpfa_google_error'] ) && is_string( $_GET['wpfa_google_error'] ) // phpcs:ignore WordPress.Security.NonceVerification
        ? sanitize_key( wp_unslash( $_GET['wpfa_google_error'] ) ) // phpcs:ignore WordPress.Security.NonceVerification
        : '';
    if ( '' === $code ) {
        return;
    }
    $messages = [
        'denied'       => __( 'Google sign-in was cancelled.', 'frontend-auth' ),
        'state'        => __( 'The sign-in attempt expired. Please try again.', 'frontend-auth' ),
        'email'        => __( 'Your Google account email address is not verified, so it cannot be used to sign in.', 'frontend-auth' ),
        'registration' => __( 'No account matches this Google email address, and new registrations via Google are disabled.', 'frontend-auth' ),
        'locked'       => __( 'Too many attempts. Please try again later.', 'frontend-auth' ),
        'failed'       => __( 'Google sign-in failed. Please try again.', 'frontend-auth' ),
    ];
    $form->add_error( 'google_' . $code, $messages[ $code ] ?? $messages['failed'] );
}

<?php
/**
 * Zen Login & Authentication – Cloudflare Turnstile
 *
 * Privacy-first bot / credential-stuffing challenge on the login, registration,
 * and lost-password forms. The widget is injected through WordPress's own
 * login_form / register_form / lostpassword_form hooks, so it appears in the
 * plugin's forms AND on wp-login.php. Verification runs through the standard
 * auth filters (authenticate / registration_errors / lostpassword_post), which
 * the plugin's handlers already route through — so AJAX submissions are covered
 * too, and the token oracle is closed (an invalid token never reaches the
 * credential check).
 *
 * The site key is public; the secret key is stored encrypted at rest (reusing
 * includes/crypto.php) or can be set via the ZENLOGAU_TURNSTILE_SECRET_KEY
 * constant. Token verification fails OPEN on a transport error (so a Cloudflare
 * outage can't lock everyone out) but fails CLOSED on a missing/invalid token
 * (the actual enforcement).
 *
 * Service: Cloudflare Turnstile (https://www.cloudflare.com/products/turnstile/).
 * Loads challenges.cloudflare.com/turnstile/v0/api.js on pages with a protected
 * form and sends the response token to .../siteverify on submission.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_TURNSTILE_API_JS  = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
const ZENLOGAU_TURNSTILE_VERIFY  = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/* -----------------------------------------------------------------------
 * Configuration accessors
 * -------------------------------------------------------------------- */

function zenlogau_turnstile_enabled(): bool {
    return (bool) apply_filters( 'zenlogau_turnstile_enabled', get_option( 'zenlogau_turnstile_enabled', false ) );
}

function zenlogau_turnstile_site_key(): string {
    if ( defined( 'ZENLOGAU_TURNSTILE_SITE_KEY' ) && '' !== constant( 'ZENLOGAU_TURNSTILE_SITE_KEY' ) ) {
        return (string) constant( 'ZENLOGAU_TURNSTILE_SITE_KEY' );
    }
    return trim( (string) get_option( 'zenlogau_turnstile_site_key', '' ) );
}

/**
 * The secret key. Resolution order mirrors the Google client secret:
 *  1. the ZENLOGAU_TURNSTILE_SECRET_KEY constant (never in the DB),
 *  2. the stored option, encrypted at rest (see includes/crypto.php).
 */
function zenlogau_turnstile_secret_key(): string {
    if ( defined( 'ZENLOGAU_TURNSTILE_SECRET_KEY' ) && '' !== constant( 'ZENLOGAU_TURNSTILE_SECRET_KEY' ) ) {
        return (string) constant( 'ZENLOGAU_TURNSTILE_SECRET_KEY' );
    }
    $stored = trim( (string) get_option( 'zenlogau_turnstile_secret_key', '' ) );
    if ( '' === $stored ) {
        return '';
    }
    if ( zenlogau_crypto_is_encrypted( $stored ) ) {
        return zenlogau_crypto_decrypt( $stored );
    }
    // Legacy plaintext (e.g. saved before encryption) — re-encrypt in place.
    $encrypted = zenlogau_crypto_encrypt( $stored );
    if ( $encrypted !== $stored ) {
        update_option( 'zenlogau_turnstile_secret_key', $encrypted, false );
    }
    return $stored;
}

/**
 * Sanitizer for the secret-key setting: empty submission keeps the stored value
 * (the field never re-displays it); a new value is encrypted. Idempotent.
 */
function zenlogau_sanitize_turnstile_secret( $value ): string {
    $value = is_scalar( $value ) ? trim( (string) $value ) : '';
    if ( '' === $value ) {
        return (string) get_option( 'zenlogau_turnstile_secret_key', '' );
    }
    if ( zenlogau_crypto_is_encrypted( $value ) ) {
        return $value;
    }
    return zenlogau_crypto_encrypt( $value );
}

/**
 * Turnstile is usable only when enabled AND both keys are present.
 */
function zenlogau_turnstile_active(): bool {
    return zenlogau_turnstile_enabled()
        && '' !== zenlogau_turnstile_site_key()
        && '' !== zenlogau_turnstile_secret_key();
}

/**
 * Whether a given form (login|register|lostpassword) is protected. Default ON
 * for all three once Turnstile is active.
 */
function zenlogau_turnstile_protects( string $form ): bool {
    $map = [
        'login'        => 'zenlogau_turnstile_login',
        'register'     => 'zenlogau_turnstile_register',
        'lostpassword' => 'zenlogau_turnstile_lostpassword',
    ];
    if ( ! isset( $map[ $form ] ) ) {
        return false;
    }
    return (bool) apply_filters( 'zenlogau_turnstile_protects', (bool) get_option( $map[ $form ], true ), $form );
}

function zenlogau_turnstile_error_message(): string {
    return (string) apply_filters(
        'zenlogau_turnstile_error',
        __( 'Please complete the verification challenge and try again.', 'zen-login-authentication' )
    );
}

/* -----------------------------------------------------------------------
 * Script registration + widget rendering
 * -------------------------------------------------------------------- */
add_action( 'init', 'zenlogau_turnstile_register_script' );

function zenlogau_turnstile_register_script(): void {
    // null version → no ?ver appended to Cloudflare's URL. Deferred so it runs
    // after the form markup is parsed and auto-renders every .cf-turnstile div.
    // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- external Cloudflare endpoint; a local ?ver is meaningless and Cloudflare versions the API itself.
    wp_register_script( 'zenlogau-turnstile', ZENLOGAU_TURNSTILE_API_JS, [], null, [ 'strategy' => 'defer', 'in_footer' => false ] );
}

// Ensure the script is present on wp-login.php (head).
add_action( 'login_enqueue_scripts', 'zenlogau_turnstile_login_enqueue' );

function zenlogau_turnstile_login_enqueue(): void {
    if ( zenlogau_turnstile_active() ) {
        wp_enqueue_script( 'zenlogau-turnstile' );
    }
}

// Inject the widget into the login / register / lost-password forms. These
// actions fire inside the plugin's forms (via the "action" field) and on
// wp-login.php, so one set of hooks covers both.
add_action( 'login_form',        'zenlogau_turnstile_render_login' );
add_action( 'register_form',     'zenlogau_turnstile_render_register' );
add_action( 'lostpassword_form', 'zenlogau_turnstile_render_lostpassword' );

function zenlogau_turnstile_render_login(): void        { zenlogau_turnstile_render_widget( 'login' ); }
function zenlogau_turnstile_render_register(): void     { zenlogau_turnstile_render_widget( 'register' ); }
function zenlogau_turnstile_render_lostpassword(): void { zenlogau_turnstile_render_widget( 'lostpassword' ); }

function zenlogau_turnstile_render_widget( string $form ): void {
    if ( ! zenlogau_turnstile_active() || ! zenlogau_turnstile_protects( $form ) ) {
        return;
    }
    wp_enqueue_script( 'zenlogau-turnstile' );
    $theme = (string) apply_filters( 'zenlogau_turnstile_theme', 'auto', $form );
    printf(
        '<div class="fauth-turnstile cf-turnstile" data-sitekey="%s" data-theme="%s"></div>',
        esc_attr( zenlogau_turnstile_site_key() ),
        esc_attr( $theme )
    );
}

/* -----------------------------------------------------------------------
 * Token verification
 * -------------------------------------------------------------------- */

/**
 * Verify the submitted Turnstile token with Cloudflare.
 *
 * Returns true when the token is valid. Returns false for a missing/invalid
 * token (real enforcement). Returns true on a transport error (fail open) so a
 * Cloudflare outage cannot lock users out. A missing token short-circuits
 * before any HTTP call, so token-less bots are rejected for free.
 */
function zenlogau_turnstile_verify(): bool {
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- third-party challenge token on the same submission the handler nonce-verifies; read-only.
    $token = isset( $_POST['cf-turnstile-response'] ) ? sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    if ( '' === $token ) {
        return false;
    }

    $response = wp_remote_post( ZENLOGAU_TURNSTILE_VERIFY, [
        'timeout' => (int) apply_filters( 'zenlogau_turnstile_timeout', 5 ),
        'body'    => [
            'secret'   => zenlogau_turnstile_secret_key(),
            'response' => $token,
            'remoteip' => zenlogau_rate_limit_get_ip(),
        ],
    ] );

    if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
        return true; // fail open on transport error
    }

    $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
    return is_array( $data ) && ! empty( $data['success'] );
}

/**
 * True when the current request is an interactive submission that should be
 * challenged for the given form. Limits enforcement to real browser POSTs of
 * our / wp-login's forms — never REST, XML-RPC, app passwords, or cookie auth.
 */
function zenlogau_turnstile_should_check( string $form ): bool {
    if ( ! zenlogau_turnstile_active() || ! zenlogau_turnstile_protects( $form ) ) {
        return false;
    }
    return 'POST' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) );
}

/* -----------------------------------------------------------------------
 * Enforcement — login
 *
 * Runs at priority 99 (after core's credential check at 20, before the
 * generic-errors filter at 9999). When the token is invalid we return the
 * Turnstile error regardless of whether the credentials were right — so a
 * valid login can't slip through, and a bad token never leaks credential
 * validity. Gated to interactive login POSTs (log + pwd present), which the
 * plugin's form and wp-login both use; REST/XML-RPC never match.
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'zenlogau_turnstile_authenticate', 99, 3 );

function zenlogau_turnstile_authenticate( $user, $username, $password ) {
    unset( $username, $password );
    if ( ! zenlogau_turnstile_should_check( 'login' ) ) {
        return $user;
    }
    // phpcs:ignore WordPress.Security.NonceVerification.Missing -- detecting an interactive login submit; the handler/wp-login verify the nonce. We read no values here.
    if ( ! isset( $_POST['log'] ) || ! isset( $_POST['pwd'] ) ) {
        return $user;
    }
    if ( ! zenlogau_turnstile_verify() ) {
        return new WP_Error( 'zenlogau_turnstile_failed', zenlogau_turnstile_error_message() );
    }
    return $user;
}

/* -----------------------------------------------------------------------
 * Enforcement — registration (plugin form + wp-login register)
 * -------------------------------------------------------------------- */
add_filter( 'registration_errors', 'zenlogau_turnstile_registration_errors', 5, 1 );

function zenlogau_turnstile_registration_errors( $errors ) {
    if ( $errors instanceof WP_Error
        && zenlogau_turnstile_should_check( 'register' )
        && ! zenlogau_turnstile_verify() ) {
        $errors->add( 'zenlogau_turnstile_failed', zenlogau_turnstile_error_message() );
    }
    return $errors;
}

/* -----------------------------------------------------------------------
 * Enforcement — lost password (plugin handler + wp-login both call
 * retrieve_password(), which fires lostpassword_post with the WP_Error).
 * -------------------------------------------------------------------- */
add_action( 'lostpassword_post', 'zenlogau_turnstile_lostpassword_post', 5, 1 );

function zenlogau_turnstile_lostpassword_post( $errors ): void {
    if ( $errors instanceof WP_Error
        && zenlogau_turnstile_should_check( 'lostpassword' )
        && ! zenlogau_turnstile_verify() ) {
        $errors->add( 'zenlogau_turnstile_failed', zenlogau_turnstile_error_message() );
    }
}

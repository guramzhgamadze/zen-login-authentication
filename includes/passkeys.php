<?php
/**
 * Zen Login & Authentication – Passkeys (WebAuthn passwordless login)
 *
 * Lets a logged-in user register one or more passkeys from the Account page and
 * then sign in with no password at all (Face ID / fingerprint / Windows Hello /
 * a security key). Passkeys are inherently multi-factor (possession + the
 * device's own user verification), so a successful passkey login bypasses both
 * the password step and the TOTP second factor.
 *
 * Server-side verification is done by the bundled lbuchs/WebAuthn library (MIT,
 * includes/lib/webauthn). Only "none" attestation is accepted, so no attestation
 * certificate chains are validated and NO external request is ever made.
 *
 * Requires HTTPS (WebAuthn refuses to run otherwise, except on localhost).
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_PASSKEY_META       = 'zenlogau_passkeys';
const ZENLOGAU_PASSKEY_REG_TTL    = 300; // seconds a registration challenge is valid
const ZENLOGAU_PASSKEY_LOGIN_TTL  = 300; // seconds a login challenge is valid

/* -----------------------------------------------------------------------
 * Autoloader for the vendored lbuchs\WebAuthn library
 * -------------------------------------------------------------------- */
spl_autoload_register( static function ( string $class ): void {
    $prefix = 'lbuchs\\WebAuthn\\';
    if ( 0 !== strpos( $class, $prefix ) ) {
        return;
    }
    $relative = str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) );
    $file     = ZENLOGAU_PATH . 'includes/lib/webauthn/src/' . $relative . '.php';
    if ( is_readable( $file ) ) {
        require_once $file;
    }
} );

/* -----------------------------------------------------------------------
 * Feature switches and environment
 * -------------------------------------------------------------------- */

function zenlogau_passkeys_feature_enabled(): bool {
    return (bool) apply_filters(
        'zenlogau_passkeys_feature_enabled',
        (bool) get_option( 'zenlogau_passkeys_feature', true )
    );
}

/**
 * WebAuthn needs a secure context. Browsers make an exception for localhost.
 */
function zenlogau_passkeys_secure_context(): bool {
    if ( is_ssl() ) {
        return true;
    }
    $host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
    return 'localhost' === $host || '127.0.0.1' === $host || str_ends_with( $host, '.localhost' );
}

/**
 * Whether passkeys are usable right now (feature on + secure context + library
 * + an OpenSSL build that can verify the signatures).
 */
function zenlogau_passkeys_available(): bool {
    return zenlogau_passkeys_feature_enabled()
        && zenlogau_passkeys_secure_context()
        && function_exists( 'openssl_verify' );
}

function zenlogau_passkey_rp_id(): string {
    $host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
    return (string) apply_filters( 'zenlogau_passkey_rp_id', $host );
}

function zenlogau_passkey_rp_name(): string {
    $name = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );
    return (string) apply_filters( 'zenlogau_passkey_rp_name', $name );
}

/**
 * @return \lbuchs\WebAuthn\WebAuthn
 */
function zenlogau_passkey_webauthn() {
    // Only "none" attestation — passwordless passkeys, no cert-chain validation,
    // no network calls.
    return new \lbuchs\WebAuthn\WebAuthn(
        zenlogau_passkey_rp_name(),
        zenlogau_passkey_rp_id(),
        [ 'none' ]
    );
}

/* -----------------------------------------------------------------------
 * base64url helpers (storage key encoding)
 * -------------------------------------------------------------------- */

function zenlogau_b64url_encode( string $bin ): string {
    return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
}

function zenlogau_b64url_decode( string $b64url ): string {
    $b64 = strtr( $b64url, '-_', '+/' );
    $pad = strlen( $b64 ) % 4;
    if ( $pad ) {
        $b64 .= str_repeat( '=', 4 - $pad );
    }
    $out = base64_decode( $b64, true );
    return is_string( $out ) ? $out : '';
}

/* -----------------------------------------------------------------------
 * Per-user credential storage
 *
 * Meta "zenlogau_passkeys" => [ base64url(credentialId) => [
 *     'key'       => credential public key (PEM),
 *     'counter'   => int signature counter,
 *     'label'     => user-supplied name,
 *     'created'   => timestamp,
 *     'last_used' => timestamp,
 * ] ]
 *
 * The userHandle stored on the authenticator is the user ID, so a discoverable
 * (passwordless) login resolves straight to the user with no table scan.
 * -------------------------------------------------------------------- */

function zenlogau_get_passkeys( int $user_id ): array {
    $stored = get_user_meta( $user_id, ZENLOGAU_PASSKEY_META, true );
    return is_array( $stored ) ? $stored : [];
}

function zenlogau_save_passkeys( int $user_id, array $passkeys ): void {
    update_user_meta( $user_id, ZENLOGAU_PASSKEY_META, $passkeys );
}

function zenlogau_passkey_user_handle( int $user_id ): string {
    // Opaque to the authenticator; an integer ID is not PII and avoids a lookup.
    return (string) $user_id;
}

/* -----------------------------------------------------------------------
 * Script registration
 * -------------------------------------------------------------------- */
add_action( 'init', 'zenlogau_passkey_register_assets' );

function zenlogau_passkey_register_assets(): void {
    wp_register_script(
        'zenlogau-passkey',
        ZENLOGAU_URL . 'assets/scripts/zenlogau-passkey.js',
        [],
        ZENLOGAU_VERSION,
        [ 'in_footer' => true ]
    );
}

/**
 * Enqueue + localise the passkey script. Safe to call more than once per request.
 */
function zenlogau_passkey_enqueue(): void {
    static $done = false;
    wp_enqueue_script( 'zenlogau-passkey' );
    if ( $done ) {
        return;
    }
    $done = true;
    wp_localize_script( 'zenlogau-passkey', 'zenlogauPasskey', [
        'ajaxUrl' => admin_url( 'admin-ajax.php' ),
        'nonce'   => is_user_logged_in() ? wp_create_nonce( 'zenlogau_passkey' ) : '',
        'i18n'    => [
            'unsupported' => __( 'This browser does not support passkeys.', 'zen-login-authentication' ),
            'registering' => __( 'Follow the prompt to create your passkey…', 'zen-login-authentication' ),
            'reg_ok'      => __( 'Passkey added.', 'zen-login-authentication' ),
            'reg_fail'    => __( 'Could not add the passkey. Please try again.', 'zen-login-authentication' ),
            'signing_in'  => __( 'Follow the prompt to sign in…', 'zen-login-authentication' ),
            'login_fail'  => __( 'Passkey sign-in failed. Please try again or use your password.', 'zen-login-authentication' ),
            'cancelled'   => __( 'Cancelled.', 'zen-login-authentication' ),
            'name_prompt' => __( 'Name this passkey (e.g. "iPhone", "Work laptop"):', 'zen-login-authentication' ),
            'confirm_del' => __( 'Remove this passkey? You will no longer be able to sign in with it.', 'zen-login-authentication' ),
        ],
    ] );
}

/* -----------------------------------------------------------------------
 * AJAX: registration — step 1, options
 * -------------------------------------------------------------------- */
add_action( 'wp_ajax_zenlogau_passkey_register_options', 'zenlogau_passkey_ajax_register_options' );

function zenlogau_passkey_ajax_register_options(): void {
    check_ajax_referer( 'zenlogau_passkey', 'nonce' );
    if ( ! is_user_logged_in() || ! zenlogau_passkeys_available() ) {
        wp_send_json_error( [ 'message' => __( 'Passkeys are not available.', 'zen-login-authentication' ) ], 400 );
    }

    $user    = wp_get_current_user();
    $webauthn = zenlogau_passkey_webauthn();

    // Exclude already-registered credentials so the same authenticator is not
    // enrolled twice.
    $exclude = [];
    foreach ( zenlogau_get_passkeys( $user->ID ) as $cred_key => $unused ) {
        $exclude[] = zenlogau_b64url_decode( (string) $cred_key );
    }

    try {
        $args = $webauthn->getCreateArgs(
            zenlogau_passkey_user_handle( $user->ID ),
            $user->user_login,
            $user->display_name,
            ZENLOGAU_PASSKEY_REG_TTL,
            true,        // resident / discoverable key (passkey)
            'preferred', // user verification
            null,        // allow both platform and cross-platform authenticators
            $exclude
        );
    } catch ( \Throwable $e ) {
        wp_send_json_error( [ 'message' => __( 'Could not start passkey registration.', 'zen-login-authentication' ) ], 500 );
    }

    set_transient(
        'zenlogau_pk_reg_' . $user->ID,
        base64_encode( $webauthn->getChallenge()->getBinaryString() ),
        ZENLOGAU_PASSKEY_REG_TTL
    );

    wp_send_json_success( $args );
}

/* -----------------------------------------------------------------------
 * AJAX: registration — step 2, verify + store
 * -------------------------------------------------------------------- */
add_action( 'wp_ajax_zenlogau_passkey_register_verify', 'zenlogau_passkey_ajax_register_verify' );

function zenlogau_passkey_ajax_register_verify(): void {
    check_ajax_referer( 'zenlogau_passkey', 'nonce' );
    if ( ! is_user_logged_in() || ! zenlogau_passkeys_available() ) {
        wp_send_json_error( [ 'message' => __( 'Passkeys are not available.', 'zen-login-authentication' ) ], 400 );
    }

    $user = wp_get_current_user();

    $client_data = base64_decode( (string) zenlogau_get_request_value( 'clientDataJSON', 'post' ), true );
    $attestation = base64_decode( (string) zenlogau_get_request_value( 'attestationObject', 'post' ), true );
    $challenge_b = get_transient( 'zenlogau_pk_reg_' . $user->ID );
    delete_transient( 'zenlogau_pk_reg_' . $user->ID );

    if ( ! is_string( $client_data ) || ! is_string( $attestation ) || ! is_string( $challenge_b ) || '' === $challenge_b ) {
        wp_send_json_error( [ 'message' => __( 'Registration expired. Please try again.', 'zen-login-authentication' ) ], 400 );
    }
    $challenge = base64_decode( $challenge_b, true );

    try {
        $data = zenlogau_passkey_webauthn()->processCreate(
            $client_data,
            $attestation,
            (string) $challenge,
            false, // user verification required
            true,  // user present required
            false  // do not fail on root mismatch (none attestation has no root)
        );
    } catch ( \Throwable $e ) {
        wp_send_json_error( [ 'message' => __( 'The passkey could not be verified.', 'zen-login-authentication' ) ], 400 );
    }

    $cred_id = '';
    if ( isset( $data->credentialId ) ) {
        $cred_id = $data->credentialId instanceof \lbuchs\WebAuthn\Binary\ByteBuffer
            ? $data->credentialId->getBinaryString()
            : (string) $data->credentialId;
    }
    $public_key = isset( $data->credentialPublicKey ) ? (string) $data->credentialPublicKey : '';
    if ( '' === $cred_id || '' === $public_key ) {
        wp_send_json_error( [ 'message' => __( 'The passkey could not be verified.', 'zen-login-authentication' ) ], 400 );
    }

    $label = sanitize_text_field( (string) zenlogau_get_request_value( 'label', 'post' ) );
    if ( '' === $label ) {
        $label = __( 'Passkey', 'zen-login-authentication' );
    }
    $label = mb_substr( $label, 0, 60 );

    $passkeys = zenlogau_get_passkeys( $user->ID );
    $passkeys[ zenlogau_b64url_encode( $cred_id ) ] = [
        'key'       => $public_key,
        'counter'   => (int) ( $data->signatureCounter ?? 0 ),
        'label'     => $label,
        'created'   => time(),
        'last_used' => 0,
    ];
    zenlogau_save_passkeys( $user->ID, $passkeys );

    do_action( 'zenlogau_passkey_registered', $user->ID );

    wp_send_json_success( [
        'message' => __( 'Passkey added.', 'zen-login-authentication' ),
        'list'    => zenlogau_passkey_list_html( $user->ID ),
    ] );
}

/* -----------------------------------------------------------------------
 * AJAX: login — step 1, options (no user known yet → discoverable)
 * -------------------------------------------------------------------- */
add_action( 'wp_ajax_nopriv_zenlogau_passkey_login_options', 'zenlogau_passkey_ajax_login_options' );
add_action( 'wp_ajax_zenlogau_passkey_login_options', 'zenlogau_passkey_ajax_login_options' );

function zenlogau_passkey_ajax_login_options(): void {
    if ( ! zenlogau_passkeys_available() ) {
        wp_send_json_error( [ 'message' => __( 'Passkeys are not available.', 'zen-login-authentication' ) ], 400 );
    }

    try {
        // Empty allowCredentials → the browser offers any discoverable passkey.
        $args = zenlogau_passkey_webauthn()->getGetArgs(
            [],
            ZENLOGAU_PASSKEY_LOGIN_TTL,
            true, true, true, true, true,
            'preferred'
        );
        $challenge = zenlogau_passkey_webauthn_challenge_from( $args );
    } catch ( \Throwable $e ) {
        wp_send_json_error( [ 'message' => __( 'Could not start passkey sign-in.', 'zen-login-authentication' ) ], 500 );
    }

    $handle = bin2hex( random_bytes( 16 ) );
    set_transient( 'zenlogau_pk_login_' . $handle, base64_encode( $challenge ), ZENLOGAU_PASSKEY_LOGIN_TTL );

    wp_send_json_success( [
        'publicKey' => $args->publicKey,
        'handle'    => $handle,
    ] );
}

/**
 * The library stores the challenge on its instance; getGetArgs put it into the
 * returned args. Read it straight from there so we persist exactly what was sent.
 */
function zenlogau_passkey_webauthn_challenge_from( \stdClass $args ): string {
    if ( isset( $args->publicKey->challenge ) && $args->publicKey->challenge instanceof \lbuchs\WebAuthn\Binary\ByteBuffer ) {
        return $args->publicKey->challenge->getBinaryString();
    }
    return '';
}

/* -----------------------------------------------------------------------
 * AJAX: login — step 2, verify + sign the user in
 * -------------------------------------------------------------------- */
add_action( 'wp_ajax_nopriv_zenlogau_passkey_login_verify', 'zenlogau_passkey_ajax_login_verify' );
add_action( 'wp_ajax_zenlogau_passkey_login_verify', 'zenlogau_passkey_ajax_login_verify' );

function zenlogau_passkey_ajax_login_verify(): void {
    if ( ! zenlogau_passkeys_available() ) {
        wp_send_json_error( [ 'message' => __( 'Passkeys are not available.', 'zen-login-authentication' ) ], 400 );
    }

    $client_data = base64_decode( (string) zenlogau_get_request_value( 'clientDataJSON', 'post' ), true );
    $auth_data   = base64_decode( (string) zenlogau_get_request_value( 'authenticatorData', 'post' ), true );
    $signature   = base64_decode( (string) zenlogau_get_request_value( 'signature', 'post' ), true );
    $raw_id      = base64_decode( (string) zenlogau_get_request_value( 'id', 'post' ), true );
    $user_handle = base64_decode( (string) zenlogau_get_request_value( 'userHandle', 'post' ), true );
    $handle      = preg_replace( '/[^a-f0-9]/', '', (string) zenlogau_get_request_value( 'handle', 'post' ) );

    $generic = [ 'message' => __( 'Passkey sign-in failed.', 'zen-login-authentication' ) ];

    if ( ! is_string( $client_data ) || ! is_string( $auth_data ) || ! is_string( $signature )
        || ! is_string( $raw_id ) || '' === $raw_id || ! is_string( $handle ) || '' === $handle ) {
        wp_send_json_error( $generic, 400 );
    }

    $challenge_b = get_transient( 'zenlogau_pk_login_' . $handle );
    delete_transient( 'zenlogau_pk_login_' . $handle );
    if ( ! is_string( $challenge_b ) || '' === $challenge_b ) {
        wp_send_json_error( $generic, 400 );
    }
    $challenge = (string) base64_decode( $challenge_b, true );

    // userHandle (= the user ID) tells us whose credential this must be.
    $user_id = is_string( $user_handle ) ? absint( $user_handle ) : 0;
    $user    = $user_id ? get_user_by( 'id', $user_id ) : false;
    if ( ! $user instanceof WP_User ) {
        wp_send_json_error( $generic, 400 );
    }

    $passkeys = zenlogau_get_passkeys( $user->ID );
    $cred_key = zenlogau_b64url_encode( $raw_id );
    if ( ! isset( $passkeys[ $cred_key ]['key'] ) ) {
        wp_send_json_error( $generic, 400 );
    }

    $webauthn = zenlogau_passkey_webauthn();
    try {
        // prevSignatureCnt = null: synced passkeys legitimately keep the counter
        // at zero / do not increment, so the regression check is skipped.
        $webauthn->processGet(
            $client_data,
            $auth_data,
            $signature,
            (string) $passkeys[ $cred_key ]['key'],
            $challenge,
            null,
            false, // require user verification
            true   // require user present
        );
    } catch ( \Throwable $e ) {
        wp_send_json_error( $generic, 400 );
    }

    // Verified. Record use (counter read from the same instance that verified).
    $passkeys[ $cred_key ]['last_used'] = time();
    $passkeys[ $cred_key ]['counter']   = (int) $webauthn->getSignatureCounter();
    zenlogau_save_passkeys( $user->ID, $passkeys );

    // Sign in. A passkey is already multi-factor, so we set the auth cookie
    // directly — this intentionally bypasses the password and the TOTP guard.
    $remember = (bool) zenlogau_get_request_value( 'remember', 'post' );
    wp_set_auth_cookie( $user->ID, $remember );
    wp_set_current_user( $user->ID );

    /** This is documented in WordPress core as firing on every login. */
    do_action( 'wp_login', $user->user_login, $user );
    do_action( 'zenlogau_passkey_login', $user->ID );

    $requested = zenlogau_validate_redirect( (string) zenlogau_get_request_value( 'redirect_to', 'post' ) );
    $redirect  = zenlogau_resolve_login_redirect( $user, $requested );

    wp_send_json_success( [ 'redirect' => $redirect ] );
}

/* -----------------------------------------------------------------------
 * AJAX: remove a passkey
 * -------------------------------------------------------------------- */
add_action( 'wp_ajax_zenlogau_passkey_delete', 'zenlogau_passkey_ajax_delete' );

function zenlogau_passkey_ajax_delete(): void {
    check_ajax_referer( 'zenlogau_passkey', 'nonce' );
    if ( ! is_user_logged_in() ) {
        wp_send_json_error( [ 'message' => __( 'Please log in and try again.', 'zen-login-authentication' ) ], 400 );
    }

    $user     = wp_get_current_user();
    $cred_key = sanitize_text_field( (string) zenlogau_get_request_value( 'credential', 'post' ) );
    $passkeys = zenlogau_get_passkeys( $user->ID );

    if ( '' === $cred_key || ! isset( $passkeys[ $cred_key ] ) ) {
        wp_send_json_error( [ 'message' => __( 'Passkey not found.', 'zen-login-authentication' ) ], 404 );
    }

    unset( $passkeys[ $cred_key ] );
    zenlogau_save_passkeys( $user->ID, $passkeys );
    do_action( 'zenlogau_passkey_removed', $user->ID );

    wp_send_json_success( [
        'message' => __( 'Passkey removed.', 'zen-login-authentication' ),
        'list'    => zenlogau_passkey_list_html( $user->ID ),
    ] );
}

/* -----------------------------------------------------------------------
 * Account page UI — manage passkeys
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_after_form_account', 'zenlogau_passkey_render_account_panel', 8 );

function zenlogau_passkey_render_account_panel(): void {
    if ( ! zenlogau_passkeys_feature_enabled() || ! is_user_logged_in() ) {
        return;
    }

    echo '<div class="fauth fauth-passkeys">';
    echo '<h3 class="fauth-passkeys-title">' . esc_html__( 'Passkeys', 'zen-login-authentication' ) . '</h3>';
    echo '<p class="fauth-passkeys-intro">' . esc_html__( 'Sign in without a password using your fingerprint, face, screen lock, or a security key.', 'zen-login-authentication' ) . '</p>';

    if ( ! zenlogau_passkeys_secure_context() ) {
        echo '<p class="fauth-passkeys-note">' . esc_html__( 'Passkeys require a secure (HTTPS) connection. They will become available once your site is served over HTTPS.', 'zen-login-authentication' ) . '</p>';
        echo '</div>';
        return;
    }

    echo '<div class="fauth-passkeys-list">' . zenlogau_passkey_list_html( get_current_user_id() ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- builder escapes internally.
    echo '<p class="fauth-passkeys-actions"><button type="button" class="fauth-button fauth-submit-button fauth-passkey-add">' . esc_html__( 'Add a passkey', 'zen-login-authentication' ) . '</button></p>';
    echo '<p class="fauth-passkey-status" role="status" aria-live="polite"></p>';
    echo '</div>';

    zenlogau_passkey_enqueue();
}

/**
 * Markup for the list of a user's registered passkeys. Returns escaped HTML.
 */
function zenlogau_passkey_list_html( int $user_id ): string {
    $passkeys = zenlogau_get_passkeys( $user_id );
    if ( empty( $passkeys ) ) {
        return '<p class="fauth-passkeys-empty">' . esc_html__( 'You have no passkeys yet.', 'zen-login-authentication' ) . '</p>';
    }

    $date_fmt = get_option( 'date_format' );
    $html     = '<ul class="fauth-passkey-items">';
    foreach ( $passkeys as $cred_key => $pk ) {
        $label   = isset( $pk['label'] ) ? (string) $pk['label'] : __( 'Passkey', 'zen-login-authentication' );
        $created = ! empty( $pk['created'] ) ? wp_date( $date_fmt, (int) $pk['created'] ) : '';
        $html   .= '<li class="fauth-passkey-item">';
        $html   .= '<span class="fauth-passkey-name">' . esc_html( $label ) . '</span>';
        if ( '' !== $created ) {
            $html .= ' <span class="fauth-passkey-meta">' . sprintf(
                /* translators: %s: date the passkey was added. */
                esc_html__( 'added %s', 'zen-login-authentication' ),
                esc_html( $created )
            ) . '</span>';
        }
        $html .= ' <button type="button" class="fauth-link-button fauth-passkey-remove" data-credential="' . esc_attr( (string) $cred_key ) . '">'
            . esc_html__( 'Remove', 'zen-login-authentication' ) . '</button>';
        $html .= '</li>';
    }
    $html .= '</ul>';
    return $html;
}

/* -----------------------------------------------------------------------
 * Login form UI — "Sign in with a passkey" button
 * -------------------------------------------------------------------- */
/**
 * Inline fingerprint icon for the passkey button. Uses currentColor and scales
 * with the button's font size, mirroring how the Google button carries its icon.
 */
function zenlogau_passkey_icon_svg(): string {
    return '<svg class="fauth-passkey-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . '<path d="M18.9 7a8 8 0 0 1 1.1 5v1a6 6 0 0 0 .8 3"/>'
        . '<path d="M8 11a4 4 0 0 1 8 0v1a10 10 0 0 0 2 6"/>'
        . '<path d="M12 11v2a14 14 0 0 0 2.5 8"/>'
        . '<path d="M8 15a18 18 0 0 0 1.8 6"/>'
        . '<path d="M4.9 19a22 22 0 0 1 -.9 -7v-1a8 8 0 0 1 12 -6.95"/>'
        . '</svg>';
}

// Priority 8: below the shared "or" divider (priority 6), above the Google
// button (priority 10) — so the order is divider -> passkey -> Google.
add_action( 'zenlogau_after_form_login', 'zenlogau_passkey_render_login_button', 8 );

function zenlogau_passkey_render_login_button( $form = null ): void {
    if ( ! zenlogau_passkeys_available() ) {
        return;
    }
    // In the Elementor editor the current user (the admin) is logged in; still
    // render the button there so it shows in the builder and can be styled. On
    // the live page it stays hidden for already-authenticated visitors.
    $in_editor = function_exists( 'zenlogau_is_elementor_context' ) && zenlogau_is_elementor_context();
    if ( is_user_logged_in() && ! $in_editor ) {
        return;
    }

    $redirect = zenlogau_validate_redirect( (string) zenlogau_get_request_value( 'redirect_to', 'get' ) );
    $text     = (string) apply_filters( 'zenlogau_passkey_button_text', __( 'Sign in with a passkey', 'zen-login-authentication' ) );

    echo '<div class="fauth fauth-passkey-login">';
    echo '<button type="button" class="fauth-button fauth-button-secondary fauth-passkey-signin" data-redirect="' . esc_attr( $redirect ) . '">'
        . zenlogau_passkey_icon_svg() // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static inline SVG.
        . '<span>' . esc_html( $text ) . '</span></button>';
    echo '<p class="fauth-passkey-status" role="status" aria-live="polite"></p>';
    echo '</div>';

    zenlogau_passkey_enqueue();
}

/* -----------------------------------------------------------------------
 * Cleanup
 * -------------------------------------------------------------------- */
add_action( 'deleted_user', 'zenlogau_passkey_delete_user_data' );

function zenlogau_passkey_delete_user_data( $user_id ): void {
    delete_user_meta( (int) $user_id, ZENLOGAU_PASSKEY_META );
}

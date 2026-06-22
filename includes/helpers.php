<?php
/**
 * Zen Login & Authentication – Helpers
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Request helpers
 * -------------------------------------------------------------------- */

function zenlogau_get_request_value( string $key, string $type = 'any' ) {
    $type = strtoupper( $type );
    // phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- central raw-input accessor: nonce verification and per-field sanitization happen at every call site, which knows the field's type.
    if ( 'POST' === $type ) {
        $value = $_POST[ $key ] ?? '';
    } elseif ( 'GET' === $type ) {
        $value = $_GET[ $key ] ?? '';
    } else {
        $value = $_REQUEST[ $key ] ?? '';
    }
    // phpcs:enable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
    // FIX (v1.4.14): Reject non-string input to prevent PHP 8.0+ TypeError.
    //
    // If an attacker sends array-valued parameters (e.g. log[]=foo), the raw
    // array would be returned and passed to sanitize_user(), sanitize_text_field(),
    // etc. — all of which expect strings. On PHP 8.0+ this causes a fatal
    // TypeError (e.g. strip_tags(): Argument #1 must be of type string, array given).
    //
    // No legitimate form submission sends array values for these fields, so
    // silently returning an empty string is the correct defensive approach.
    if ( ! is_string( $value ) ) {
        return '';
    }
    return wp_unslash( $value );
}

function zenlogau_is_post_request(): bool {
    return 'POST' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) );
}

function zenlogau_is_get_request(): bool {
    return 'GET' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) );
}

function zenlogau_is_ajax_request(): bool {
    return (bool) zenlogau_get_request_value( 'zenlogau_ajax' );
}

/* -----------------------------------------------------------------------
 * Redirect helpers
 * -------------------------------------------------------------------- */

function zenlogau_validate_redirect( string $url ): string {
    return wp_validate_redirect(
        wp_sanitize_redirect( $url ),
        apply_filters( 'wp_safe_redirect_fallback', admin_url(), 302 )
    );
}

/* -----------------------------------------------------------------------
 * URL helpers
 * -------------------------------------------------------------------- */

/**
 * Build the URL for a given action.
 *
 * ALWAYS uses the slug from the user's settings (zenlogau_slug_*).
 * Never uses get_permalink() on stored page IDs — that creates an
 * unsolvable desync between "what the user configured in settings"
 * and "what the auto-created page's actual post_name is."
 */
function zenlogau_get_action_url( string $action, bool $network = false ): string {
    if ( zenlogau_use_permalinks() ) {
        $slug = zenlogau_get_action_slug( $action );
        $base = $network ? network_home_url( '/' ) : home_url( '/' );
        $url  = trailingslashit( $base . $slug );
    } else {
        $raw_base = $network ? network_home_url( '/', 'login' ) : home_url( '/', 'login' );
        $url      = rtrim( $raw_base, '/' ) . '/wp-login.php';
        $url      = add_query_arg( 'action', $action, $url );
    }
    return (string) apply_filters( 'zenlogau_action_url', $url, $action );
}

function zenlogau_get_action_slug( string $action ): string {
    $default = zenlogau_get_action_slug_default( $action );
    $slug    = get_option( "zenlogau_slug_{$action}", $default );
    return (string) apply_filters( "zenlogau_action_slug_{$action}", sanitize_title( $slug ) );
}

/* -----------------------------------------------------------------------
 * Misc
 * -------------------------------------------------------------------- */

function zenlogau_get_username_label( string $context = 'login' ): string {
    if ( 'register' === $context ) {
        $label = __( 'Username', 'zen-login-authentication' );
    } elseif ( zenlogau_is_username_login_type() ) {
        $label = __( 'Username', 'zen-login-authentication' );
    } elseif ( zenlogau_is_email_login_type() ) {
        $label = __( 'Email Address', 'zen-login-authentication' );
    } else {
        $label = __( 'Username or Email Address', 'zen-login-authentication' );
    }
    return (string) apply_filters( 'zenlogau_username_label', $label, $context );
}

function zenlogau_honeypot_field_name( string $hour = '' ): string {
    if ( '' === $hour ) {
        $hour = gmdate( 'YmdH' );
    }
    // nosemgrep: php.lang.security.weak-crypto.weak-crypto -- non-security hash: derives a rotating honeypot field name for bot obfuscation, not a secret, password, or integrity check.
    return 'hp_' . substr( md5( wp_salt( 'auth' ) . $hour ), 0, 8 );
}

function zenlogau_honeypot_is_spam(): bool {
    if ( ! zenlogau_use_honeypot() ) {
        return false;
    }
    $current_hour  = gmdate( 'YmdH' );
    $previous_hour = gmdate( 'YmdH', time() - HOUR_IN_SECONDS );

    $field_current  = zenlogau_honeypot_field_name( $current_hour );
    $field_previous = zenlogau_honeypot_field_name( $previous_hour );

    $value_current  = wp_unslash( $_POST[ $field_current ]  ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Missing -- anti-bot trap field, checked for emptiness only and intentionally evaluated before (alongside) nonce verification.
    $value_previous = wp_unslash( $_POST[ $field_previous ] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Missing -- anti-bot trap field, checked for emptiness only and intentionally evaluated before (alongside) nonce verification.

    return ! empty( $value_current ) || ! empty( $value_previous );
}

function zenlogau_honeypot_field_html(): string {
    if ( ! zenlogau_use_honeypot() ) {
        return '';
    }
    $field = esc_attr( zenlogau_honeypot_field_name() );
    return '<div class="fauth-hp" style="display:none!important" aria-hidden="true">'
        . '<label for="' . $field . '">' . esc_html__( 'Leave this empty', 'zen-login-authentication' ) . '</label>'
        . '<input type="text" id="' . $field . '" name="' . $field . '" value="" autocomplete="off" tabindex="-1">'
        . '</div>';
}

function zenlogau_send_ajax_success( $data = null ): void {
    // Explicit 200 is critical: if the form posts to a virtual/404 URL,
    // WordPress sets status_header(404) before template_redirect fires.
    // wp_send_json_success() with null $status_code does NOT override it,
    // so jQuery sees a 404 JSON response and fires .fail() instead of .done().
    wp_send_json_success( apply_filters( 'zenlogau_ajax_success_data', $data ), 200 );
}

function zenlogau_send_ajax_error( $data = null ): void {
    // FIX: Use HTTP 200 instead of 400 so jQuery's .done() fires instead of
    // .fail(). The success/error distinction is carried by response.success
    // (false) and response.data.errors — not the HTTP status code.
    // With 400, jQuery's dataType:'json' routes the response to .fail() and
    // the real error messages from PHP are never shown to the user — instead
    // the generic fallback string "An error occurred. Please try again." fires.
    wp_send_json_error( apply_filters( 'zenlogau_ajax_error_data', $data ), 200 );
}

/* -----------------------------------------------------------------------
 * Elementor context detection
 * MEDIUM fix: added REST_REQUEST check for Elementor REST API calls.
 * -------------------------------------------------------------------- */

function zenlogau_is_elementor_context(): bool {
    if ( ! defined( 'ELEMENTOR_VERSION' ) ) {
        return false;
    }

    // MEDIUM FIX: Elementor uses WP REST API for saving/loading templates.
    // URL filters must not mutate data inside these requests.
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        $route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
        if ( str_contains( (string) $route, '/elementor/' ) ) {
            return true;
        }
    }

    // phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only environment detection (is this an Elementor editor/preview request?); no data is processed or persisted.
    if ( is_admin() && isset( $_GET['action'] ) && is_string( $_GET['action'] ) && 'elementor' === sanitize_key( wp_unslash( $_GET['action'] ) ) ) {
        return true;
    }
    if ( isset( $_GET['elementor-preview'] ) ) {
        return true;
    }
    if ( wp_doing_ajax() ) {
        $action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
        if ( str_starts_with( $action, 'elementor_' ) ) {
            return true;
        }
    }
    // phpcs:enable WordPress.Security.NonceVerification.Recommended
    if (
        isset( \Elementor\Plugin::$instance )
        && isset( \Elementor\Plugin::$instance->preview )
        && \Elementor\Plugin::$instance->preview->is_preview_mode()
    ) {
        return true;
    }
    return false;
}

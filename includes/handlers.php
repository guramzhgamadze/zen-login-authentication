<?php
/**
 * Frontend Auth – Handlers
 *
 * All form-processing and routing logic.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Route POST requests (login, register, lostpassword, resetpass)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'fauth_route_post_request', 0 );

function fauth_route_post_request(): void {
    if ( ! fauth_is_post_request() ) {
        return;
    }
    $action = sanitize_key( fauth_get_request_value( 'fauth_action', 'post' ) );
    if ( empty( $action ) || ! fauth()->get_action( $action ) ) {
        return;
    }
    $nonce = sanitize_key( fauth_get_request_value( "fauth_{$action}_nonce", 'post' ) );
    if ( ! wp_verify_nonce( $nonce, "fauth_{$action}" ) ) {
        // An expired/invalid nonce usually means the form was served from cache or
        // pasted as static HTML (a baked-in nonce eventually expires). For AJAX
        // submissions, return a clear JSON message instead of a raw 403 page — the
        // script can only render a 403 as the unhelpful generic-error fallback.
        if ( fauth_is_ajax_request() ) {
            fauth_send_ajax_error( [
                'errors' => [ __( 'Your session has expired. Please reload the page and try again.', 'frontend-auth' ) ],
            ] );
        }
        wp_die(
            esc_html__( 'Security check failed. Please try again.', 'frontend-auth' ),
            esc_html__( 'Security Error', 'frontend-auth' ),
            [ 'response' => 403 ]
        );
    }
    do_action( "fauth_action_{$action}" );
}

/* -----------------------------------------------------------------------
 * Route GET requests (logout)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'fauth_route_get_request', 0 );

function fauth_route_get_request(): void {
    if ( ! fauth_is_get_request() ) {
        return;
    }
    if ( 'logout' !== get_query_var( 'fauth_action', '' ) ) {
        return;
    }
    fauth_handle_logout();
}

/* -----------------------------------------------------------------------
 * Default action registration
 * -------------------------------------------------------------------- */
add_action( 'init', 'fauth_register_default_actions', 0 );

function fauth_register_default_actions(): void {
    static $done = false;
    if ( $done ) {
        return;
    }
    $done = true;

    fauth()->register_action( 'login', [
        'title'              => __( 'Log In', 'frontend-auth' ),
        'slug'               => fauth_get_action_slug( 'login' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    fauth()->register_action( 'logout', [
        'title'              => __( 'Log Out', 'frontend-auth' ),
        'slug'               => fauth_get_action_slug( 'logout' ),
        'show_in_widget'     => false,
        'show_on_forms'      => false,
        'show_nav_menu_item' => is_user_logged_in(),
    ] );

    fauth()->register_action( 'register', [
        'title'              => __( 'Register', 'frontend-auth' ),
        'slug'               => fauth_get_action_slug( 'register' ),
        'show_on_forms'      => (bool) get_option( 'users_can_register' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    fauth()->register_action( 'lostpassword', [
        'title'             => __( 'Lost Password', 'frontend-auth' ),
        'slug'              => fauth_get_action_slug( 'lostpassword' ),
        'show_in_nav_menus' => false,
    ] );

    fauth()->register_action( 'resetpass', [
        'title'             => __( 'Reset Password', 'frontend-auth' ),
        'slug'              => fauth_get_action_slug( 'resetpass' ),
        'show_in_widget'    => false,
        'show_in_nav_menus' => false,
    ] );
}

/* -----------------------------------------------------------------------
 * Login handler
 * -------------------------------------------------------------------- */
add_action( 'fauth_action_login', 'fauth_handle_login' );

function fauth_handle_login(): void {
    $is_ajax = fauth_is_ajax_request();

    if ( fauth_rate_limit_is_locked( 'login' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many failed attempts. Please try again in %d minutes.', 'frontend-auth' ),
            fauth_get_rate_limit_window()
        );
        $form = fauth()->get_form( 'login' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- the nonce is verified in fauth_route_post_request() before any handler is dispatched.
    $credentials = [
        'user_login'    => sanitize_user( fauth_get_request_value( 'log', 'post' ) ),
        'user_password' => fauth_get_request_value( 'pwd', 'post' ),
        'remember'      => isset( $_POST['rememberme'] ) && is_string( $_POST['rememberme'] )
                           && 'forever' === sanitize_key( wp_unslash( $_POST['rememberme'] ) ),
    ];
    // phpcs:enable WordPress.Security.NonceVerification.Missing

    $user = wp_signon( $credentials, is_ssl() );

    if ( is_wp_error( $user ) ) {
        fauth_rate_limit_bump( 'login' );

        $messages = [];
        $form     = fauth()->get_form( 'login' );

        foreach ( $user->get_error_codes() as $code ) {
            $raw = $user->get_error_message( $code );
            // Strip anchor tags — use /is flag so . matches newlines (WP error
            // messages wrap the "Lost your password?" link across multiple lines).
            $msg = preg_replace( '/<a[^>]*>.*?<\/a>/is', '', $raw );
            $msg = (string) $msg;
            // Strip any orphaned punctuation left after anchor removal.
            // e.g. WP may leave a trailing "?" from "Lost your password?" if
            // the "?" sits outside the closing </a> in some WP versions.
            $msg = trim( $msg, " \t\n\r\0\x0B.?!" );
            $msg = trim( $msg );
            // If stripping left nothing meaningful, fall back to stripping all
            // tags from the raw message so the sentence text is preserved.
            $plain = trim( wp_strip_all_tags( $msg ) );
            if ( '' === $plain ) {
                $plain = trim( wp_strip_all_tags( $raw ) );
                $plain = trim( $plain, " \t\n\r\0\x0B.?!" );
                $plain = trim( $plain );
            }
            $messages[] = $plain;
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => $messages ] );
        }

        do_action( 'fauth_login_failed', $credentials['user_login'] );
        return;
    }

    fauth_rate_limit_clear( 'login' );

    $redirect_to = fauth_get_request_value( 'redirect_to' );
    $redirect_to = $redirect_to ? fauth_validate_redirect( $redirect_to ) : '';

    // Determine if this is a subscriber (no wp-admin access).
    $is_subscriber = fauth_user_is_restricted_subscriber( $user );

    // Subscriber default destination — where subscribers land when there is no
    // explicit redirect_to, or when they try to go to wp-admin. Configurable via
    // Settings → Frontend Auth → "Subscriber redirect" (empty = site home).
    $subscriber_default = fauth_get_subscriber_redirect();

    if ( $is_subscriber ) {
        // Subscribers always land on the configured Subscriber redirect — it wins
        // over any redirect_to baked into the form/widget (e.g. a Login widget
        // "Redirect URL" or the home URL). To honour an explicit per-login
        // redirect for subscribers instead, return $redirect_to from this filter.
        $redirect_to = (string) apply_filters( 'fauth_subscriber_login_redirect_to', $subscriber_default, $redirect_to, $user );
    } elseif ( empty( $redirect_to ) ) {
        $redirect_to = apply_filters( 'login_redirect', home_url(), '', $user );
    }

    do_action( 'fauth_login_success', $user );

    if ( $is_ajax ) {
        fauth_send_ajax_success( [ 'redirect' => $redirect_to ] );
    }

    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Logout handler
 * -------------------------------------------------------------------- */
function fauth_handle_logout(): void {
    if ( ! is_user_logged_in() ) {
        wp_safe_redirect( fauth_get_action_url( 'login' ) );
        exit;
    }
    check_admin_referer( 'log-out' );
    wp_logout();

    $redirect_to = fauth_get_request_value( 'redirect_to' );
    $redirect_to = $redirect_to
        ? fauth_validate_redirect( $redirect_to )
        : apply_filters( 'fauth_logout_redirect', home_url() );

    do_action( 'fauth_logout_success' );
    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Registration handler
 * -------------------------------------------------------------------- */
add_action( 'fauth_action_register', 'fauth_handle_register' );

function fauth_handle_register(): void {
    $is_ajax = fauth_is_ajax_request();

    if ( ! get_option( 'users_can_register' ) ) {
        wp_safe_redirect( fauth_get_action_url( 'login' ) );
        exit;
    }

    if ( fauth_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            fauth_send_ajax_success( [
                'message' => __( 'Registration complete. Please check your email.', 'frontend-auth' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'registered', '1', fauth_get_action_url( 'login' ) ) );
        exit;
    }

    if ( fauth_rate_limit_is_locked( 'register' ) ) {
        $message = __( 'Too many registration attempts. Please wait before trying again.', 'frontend-auth' );
        $form    = fauth()->get_form( 'register' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user_login   = sanitize_user( fauth_get_request_value( 'user_login', 'post' ) );
    $user_email   = sanitize_email( fauth_get_request_value( 'user_email', 'post' ) );
    $registration = register_new_user( $user_login, $user_email );

    if ( is_wp_error( $registration ) ) {
        fauth_rate_limit_bump( 'register' );

        $messages = [];
        $form     = fauth()->get_form( 'register' );

        foreach ( $registration->get_error_codes() as $code ) {
            $msg        = $registration->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    $new_user_id = (int) $registration;

    // Hide the front-end admin toolbar by default for users who register here.
    // This only sets the initial preference (stored as user meta) — the user can
    // re-enable "Show Toolbar when viewing site" from their profile at any time.
    if ( apply_filters( 'fauth_hide_admin_bar_on_register', true, $new_user_id ) ) {
        update_user_meta( $new_user_id, 'show_admin_bar_front', 'false' );
    }

    if ( fauth_allow_user_passwords() ) {
        $pass1 = fauth_get_request_value( 'user_pass1', 'post' );
        wp_set_password( $pass1, $new_user_id );
        update_user_option( $new_user_id, 'default_password_nag', false, true );
        fauth_send_new_user_notifications( $new_user_id, 'admin' );
    }

    fauth_rate_limit_clear( 'register' );
    do_action( 'fauth_registration_success', $new_user_id );

    if ( fauth_allow_auto_login() ) {
        wp_set_auth_cookie( $new_user_id );
        $new_user    = get_user_by( 'id', $new_user_id );
        $redirect_to = apply_filters( 'login_redirect', home_url(), '', $new_user );
        if ( $is_ajax ) {
            fauth_send_ajax_success( [ 'redirect' => $redirect_to ] );
        }
        wp_safe_redirect( $redirect_to );
        exit;
    }

    if ( $is_ajax ) {
        fauth_send_ajax_success( [
            'message' => __( 'Registration complete. Please check your email for login instructions.', 'frontend-auth' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'registered', '1', fauth_get_action_url( 'login' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Lost Password handler
 * -------------------------------------------------------------------- */
add_action( 'fauth_action_lostpassword', 'fauth_handle_lostpassword' );

function fauth_handle_lostpassword(): void {
    $is_ajax = fauth_is_ajax_request();

    if ( fauth_rate_limit_is_locked( 'lostpassword' ) ) {
        $message = __( 'Too many attempts. Please wait a few minutes before trying again.', 'frontend-auth' );
        $form    = fauth()->get_form( 'lostpassword' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    // FIX (v1.4.14): Honeypot check was missing from this handler.
    if ( fauth_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            fauth_send_ajax_success( [
                'message' => __( 'Check your email for a link to reset your password.', 'frontend-auth' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', fauth_get_action_url( 'lostpassword' ) ) );
        exit;
    }

    $result = retrieve_password(
        sanitize_text_field( fauth_get_request_value( 'user_login', 'post' ) )
    );

    $count_all = (bool) get_option( 'fauth_lostpassword_count_all', false );

    if ( is_wp_error( $result ) ) {
        fauth_rate_limit_bump( 'lostpassword' );

        $messages = [];
        $form     = fauth()->get_form( 'lostpassword' );

        foreach ( $result->get_error_codes() as $code ) {
            $msg        = $result->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    if ( $count_all ) {
        fauth_rate_limit_bump( 'lostpassword' );
    } else {
        fauth_rate_limit_clear( 'lostpassword' );
    }

    if ( $is_ajax ) {
        fauth_send_ajax_success( [
            'message' => __( 'Check your email for a link to reset your password.', 'frontend-auth' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', fauth_get_action_url( 'lostpassword' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Reset Password handler
 * -------------------------------------------------------------------- */
add_action( 'fauth_action_resetpass', 'fauth_handle_resetpass' );

function fauth_handle_resetpass(): void {
    $is_ajax  = fauth_is_ajax_request();
    $rp_key   = sanitize_text_field( fauth_get_request_value( 'rp_key',   'post' ) );
    $rp_login = sanitize_text_field( fauth_get_request_value( 'rp_login', 'post' ) );
    $pass1    = fauth_get_request_value( 'pass1', 'post' );
    $pass2    = fauth_get_request_value( 'pass2', 'post' );
    $form     = fauth()->get_form( 'resetpass' );

    if ( fauth_rate_limit_is_locked( 'resetpass' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many attempts. Please try again in %d minutes.', 'frontend-auth' ),
            fauth_get_rate_limit_window()
        );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user = check_password_reset_key( $rp_key, $rp_login );

    if ( is_wp_error( $user ) ) {
        fauth_rate_limit_bump( 'resetpass' );
        $message = __( 'This password reset link has expired or is invalid. Please request a new one.', 'frontend-auth' );
        if ( $form ) {
            $form->add_error( 'invalid_key', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( empty( $pass1 ) || $pass1 !== $pass2 ) {
        $message = __( 'Passwords do not match. Please try again.', 'frontend-auth' );
        if ( $form ) {
            $form->add_error( 'password_mismatch', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( strlen( $pass1 ) < 8 ) {
        $message = __( 'Password must be at least 8 characters.', 'frontend-auth' );
        if ( $form ) {
            $form->add_error( 'password_too_short', $message );
        }
        if ( $is_ajax ) {
            fauth_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    fauth_rate_limit_clear( 'resetpass' );
    reset_password( $user, $pass1 );
    do_action( 'fauth_password_reset', $user );

    $redirect = add_query_arg( 'password', 'changed', fauth_get_action_url( 'login' ) );

    if ( $is_ajax ) {
        fauth_send_ajax_success( [ 'redirect' => $redirect ] );
    }

    wp_safe_redirect( $redirect );
    exit;
}

/* -----------------------------------------------------------------------
 * Server-side registration password validation
 * -------------------------------------------------------------------- */
add_filter( 'registration_errors', 'fauth_validate_registration_password', 10, 3 );

function fauth_validate_registration_password( WP_Error $errors, $sanitized_user_login, $user_email ): WP_Error {
    if ( ! fauth_allow_user_passwords() ) {
        return $errors;
    }
    $pass1 = fauth_get_request_value( 'user_pass1', 'post' );
    $pass2 = fauth_get_request_value( 'user_pass2', 'post' );

    if ( empty( $pass1 ) || empty( $pass2 ) ) {
        $errors->add( 'empty_password', __( 'Please enter a password.', 'frontend-auth' ) );
    } elseif ( $pass1 !== $pass2 ) {
        $errors->add( 'password_mismatch', __( 'Passwords do not match.', 'frontend-auth' ) );
    } elseif ( strlen( $pass1 ) < 8 ) {
        $errors->add( 'password_too_short', __( 'Password must be at least 8 characters.', 'frontend-auth' ) );
    }

    return $errors;
}

/* -----------------------------------------------------------------------
 * Enforce login type (email-only or username-only)
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'fauth_enforce_login_type', 20, 3 );

function fauth_enforce_login_type( $user, $username, $password ) {
    if ( $user instanceof WP_User || is_wp_error( $user ) ) {
        return $user;
    }
    if ( fauth_is_email_login_type() && ! is_email( $username ) ) {
        return new WP_Error(
            'invalid_email',
            __( 'Please log in with your email address.', 'frontend-auth' )
        );
    }
    if ( fauth_is_username_login_type() && is_email( $username ) ) {
        return new WP_Error(
            'invalid_username',
            __( 'Please log in with your username, not your email address.', 'frontend-auth' )
        );
    }
    return $user;
}

/* -----------------------------------------------------------------------
 * New user notification helpers
 * -------------------------------------------------------------------- */

function fauth_send_new_user_notifications( int $user_id, string $notify = 'both' ): void {
    $notify = apply_filters( 'fauth_new_user_notification', $notify, $user_id );
    if ( 'none' === $notify ) {
        return;
    }
    wp_new_user_notification( $user_id, null, $notify );
}

add_filter( 'wp_send_new_user_notification_to_user', 'fauth_maybe_suppress_user_notification', 10, 2 );

function fauth_maybe_suppress_user_notification( bool $send, WP_User $user ): bool {
    if ( ! fauth_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( fauth_get_request_value( 'fauth_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    if ( fauth_allow_user_passwords() ) {
        return false;
    }
    return $send;
}

/**
 * Suppress the ADMIN notification fired internally by register_new_user() when
 * user-chosen passwords are enabled.
 *
 * wp_send_new_user_notification_to_admin was introduced in WP 6.1.
 * Source: developer.wordpress.org/reference/hooks/wp_send_new_user_notification_to_admin/
 */
add_filter( 'wp_send_new_user_notification_to_admin', 'fauth_maybe_suppress_admin_notification', 10, 2 );

function fauth_maybe_suppress_admin_notification( bool $send, WP_User $user ): bool {
    if ( ! fauth_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( fauth_get_request_value( 'fauth_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    if ( fauth_allow_user_passwords() ) {
        return false;
    }
    return $send;
}

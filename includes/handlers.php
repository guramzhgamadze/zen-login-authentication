<?php
/**
 * WP Frontend Auth – Handlers
 *
 * All form-processing and routing logic.
 *
 * @package WP_Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Route POST requests (login, register, lostpassword, resetpass)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'wpfa_route_post_request', 0 );

function wpfa_route_post_request(): void {
    if ( ! wpfa_is_post_request() ) {
        return;
    }
    $action = sanitize_key( wpfa_get_request_value( 'wpfa_action', 'post' ) );
    if ( empty( $action ) || ! wpfa()->get_action( $action ) ) {
        return;
    }
    $nonce = sanitize_key( wpfa_get_request_value( "wpfa_{$action}_nonce", 'post' ) );
    if ( ! wp_verify_nonce( $nonce, "wpfa_{$action}" ) ) {
        wp_die(
            esc_html__( 'Security check failed. Please try again.', 'wp-frontend-auth' ),
            esc_html__( 'Security Error', 'wp-frontend-auth' ),
            [ 'response' => 403 ]
        );
    }
    do_action( "wpfa_action_{$action}" );
}

/* -----------------------------------------------------------------------
 * Route GET requests (logout)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'wpfa_route_get_request', 0 );

function wpfa_route_get_request(): void {
    if ( ! wpfa_is_get_request() ) {
        return;
    }
    if ( 'logout' !== get_query_var( 'wpfa_action', '' ) ) {
        return;
    }
    wpfa_handle_logout();
}

/* -----------------------------------------------------------------------
 * Default action registration
 * -------------------------------------------------------------------- */
add_action( 'init', 'wpfa_register_default_actions', 0 );

function wpfa_register_default_actions(): void {
    static $done = false;
    if ( $done ) {
        return;
    }
    $done = true;

    wpfa()->register_action( 'login', [
        'title'              => __( 'Log In', 'wp-frontend-auth' ),
        'slug'               => wpfa_get_action_slug( 'login' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    wpfa()->register_action( 'logout', [
        'title'              => __( 'Log Out', 'wp-frontend-auth' ),
        'slug'               => wpfa_get_action_slug( 'logout' ),
        'show_in_widget'     => false,
        'show_on_forms'      => false,
        'show_nav_menu_item' => is_user_logged_in(),
    ] );

    wpfa()->register_action( 'register', [
        'title'              => __( 'Register', 'wp-frontend-auth' ),
        'slug'               => wpfa_get_action_slug( 'register' ),
        'show_on_forms'      => (bool) get_option( 'users_can_register' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    wpfa()->register_action( 'lostpassword', [
        'title'             => __( 'Lost Password', 'wp-frontend-auth' ),
        'slug'              => wpfa_get_action_slug( 'lostpassword' ),
        'show_in_nav_menus' => false,
    ] );

    wpfa()->register_action( 'resetpass', [
        'title'             => __( 'Reset Password', 'wp-frontend-auth' ),
        'slug'              => wpfa_get_action_slug( 'resetpass' ),
        'show_in_widget'    => false,
        'show_in_nav_menus' => false,
    ] );
}

/* -----------------------------------------------------------------------
 * Login handler
 * -------------------------------------------------------------------- */
add_action( 'wpfa_action_login', 'wpfa_handle_login' );

function wpfa_handle_login(): void {
    $is_ajax = wpfa_is_ajax_request();

    if ( wpfa_rate_limit_is_locked( 'login' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many failed attempts. Please try again in %d minutes.', 'wp-frontend-auth' ),
            wpfa_get_rate_limit_window()
        );
        $form = wpfa()->get_form( 'login' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $credentials = [
        'user_login'    => sanitize_user( wpfa_get_request_value( 'log', 'post' ) ),
        'user_password' => wpfa_get_request_value( 'pwd', 'post' ),
        // Fix 5 — explicit check against expected value 'forever' matching the form field;
        //          sanitize_key() strips slashes (WP magic-quotes) and normalises case.
        //          Source: developer.wordpress.org/apis/security/sanitizing/
        'remember'      => isset( $_POST['rememberme'] ) && is_string( $_POST['rememberme'] )
                           && 'forever' === sanitize_key( wp_unslash( $_POST['rememberme'] ) ),
    ];

    $user = wp_signon( $credentials, is_ssl() );

    if ( is_wp_error( $user ) ) {
        wpfa_rate_limit_bump( 'login' );

        $messages = [];
        $form     = wpfa()->get_form( 'login' );

        foreach ( $user->get_error_codes() as $code ) {
            $msg        = preg_replace( '/<a[^>]*>.*?<\/a>/i', '', $user->get_error_message( $code ) );
            $msg        = trim( $msg );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => $messages ] );
        }

        do_action( 'wpfa_login_failed', $credentials['user_login'] );
        return;
    }

    wpfa_rate_limit_clear( 'login' );

    $redirect_to = wpfa_get_request_value( 'redirect_to' );
    $redirect_to = $redirect_to ? wpfa_validate_redirect( $redirect_to ) : '';

    // Determine if this is a subscriber (no wp-admin access).
    $is_subscriber = count( $user->roles ) === 1 && in_array( 'subscriber', $user->roles, true );

    // Subscriber default destination — where subscribers land when there is no
    // explicit redirect_to, or when they try to go to wp-admin.
    $subscriber_default = apply_filters( 'wpfa_subscriber_redirect', home_url( '/instructor_dashboard/' ) );

    if ( empty( $redirect_to ) ) {
        // No redirect_to supplied:
        //   — Subscribers → instructor dashboard (never wp-admin).
        //   — Privileged users → home_url(). They came via the login page
        //     directly (no ?redirect_to=), so sending them to wp-admin
        //     is presumptuous. home_url() is a safe, neutral landing point.
        //     They can navigate to wp-admin themselves if that's where they want to go.
        //     Use the standard login_redirect filter so other plugins can override.
        $default     = $is_subscriber ? $subscriber_default : home_url();
        $redirect_to = apply_filters( 'login_redirect', $default, '', $user );
    } elseif ( $is_subscriber && str_starts_with( $redirect_to, admin_url() ) ) {
        // Subscriber tried to go to wp-admin via redirect_to — block it.
        $redirect_to = $subscriber_default;
    }
    // For privileged users with a valid redirect_to: honour it exactly.

    do_action( 'wpfa_login_success', $user );

    if ( $is_ajax ) {
        wpfa_send_ajax_success( [ 'redirect' => $redirect_to ] );
    }

    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Logout handler
 * -------------------------------------------------------------------- */
function wpfa_handle_logout(): void {
    if ( ! is_user_logged_in() ) {
        wp_safe_redirect( wpfa_get_action_url( 'login' ) );
        exit;
    }
    check_admin_referer( 'log-out' );
    wp_logout();

    $redirect_to = wpfa_get_request_value( 'redirect_to' );
    $redirect_to = $redirect_to
        ? wpfa_validate_redirect( $redirect_to )
        : apply_filters( 'wpfa_logout_redirect', home_url() );

    do_action( 'wpfa_logout_success' );
    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Registration handler
 * -------------------------------------------------------------------- */
add_action( 'wpfa_action_register', 'wpfa_handle_register' );

function wpfa_handle_register(): void {
    $is_ajax = wpfa_is_ajax_request();

    if ( ! get_option( 'users_can_register' ) ) {
        wp_safe_redirect( wpfa_get_action_url( 'login' ) );
        exit;
    }

    if ( wpfa_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            wpfa_send_ajax_success( [
                'message' => __( 'Registration complete. Please check your email.', 'wp-frontend-auth' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'registered', '1', wpfa_get_action_url( 'login' ) ) );
        exit;
    }

    if ( wpfa_rate_limit_is_locked( 'register' ) ) {
        $message = __( 'Too many registration attempts. Please wait before trying again.', 'wp-frontend-auth' );
        $form    = wpfa()->get_form( 'register' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user_login   = sanitize_user( wpfa_get_request_value( 'user_login', 'post' ) );
    $user_email   = sanitize_email( wpfa_get_request_value( 'user_email', 'post' ) );
    $registration = register_new_user( $user_login, $user_email );

    if ( is_wp_error( $registration ) ) {
        wpfa_rate_limit_bump( 'register' );

        $messages = [];
        $form     = wpfa()->get_form( 'register' );

        foreach ( $registration->get_error_codes() as $code ) {
            $msg        = $registration->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    $new_user_id = (int) $registration;

    if ( wpfa_allow_user_passwords() ) {
        $pass1 = wpfa_get_request_value( 'user_pass1', 'post' );
        wp_set_password( $pass1, $new_user_id );
        update_user_option( $new_user_id, 'default_password_nag', false, true );
        wpfa_send_new_user_notifications( $new_user_id, 'admin' );
    }

    wpfa_rate_limit_clear( 'register' );
    do_action( 'wpfa_registration_success', $new_user_id );

    if ( wpfa_allow_auto_login() ) {
        wp_set_auth_cookie( $new_user_id );
        $new_user    = get_user_by( 'id', $new_user_id );
        $redirect_to = apply_filters( 'login_redirect', home_url(), '', $new_user );
        if ( $is_ajax ) {
            wpfa_send_ajax_success( [ 'redirect' => $redirect_to ] );
        }
        wp_safe_redirect( $redirect_to );
        exit;
    }

    if ( $is_ajax ) {
        wpfa_send_ajax_success( [
            'message' => __( 'Registration complete. Please check your email for login instructions.', 'wp-frontend-auth' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'registered', '1', wpfa_get_action_url( 'login' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Lost Password handler
 * -------------------------------------------------------------------- */
add_action( 'wpfa_action_lostpassword', 'wpfa_handle_lostpassword' );

function wpfa_handle_lostpassword(): void {
    $is_ajax = wpfa_is_ajax_request();

    if ( wpfa_rate_limit_is_locked( 'lostpassword' ) ) {
        $message = __( 'Too many attempts. Please wait a few minutes before trying again.', 'wp-frontend-auth' );
        $form    = wpfa()->get_form( 'lostpassword' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    // FIX (v1.4.14): Honeypot check was missing from this handler.
    //
    // The honeypot hidden field is rendered in EVERY form (via WPFA_Form::render()),
    // but the spam check was only called in wpfa_handle_register(). Without this
    // guard, bots can automate the lost-password form to trigger mass password-reset
    // emails to arbitrary users — even if rate limiting slows them down, they still
    // generate real emails up to the limit. The honeypot catches simple bots before
    // retrieve_password() fires, and returns a fake success so the bot never adapts.
    if ( wpfa_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            wpfa_send_ajax_success( [
                'message' => __( 'Check your email for a link to reset your password.', 'wp-frontend-auth' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', wpfa_get_action_url( 'lostpassword' ) ) );
        exit;
    }

    $result = retrieve_password(
        sanitize_text_field( wpfa_get_request_value( 'user_login', 'post' ) )
    );

    // FIX (v1.4.18): Optionally count successful submissions toward the rate limit.
    //
    // WordPress core's retrieve_password() returns true on success — including for
    // unknown email addresses (anti-enumeration behavior since WP 5.5). This means
    // a determined attacker spamming reset emails to a single known-valid address
    // can bypass the rate limiter entirely: every call returns true, the counter
    // is cleared on success below, and emails go out unchecked.
    //
    // When wpfa_lostpassword_count_all is enabled, every submission bumps the
    // counter. The success-clear path is skipped, so attempt #11 from the same
    // IP gets blocked regardless of whether the email is valid.
    //
    // Default OFF for backward compatibility — admins can opt in via the
    // "Count successful lost-password requests" toggle in Settings → Frontend Auth.
    $count_all = (bool) get_option( 'wpfa_lostpassword_count_all', false );

    if ( is_wp_error( $result ) ) {
        wpfa_rate_limit_bump( 'lostpassword' );

        $messages = [];
        $form     = wpfa()->get_form( 'lostpassword' );

        foreach ( $result->get_error_codes() as $code ) {
            $msg        = $result->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    if ( $count_all ) {
        wpfa_rate_limit_bump( 'lostpassword' );
    } else {
        wpfa_rate_limit_clear( 'lostpassword' );
    }

    if ( $is_ajax ) {
        wpfa_send_ajax_success( [
            'message' => __( 'Check your email for a link to reset your password.', 'wp-frontend-auth' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', wpfa_get_action_url( 'lostpassword' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Reset Password handler
 * -------------------------------------------------------------------- */
add_action( 'wpfa_action_resetpass', 'wpfa_handle_resetpass' );

function wpfa_handle_resetpass(): void {
    $is_ajax  = wpfa_is_ajax_request();
    $rp_key   = sanitize_text_field( wpfa_get_request_value( 'rp_key',   'post' ) );
    $rp_login = sanitize_text_field( wpfa_get_request_value( 'rp_login', 'post' ) );
    $pass1    = wpfa_get_request_value( 'pass1', 'post' );
    $pass2    = wpfa_get_request_value( 'pass2', 'post' );
    $form     = wpfa()->get_form( 'resetpass' );

    // FIX: Rate-limit password reset submissions.
    //
    // Without this guard, an attacker can brute-force the rp_key (password reset token)
    // by submitting the reset form in a loop. login, register, and lostpassword all
    // have rate limiting — resetpass must too for consistent security posture.
    //
    // Source: owasp.org/www-community/attacks/Brute_force_attack
    //         developer.wordpress.org/reference/functions/check_password_reset_key/
    if ( wpfa_rate_limit_is_locked( 'resetpass' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many attempts. Please try again in %d minutes.', 'wp-frontend-auth' ),
            wpfa_get_rate_limit_window()
        );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user = check_password_reset_key( $rp_key, $rp_login );

    if ( is_wp_error( $user ) ) {
        wpfa_rate_limit_bump( 'resetpass' ); // FIX: count failed attempts
        $message = __( 'This password reset link has expired or is invalid. Please request a new one.', 'wp-frontend-auth' );
        if ( $form ) {
            $form->add_error( 'invalid_key', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( empty( $pass1 ) || $pass1 !== $pass2 ) {
        $message = __( 'Passwords do not match. Please try again.', 'wp-frontend-auth' );
        if ( $form ) {
            $form->add_error( 'password_mismatch', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( strlen( $pass1 ) < 8 ) {
        $message = __( 'Password must be at least 8 characters.', 'wp-frontend-auth' );
        if ( $form ) {
            $form->add_error( 'password_too_short', $message );
        }
        if ( $is_ajax ) {
            wpfa_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    wpfa_rate_limit_clear( 'resetpass' ); // FIX: clear counter on success
    reset_password( $user, $pass1 );
    do_action( 'wpfa_password_reset', $user );

    $redirect = add_query_arg( 'password', 'changed', wpfa_get_action_url( 'login' ) );

    if ( $is_ajax ) {
        wpfa_send_ajax_success( [ 'redirect' => $redirect ] );
    }

    wp_safe_redirect( $redirect );
    exit;
}

/* -----------------------------------------------------------------------
 * Server-side registration password validation
 * -------------------------------------------------------------------- */
add_filter( 'registration_errors', 'wpfa_validate_registration_password', 10, 3 );

function wpfa_validate_registration_password( WP_Error $errors, $sanitized_user_login, $user_email ): WP_Error {
    if ( ! wpfa_allow_user_passwords() ) {
        return $errors;
    }
    $pass1 = wpfa_get_request_value( 'user_pass1', 'post' );
    $pass2 = wpfa_get_request_value( 'user_pass2', 'post' );

    if ( empty( $pass1 ) || empty( $pass2 ) ) {
        $errors->add( 'empty_password', __( 'Please enter a password.', 'wp-frontend-auth' ) );
    } elseif ( $pass1 !== $pass2 ) {
        $errors->add( 'password_mismatch', __( 'Passwords do not match.', 'wp-frontend-auth' ) );
    } elseif ( strlen( $pass1 ) < 8 ) {
        $errors->add( 'password_too_short', __( 'Password must be at least 8 characters.', 'wp-frontend-auth' ) );
    }

    return $errors;
}

/* -----------------------------------------------------------------------
 * Enforce login type (email-only or username-only)
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'wpfa_enforce_login_type', 20, 3 );

function wpfa_enforce_login_type( $user, $username, $password ) {
    if ( $user instanceof WP_User || is_wp_error( $user ) ) {
        return $user;
    }
    if ( wpfa_is_email_login_type() && ! is_email( $username ) ) {
        return new WP_Error(
            'invalid_email',
            __( 'Please log in with your email address.', 'wp-frontend-auth' )
        );
    }
    if ( wpfa_is_username_login_type() && is_email( $username ) ) {
        return new WP_Error(
            'invalid_username',
            __( 'Please log in with your username, not your email address.', 'wp-frontend-auth' )
        );
    }
    return $user;
}

/* -----------------------------------------------------------------------
 * New user notification helpers
 * -------------------------------------------------------------------- */

function wpfa_send_new_user_notifications( int $user_id, string $notify = 'both' ): void {
    $notify = apply_filters( 'wpfa_new_user_notification', $notify, $user_id );
    if ( 'none' === $notify ) {
        return;
    }
    wp_new_user_notification( $user_id, null, $notify );
}

add_filter( 'wp_send_new_user_notification_to_user', 'wpfa_maybe_suppress_user_notification', 10, 2 );

function wpfa_maybe_suppress_user_notification( bool $send, WP_User $user ): bool {
    if ( ! wpfa_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( wpfa_get_request_value( 'wpfa_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    if ( wpfa_allow_user_passwords() ) {
        return false;
    }
    return $send;
}

/**
 * Suppress the ADMIN notification fired internally by register_new_user() when
 * user-chosen passwords are enabled.
 *
 * BUG FIX (v1.4.5) — Double admin email on registration with user passwords:
 *
 * When wpfa_allow_user_passwords() is true the flow is:
 *   1. register_new_user() runs and internally calls wp_new_user_notification(),
 *      which fires both the user and admin notification emails. The existing
 *      wpfa_maybe_suppress_user_notification filter (above) correctly blocks
 *      the user email at step 1. But the admin email still fires here.
 *   2. wpfa_send_new_user_notifications($id, 'admin') is then called explicitly,
 *      sending a SECOND admin notification with the correct context.
 *
 * Result: admin receives two identical "New User Registration" emails.
 *
 * Fix: also block the admin email triggered inside register_new_user() when
 * user-chosen passwords are enabled. wpfa_send_new_user_notifications() later
 * sends the one correct admin notification.
 *
 * wp_send_new_user_notification_to_admin was introduced in WP 6.1.
 * Source: developer.wordpress.org/reference/hooks/wp_send_new_user_notification_to_admin/
 */
add_filter( 'wp_send_new_user_notification_to_admin', 'wpfa_maybe_suppress_admin_notification', 10, 2 );

function wpfa_maybe_suppress_admin_notification( bool $send, WP_User $user ): bool {
    if ( ! wpfa_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( wpfa_get_request_value( 'wpfa_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    // Only suppress the internal notification from register_new_user() when
    // user passwords are enabled — wpfa_send_new_user_notifications() will
    // send the one correct admin email after wp_set_password() completes.
    if ( wpfa_allow_user_passwords() ) {
        return false;
    }
    return $send;
}

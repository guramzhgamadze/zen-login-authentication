<?php
/**
 * Zen Login & Authentication – Handlers
 *
 * All form-processing and routing logic.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Route POST requests (login, register, lostpassword, resetpass)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'zenlogau_route_post_request', 0 );

function zenlogau_route_post_request(): void {
    if ( ! zenlogau_is_post_request() ) {
        return;
    }
    $action = sanitize_key( zenlogau_get_request_value( 'zenlogau_action', 'post' ) );
    if ( empty( $action ) || ! zenlogau()->get_action( $action ) ) {
        return;
    }
    $nonce = sanitize_key( zenlogau_get_request_value( "zenlogau_{$action}_nonce", 'post' ) );
    if ( ! wp_verify_nonce( $nonce, "zenlogau_{$action}" ) ) {
        // An expired/invalid nonce usually means the form was served from cache or
        // pasted as static HTML (a baked-in nonce eventually expires). For AJAX
        // submissions, return a clear JSON message instead of a raw 403 page — the
        // script can only render a 403 as the unhelpful generic-error fallback.
        if ( zenlogau_is_ajax_request() ) {
            zenlogau_send_ajax_error( [
                'errors' => [ __( 'Your session has expired. Please reload the page and try again.', 'zen-login-authentication' ) ],
            ] );
        }
        wp_die(
            esc_html__( 'Security check failed. Please try again.', 'zen-login-authentication' ),
            esc_html__( 'Security Error', 'zen-login-authentication' ),
            [ 'response' => 403 ]
        );
    }
    do_action( "zenlogau_action_{$action}" );
}

/* -----------------------------------------------------------------------
 * Route GET requests (logout)
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'zenlogau_route_get_request', 0 );

function zenlogau_route_get_request(): void {
    if ( ! zenlogau_is_get_request() ) {
        return;
    }
    if ( 'logout' !== get_query_var( 'zenlogau_action', '' ) ) {
        return;
    }
    zenlogau_handle_logout();
}

/* -----------------------------------------------------------------------
 * Default action registration
 * -------------------------------------------------------------------- */
add_action( 'init', 'zenlogau_register_default_actions', 0 );

function zenlogau_register_default_actions(): void {
    static $done = false;
    if ( $done ) {
        return;
    }
    $done = true;

    zenlogau()->register_action( 'login', [
        'title'              => __( 'Log In', 'zen-login-authentication' ),
        'slug'               => zenlogau_get_action_slug( 'login' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    zenlogau()->register_action( 'logout', [
        'title'              => __( 'Log Out', 'zen-login-authentication' ),
        'slug'               => zenlogau_get_action_slug( 'logout' ),
        'show_in_widget'     => false,
        'show_on_forms'      => false,
        'show_nav_menu_item' => is_user_logged_in(),
    ] );

    zenlogau()->register_action( 'register', [
        'title'              => __( 'Register', 'zen-login-authentication' ),
        'slug'               => zenlogau_get_action_slug( 'register' ),
        'show_on_forms'      => (bool) get_option( 'users_can_register' ),
        'show_nav_menu_item' => ! is_user_logged_in(),
    ] );

    zenlogau()->register_action( 'lostpassword', [
        'title'             => __( 'Lost Password', 'zen-login-authentication' ),
        'slug'              => zenlogau_get_action_slug( 'lostpassword' ),
        'show_in_nav_menus' => false,
    ] );

    zenlogau()->register_action( 'resetpass', [
        'title'             => __( 'Reset Password', 'zen-login-authentication' ),
        'slug'              => zenlogau_get_action_slug( 'resetpass' ),
        'show_in_widget'    => false,
        'show_in_nav_menus' => false,
    ] );

    zenlogau()->register_action( 'account', [
        'title'              => __( 'My Account', 'zen-login-authentication' ),
        'slug'               => zenlogau_get_action_slug( 'account' ),
        'show_on_forms'      => false,
        'show_nav_menu_item' => is_user_logged_in(),
    ] );
}

/* -----------------------------------------------------------------------
 * Post-login redirect resolution
 *
 * One place that decides where a user lands after a front-end login or an
 * auto-login registration. Two rules, matching the plugin's policy:
 *
 *   1. Respect other plugins. The standard `login_redirect` filter is always
 *      run — exactly as wp-login.php does — so membership/LMS plugins, themes,
 *      and the login form/widget all get their say.
 *   2. Never drop a restricted subscriber into wp-admin. Enforced by
 *      zenlogau_subscriber_login_redirect() (hooked onto login_redirect, last),
 *      which keeps any non-admin destination but rewrites empty/admin targets
 *      to the configured Subscriber redirect. Admins/editors are unaffected.
 * -------------------------------------------------------------------- */

function zenlogau_resolve_login_redirect( WP_User $user, string $requested = '' ): string {
    $requested     = '' !== $requested ? zenlogau_validate_redirect( $requested ) : '';
    $is_subscriber = zenlogau_user_is_restricted_subscriber( $user );

    // Pre-filter default. Honour an explicit destination the user was heading
    // to — for non-subscribers even an admin one (the "clicked Edit, bounced to
    // login" round-trip). Subscribers never default into wp-admin; they fall
    // back to the configured Subscriber redirect instead.
    if ( '' !== $requested && ! ( $is_subscriber && zenlogau_redirect_is_admin( $requested ) ) ) {
        $default = $requested;
    } elseif ( $is_subscriber ) {
        $default = zenlogau_get_subscriber_redirect();
    } else {
        $default = home_url();
    }

    /** This filter is documented in wp-login.php — keep other plugins working. */
    $redirect_to = (string) apply_filters( 'login_redirect', $default, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- applying WordPress core's own login_redirect filter.
    $redirect_to = zenlogau_validate_redirect( $redirect_to );

    return '' !== $redirect_to ? $redirect_to : home_url();
}

/* -----------------------------------------------------------------------
 * Login handler
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_action_login', 'zenlogau_handle_login' );

function zenlogau_handle_login(): void {
    $is_ajax = zenlogau_is_ajax_request();

    if ( zenlogau_rate_limit_is_locked( 'login' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many failed attempts. Please try again in %d minutes.', 'zen-login-authentication' ),
            zenlogau_get_rate_limit_window()
        );
        $form = zenlogau()->get_form( 'login' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    // phpcs:disable WordPress.Security.NonceVerification.Missing -- the nonce is verified in zenlogau_route_post_request() before any handler is dispatched.
    $credentials = [
        'user_login'    => sanitize_user( zenlogau_get_request_value( 'log', 'post' ) ),
        'user_password' => zenlogau_get_request_value( 'pwd', 'post' ),
        'remember'      => isset( $_POST['rememberme'] ) && is_string( $_POST['rememberme'] )
                           && 'forever' === sanitize_key( wp_unslash( $_POST['rememberme'] ) ),
    ];
    // phpcs:enable WordPress.Security.NonceVerification.Missing

    $user = wp_signon( $credentials, is_ssl() );

    if ( is_wp_error( $user ) ) {
        // Correct password, but the account has 2FA: don't treat this as a
        // failed attempt — hand off to the themed second-factor challenge.
        if ( in_array( 'zenlogau_2fa_required', $user->get_error_codes(), true ) ) {
            $zenlogau_2fa_data  = $user->get_error_data( 'zenlogau_2fa_required' );
            $zenlogau_2fa_token = is_array( $zenlogau_2fa_data ) && isset( $zenlogau_2fa_data['token'] ) ? (string) $zenlogau_2fa_data['token'] : '';
            $zenlogau_2fa_url   = add_query_arg( 'zenlogau_2fa', $zenlogau_2fa_token, zenlogau_get_action_url( 'login' ) );
            if ( $is_ajax ) {
                zenlogau_send_ajax_success( [ 'redirect' => $zenlogau_2fa_url ] );
            }
            wp_safe_redirect( $zenlogau_2fa_url );
            exit;
        }

        zenlogau_rate_limit_bump( 'login' );

        $messages = [];
        $form     = zenlogau()->get_form( 'login' );

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
            zenlogau_send_ajax_error( [ 'errors' => $messages ] );
        }

        do_action( 'zenlogau_login_failed', $credentials['user_login'] );
        return;
    }

    zenlogau_rate_limit_clear( 'login' );

    $redirect_to = zenlogau_resolve_login_redirect( $user, (string) zenlogau_get_request_value( 'redirect_to' ) );

    do_action( 'zenlogau_login_success', $user );

    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [ 'redirect' => $redirect_to ] );
    }

    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Logout handler
 * -------------------------------------------------------------------- */
function zenlogau_handle_logout(): void {
    if ( ! is_user_logged_in() ) {
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }
    check_admin_referer( 'log-out' );
    wp_logout();

    $redirect_to = zenlogau_get_request_value( 'redirect_to' );
    $redirect_to = $redirect_to
        ? zenlogau_validate_redirect( $redirect_to )
        : apply_filters( 'zenlogau_logout_redirect', home_url() );

    do_action( 'zenlogau_logout_success' );
    wp_safe_redirect( $redirect_to );
    exit;
}

/* -----------------------------------------------------------------------
 * Registration handler
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_action_register', 'zenlogau_handle_register' );

function zenlogau_handle_register(): void {
    $is_ajax = zenlogau_is_ajax_request();

    if ( ! get_option( 'users_can_register' ) ) {
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }

    if ( zenlogau_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            zenlogau_send_ajax_success( [
                'message' => __( 'Registration complete. Please check your email.', 'zen-login-authentication' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'registered', '1', zenlogau_get_action_url( 'login' ) ) );
        exit;
    }

    if ( zenlogau_rate_limit_is_locked( 'register' ) ) {
        $message = __( 'Too many registration attempts. Please wait before trying again.', 'zen-login-authentication' );
        $form    = zenlogau()->get_form( 'register' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user_login   = sanitize_user( zenlogau_get_request_value( 'user_login', 'post' ) );
    $user_email   = sanitize_email( zenlogau_get_request_value( 'user_email', 'post' ) );
    $registration = register_new_user( $user_login, $user_email );

    if ( is_wp_error( $registration ) ) {
        zenlogau_rate_limit_bump( 'register' );

        $messages = [];
        $form     = zenlogau()->get_form( 'register' );

        foreach ( $registration->get_error_codes() as $code ) {
            $msg        = $registration->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    $new_user_id = (int) $registration;

    // Hide the front-end admin toolbar by default for users who register here.
    // This only sets the initial preference (stored as user meta) — the user can
    // re-enable "Show Toolbar when viewing site" from their profile at any time.
    if ( apply_filters( 'zenlogau_hide_admin_bar_on_register', true, $new_user_id ) ) {
        update_user_meta( $new_user_id, 'show_admin_bar_front', 'false' );
    }

    if ( zenlogau_allow_user_passwords() ) {
        $pass1 = zenlogau_get_request_value( 'user_pass1', 'post' );
        wp_set_password( $pass1, $new_user_id );
        update_user_option( $new_user_id, 'default_password_nag', false, true );
        zenlogau_send_new_user_notifications( $new_user_id, 'admin' );
    }

    zenlogau_rate_limit_clear( 'register' );
    do_action( 'zenlogau_registration_success', $new_user_id );

    if ( zenlogau_allow_auto_login() ) {
        wp_set_auth_cookie( $new_user_id );
        $new_user = get_user_by( 'id', $new_user_id );
        if ( $new_user instanceof WP_User ) {
            wp_set_current_user( $new_user_id );
            // Fire the standard login hook so integrations, the activity log, and
            // the new-device alert see this auto-login — every other login path
            // fires it, and without it those features silently miss registrations.
            do_action( 'wp_login', $new_user->user_login, $new_user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing WordPress core's own wp_login hook.
        }
        $redirect_to = $new_user instanceof WP_User
            ? zenlogau_resolve_login_redirect( $new_user, (string) zenlogau_get_request_value( 'redirect_to' ) )
            : home_url();
        if ( $is_ajax ) {
            zenlogau_send_ajax_success( [ 'redirect' => $redirect_to ] );
        }
        wp_safe_redirect( $redirect_to );
        exit;
    }

    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [
            'message' => __( 'Registration complete. Please check your email for login instructions.', 'zen-login-authentication' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'registered', '1', zenlogau_get_action_url( 'login' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Lost Password handler
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_action_lostpassword', 'zenlogau_handle_lostpassword' );

function zenlogau_handle_lostpassword(): void {
    $is_ajax = zenlogau_is_ajax_request();

    if ( zenlogau_rate_limit_is_locked( 'lostpassword' ) ) {
        $message = __( 'Too many attempts. Please wait a few minutes before trying again.', 'zen-login-authentication' );
        $form    = zenlogau()->get_form( 'lostpassword' );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    // FIX (v1.4.14): Honeypot check was missing from this handler.
    if ( zenlogau_honeypot_is_spam() ) {
        if ( $is_ajax ) {
            zenlogau_send_ajax_success( [
                'message' => __( 'Check your email for a link to reset your password.', 'zen-login-authentication' ),
            ] );
        }
        wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', zenlogau_get_action_url( 'lostpassword' ) ) );
        exit;
    }

    $result = retrieve_password(
        sanitize_text_field( zenlogau_get_request_value( 'user_login', 'post' ) )
    );

    $count_all = (bool) get_option( 'zenlogau_lostpassword_count_all', false );

    if ( is_wp_error( $result ) ) {
        zenlogau_rate_limit_bump( 'lostpassword' );

        $messages = [];
        $form     = zenlogau()->get_form( 'lostpassword' );

        foreach ( $result->get_error_codes() as $code ) {
            $msg        = $result->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }

        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    if ( $count_all ) {
        zenlogau_rate_limit_bump( 'lostpassword' );
    } else {
        zenlogau_rate_limit_clear( 'lostpassword' );
    }

    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [
            'message' => __( 'Check your email for a link to reset your password.', 'zen-login-authentication' ),
        ] );
    }

    wp_safe_redirect( add_query_arg( 'checkemail', 'confirm', zenlogau_get_action_url( 'lostpassword' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Reset Password handler
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_action_resetpass', 'zenlogau_handle_resetpass' );

function zenlogau_handle_resetpass(): void {
    $is_ajax  = zenlogau_is_ajax_request();
    $rp_key   = sanitize_text_field( zenlogau_get_request_value( 'rp_key',   'post' ) );
    $rp_login = sanitize_text_field( zenlogau_get_request_value( 'rp_login', 'post' ) );
    $pass1    = zenlogau_get_request_value( 'pass1', 'post' );
    $pass2    = zenlogau_get_request_value( 'pass2', 'post' );
    $form     = zenlogau()->get_form( 'resetpass' );

    if ( zenlogau_rate_limit_is_locked( 'resetpass' ) ) {
        $message = sprintf(
            /* translators: %d = minutes */
            __( 'Too many attempts. Please try again in %d minutes.', 'zen-login-authentication' ),
            zenlogau_get_rate_limit_window()
        );
        if ( $form ) {
            $form->add_error( 'too_many_attempts', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    $user = check_password_reset_key( $rp_key, $rp_login );

    if ( is_wp_error( $user ) ) {
        zenlogau_rate_limit_bump( 'resetpass' );
        $message = __( 'This password reset link has expired or is invalid. Please request a new one.', 'zen-login-authentication' );
        if ( $form ) {
            $form->add_error( 'invalid_key', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( empty( $pass1 ) || $pass1 !== $pass2 ) {
        $message = __( 'Passwords do not match. Please try again.', 'zen-login-authentication' );
        if ( $form ) {
            $form->add_error( 'password_mismatch', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( strlen( $pass1 ) < 8 ) {
        $message = __( 'Password must be at least 8 characters.', 'zen-login-authentication' );
        if ( $form ) {
            $form->add_error( 'password_too_short', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    if ( zenlogau_password_is_breached( $pass1 ) ) {
        $message = zenlogau_breached_password_error_message();
        if ( $form ) {
            $form->add_error( 'breached_password', $message );
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => [ wp_strip_all_tags( $message ) ] ] );
        }
        return;
    }

    zenlogau_rate_limit_clear( 'resetpass' );
    reset_password( $user, $pass1 );
    // The user just chose a password they know — re-enable the current-password
    // gate for any passwordless (Google/passkey-created) account.
    zenlogau_mark_local_password_set( $user->ID );
    do_action( 'zenlogau_password_reset', $user );

    $redirect = add_query_arg( 'password', 'changed', zenlogau_get_action_url( 'login' ) );

    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [ 'redirect' => $redirect ] );
    }

    wp_safe_redirect( $redirect );
    exit;
}

/**
 * Whether a user has a local password they would actually know.
 *
 * Accounts created through Google sign-in get a random password the user never
 * sees; such accounts are flagged with the zenlogau_no_local_password user meta
 * at creation and the flag is cleared the moment they set a real password (via
 * the Account form or a password reset). The Account form uses this to avoid
 * demanding a "current password" from someone who cannot possibly have one,
 * which would otherwise lock Google-only users out of editing their own account.
 *
 * @param WP_User $user
 * @return bool True if the user knows a local password; false if passwordless.
 */
function zenlogau_user_has_local_password( WP_User $user ): bool {
    $passwordless = '1' === (string) get_user_meta( $user->ID, 'zenlogau_no_local_password', true );
    /**
     * Filter the detected "has a local password" result.
     *
     * @param bool    $has_password
     * @param WP_User $user
     */
    return (bool) apply_filters( 'zenlogau_user_has_local_password', ! $passwordless, $user );
}

/**
 * Record that a user now has a local password they know (clears the passwordless
 * flag). Call after any path that sets a user-chosen password.
 *
 * @param int $user_id
 */
function zenlogau_mark_local_password_set( int $user_id ): void {
    delete_user_meta( $user_id, 'zenlogau_no_local_password' );
}

/* -----------------------------------------------------------------------
 * Account (edit profile) handler
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_action_account', 'zenlogau_handle_account' );

function zenlogau_handle_account(): void {
    $is_ajax = zenlogau_is_ajax_request();

    // The POST router verifies the nonce but not the login state — the same
    // router serves the public login/register forms. Profile updates are for
    // the logged-in user only; their own session is the identity being edited.
    if ( ! is_user_logged_in() ) {
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [
                'errors' => [ __( 'Your session has expired. Please log in and try again.', 'zen-login-authentication' ) ],
            ] );
        }
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }

    $user = wp_get_current_user();
    $form = zenlogau()->get_form( 'account' );

    $first_name   = sanitize_text_field( zenlogau_get_request_value( 'first_name', 'post' ) );
    $last_name    = sanitize_text_field( zenlogau_get_request_value( 'last_name', 'post' ) );
    $display_name = sanitize_text_field( zenlogau_get_request_value( 'display_name', 'post' ) );
    $user_email   = sanitize_email( zenlogau_get_request_value( 'user_email', 'post' ) );
    $pass1        = zenlogau_get_request_value( 'pass1', 'post' );
    $pass2        = zenlogau_get_request_value( 'pass2', 'post' );

    // The Account page has two cards with their own submit buttons — "Save
    // Profile" and "Update Password" — each posting its section name so only
    // that section is validated and saved. A submission with no section name
    // (an AJAX serialize that dropped the clicked button, or an older cached
    // single-button form) falls back to processing both, the prior behaviour.
    $action      = sanitize_key( zenlogau_get_request_value( 'zenlogau_account_action', 'post' ) );
    $do_profile  = ( 'profile' === $action || '' === $action );
    $do_password = ( 'password' === $action || '' === $action );

    $errors = new WP_Error();

    if ( $do_profile && '' === $display_name ) {
        $errors->add( 'empty_display_name', __( 'Please choose a display name.', 'zen-login-authentication' ) );
    }

    if ( $do_profile ) {
        if ( '' === $user_email || ! is_email( $user_email ) ) {
            $errors->add( 'invalid_email', __( 'Please enter a valid email address.', 'zen-login-authentication' ) );
        } else {
            $email_owner = email_exists( $user_email );
            if ( $email_owner && (int) $email_owner !== (int) $user->ID ) {
                $errors->add( 'email_exists', __( 'That email address is already in use by another account.', 'zen-login-authentication' ) );
            }
        }
    }

    // Password change is optional — both fields blank means "keep current".
    // Same rules as the reset-password handler: match + minimum 8 characters.
    $change_password = ( $do_password && ( '' !== $pass1 || '' !== $pass2 ) );
    if ( 'password' === $action && ! $change_password ) {
        $errors->add( 'empty_password', __( 'Please enter a new password to update it.', 'zen-login-authentication' ) );
    }
    if ( $change_password ) {
        if ( $pass1 !== $pass2 ) {
            $errors->add( 'password_mismatch', __( 'Passwords do not match. Please try again.', 'zen-login-authentication' ) );
        } elseif ( strlen( $pass1 ) < 8 ) {
            $errors->add( 'password_too_short', __( 'Password must be at least 8 characters.', 'zen-login-authentication' ) );
        } elseif ( zenlogau_password_is_breached( $pass1 ) ) {
            $errors->add( 'breached_password', zenlogau_breached_password_error_message() );
        }
    }

    // Re-authenticate sensitive changes (email or password). A public-facing
    // account form is more exposed than wp-admin (e.g. a briefly unlocked
    // browser), so changing the email or password requires the current password
    // — closing the "change email → password-reset → takeover" path. Filterable
    // off for sites whose users sign in only via Google/passkeys and may not
    // know a password. (wp_update_user() also emails the OLD address on change.)
    $email_changed   = ( $do_profile && '' !== $user_email && is_email( $user_email ) && $user_email !== $user->user_email );
    $require_current = (bool) apply_filters( 'zenlogau_account_require_current_password', true, $user );
    // Automatically waive the requirement for accounts with no local password
    // (created via Google/passkeys): they cannot supply a current password, so
    // demanding one would lock them out of their own account. Setting a password
    // here clears the flag below, after which the check applies normally.
    if ( $require_current && ! zenlogau_user_has_local_password( $user ) ) {
        $require_current = false;
    }
    if ( $require_current && ( $change_password || $email_changed ) ) {
        $current_password = (string) zenlogau_get_request_value( 'current_password', 'post' );
        if ( '' === $current_password || ! wp_check_password( $current_password, $user->user_pass, $user->ID ) ) {
            $errors->add( 'current_password', __( 'Please enter your current password to change your email address or password.', 'zen-login-authentication' ) );
        }
    }

    $errors = apply_filters( 'zenlogau_account_update_errors', $errors, $user );

    if ( $errors->has_errors() ) {
        $messages = [];
        foreach ( $errors->get_error_codes() as $code ) {
            $msg        = $errors->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    $userdata = [ 'ID' => $user->ID ];
    if ( $do_profile ) {
        // First/last may be empty — clearing them is allowed, exactly like
        // wp-admin/profile.php. The submitted display name is free text there
        // too (the dropdown is UI guidance, not a server-side whitelist).
        $userdata['first_name']   = $first_name;
        $userdata['last_name']    = $last_name;
        $userdata['display_name'] = $display_name;
        $userdata['user_email']   = $user_email;
    }
    if ( $change_password ) {
        // wp_update_user() re-sets the auth cookie when the current user's own
        // password changes, so they stay logged in while every other session
        // for the account is destroyed — same behaviour as wp-admin/profile.php.
        $userdata['user_pass'] = $pass1;
    }

    $result = wp_update_user( $userdata );

    if ( is_wp_error( $result ) ) {
        $messages = [];
        foreach ( $result->get_error_codes() as $code ) {
            $msg        = $result->get_error_message( $code );
            $messages[] = wp_strip_all_tags( $msg );
            if ( $form ) {
                $form->add_error( $code, wp_kses_post( $msg ) );
            }
        }
        if ( $is_ajax ) {
            zenlogau_send_ajax_error( [ 'errors' => $messages ] );
        }
        return;
    }

    if ( $change_password ) {
        // They now know a local password — re-enable the current-password gate.
        zenlogau_mark_local_password_set( $user->ID );
    }

    do_action( 'zenlogau_account_updated', $user->ID, $change_password );

    // PRG: redirect back to the page that hosted the form (the form self-posts
    // to it) so a refresh cannot resubmit, and so the re-rendered fields show
    // the freshly saved values instead of the stale pre-update ones.
    // Flash the success notice via a one-time user transient rather than a URL
    // parameter, so it shows once and does NOT re-appear when the page is
    // refreshed (the redirect target carries no notice flag).
    $updated_flag = '' !== $action ? $action : '1';
    set_transient( 'zenlogau_acct_notice_' . $user->ID, $updated_flag, MINUTE_IN_SECONDS );
    $redirect = zenlogau_validate_redirect( remove_query_arg( 'zenlogau_updated' ) );
    if ( '' === $redirect ) {
        $redirect = zenlogau_get_action_url( 'account' );
    }

    if ( $is_ajax ) {
        zenlogau_send_ajax_success( [ 'redirect' => $redirect ] );
    }

    wp_safe_redirect( $redirect );
    exit;
}

/**
 * Show the "saved" notice after the post-update redirect.
 * Runs after zenlogau_register_default_forms() (init priority 1).
 */
add_action( 'init', 'zenlogau_account_maybe_show_updated_notice', 20 );

function zenlogau_account_maybe_show_updated_notice(): void {
    if ( ! is_user_logged_in() ) {
        return;
    }
    // Read the one-time flash set by zenlogau_handle_account(). Consuming it
    // here means the notice shows once and never re-appears on refresh.
    $key     = 'zenlogau_acct_notice_' . get_current_user_id();
    $updated = get_transient( $key );
    if ( false === $updated || '' === $updated ) {
        return;
    }
    delete_transient( $key );
    $message = 'password' === $updated
        ? __( 'Your password has been updated.', 'zen-login-authentication' )
        : ( 'profile' === $updated
            ? __( 'Your profile has been updated.', 'zen-login-authentication' )
            : __( 'Your account has been updated.', 'zen-login-authentication' ) );
    $form = zenlogau()->get_form( 'account' );
    if ( $form ) {
        $form->add_message( 'account_updated', $message );
    }
}

/* -----------------------------------------------------------------------
 * Server-side registration password validation
 * -------------------------------------------------------------------- */
add_filter( 'registration_errors', 'zenlogau_validate_registration_password', 10, 3 );

function zenlogau_validate_registration_password( WP_Error $errors, $sanitized_user_login, $user_email ): WP_Error {
    if ( ! zenlogau_allow_user_passwords() ) {
        return $errors;
    }
    $pass1 = zenlogau_get_request_value( 'user_pass1', 'post' );
    $pass2 = zenlogau_get_request_value( 'user_pass2', 'post' );

    if ( empty( $pass1 ) || empty( $pass2 ) ) {
        $errors->add( 'empty_password', __( 'Please enter a password.', 'zen-login-authentication' ) );
    } elseif ( $pass1 !== $pass2 ) {
        $errors->add( 'password_mismatch', __( 'Passwords do not match.', 'zen-login-authentication' ) );
    } elseif ( strlen( $pass1 ) < 8 ) {
        $errors->add( 'password_too_short', __( 'Password must be at least 8 characters.', 'zen-login-authentication' ) );
    } elseif ( zenlogau_password_is_breached( $pass1 ) ) {
        $errors->add( 'breached_password', zenlogau_breached_password_error_message() );
    }

    return $errors;
}

/* -----------------------------------------------------------------------
 * Enforce login type (email-only or username-only)
 * -------------------------------------------------------------------- */
add_filter( 'authenticate', 'zenlogau_enforce_login_type', 20, 3 );

function zenlogau_enforce_login_type( $user, $username, $password ) {
    if ( $user instanceof WP_User || is_wp_error( $user ) ) {
        return $user;
    }
    if ( zenlogau_is_email_login_type() && ! is_email( $username ) ) {
        // Distinct code (not core's invalid_email) so the generic-login-errors
        // hardening keeps this helpful guidance instead of collapsing it.
        return new WP_Error(
            'zenlogau_login_type_email',
            __( 'Please log in with your email address.', 'zen-login-authentication' )
        );
    }
    if ( zenlogau_is_username_login_type() && is_email( $username ) ) {
        return new WP_Error(
            'zenlogau_login_type_username',
            __( 'Please log in with your username, not your email address.', 'zen-login-authentication' )
        );
    }
    return $user;
}

/* -----------------------------------------------------------------------
 * New user notification helpers
 * -------------------------------------------------------------------- */

function zenlogau_send_new_user_notifications( int $user_id, string $notify = 'both' ): void {
    $notify = apply_filters( 'zenlogau_new_user_notification', $notify, $user_id );
    if ( 'none' === $notify ) {
        return;
    }
    wp_new_user_notification( $user_id, null, $notify );
}

add_filter( 'wp_send_new_user_notification_to_user', 'zenlogau_maybe_suppress_user_notification', 10, 2 );

function zenlogau_maybe_suppress_user_notification( bool $send, WP_User $user ): bool {
    if ( ! zenlogau_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( zenlogau_get_request_value( 'zenlogau_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    if ( zenlogau_allow_user_passwords() ) {
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
add_filter( 'wp_send_new_user_notification_to_admin', 'zenlogau_maybe_suppress_admin_notification', 10, 2 );

function zenlogau_maybe_suppress_admin_notification( bool $send, WP_User $user ): bool {
    if ( ! zenlogau_is_post_request() ) {
        return $send;
    }
    $action = sanitize_key( zenlogau_get_request_value( 'zenlogau_action', 'post' ) );
    if ( 'register' !== $action ) {
        return $send;
    }
    if ( zenlogau_allow_user_passwords() ) {
        return false;
    }
    return $send;
}

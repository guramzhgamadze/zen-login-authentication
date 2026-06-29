<?php
/**
 * Zen Login & Authentication – Account session management
 *
 * Adds a "Sign out of all other devices" action link to the Account form,
 * shown right next to the Log Out link. Uses wp_destroy_other_sessions(), so
 * the current session stays signed in while every other active session for the
 * user (other browsers/devices) is ended — the standard way to recover from a
 * shared or compromised device.
 *
 * The control is a nonce-protected GET link, mirroring how WordPress's own
 * wp_logout_url() link works: it only appears when the account actually has
 * other active sessions, so its mere presence tells the user they are signed in
 * elsewhere.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Session Management card — rendered after the account form, alongside the
 * Passkeys and Two-Factor cards (priority 30, so it comes last).
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_after_form_account', 'zenlogau_sessions_render_card', 30 );

function zenlogau_sessions_render_card(): void {
    if ( ! is_user_logged_in() ) {
        return;
    }

    $others     = zenlogau_other_sessions_count( get_current_user_id() );
    $logout_url = add_query_arg( '_wpnonce', wp_create_nonce( 'log-out' ), zenlogau_get_action_url( 'logout' ) );

    echo '<div class="fauth fauth-sessions">';
    echo '<h3 class="fauth-sessions-title">' . esc_html__( 'Session Management', 'zen-login-authentication' ) . '</h3>';
    echo '<p class="fauth-sessions-sub">' . esc_html__( 'These are the devices currently signed in to your account.', 'zen-login-authentication' ) . '</p>';

    zenlogau_sessions_render_list( get_current_user_id() );

    echo '<p class="fauth-submit"><a class="fauth-button fauth-button-secondary" href="' . esc_url( $logout_url ) . '">'
        . esc_html__( 'Log Out', 'zen-login-authentication' ) . '</a></p>';

    // The "sign out everywhere else" action is offered only when there is
    // actually another active session to end (its presence tells the user they
    // are signed in elsewhere).
    if ( $others > 0 ) {
        $signout_url = add_query_arg(
            [
                'zenlogau_sessions_action' => 'signout_others',
                '_wpnonce'                 => wp_create_nonce( 'zenlogau_signout_others' ),
            ],
            zenlogau_get_action_url( 'account' )
        );
        echo '<p class="fauth-submit"><a class="fauth-button fauth-button-secondary" href="' . esc_url( $signout_url ) . '">'
            . esc_html__( 'Sign out of all other devices', 'zen-login-authentication' ) . '</a></p>';
        echo '<p class="fauth-description">' . esc_html__( 'This signs you out everywhere except this device.', 'zen-login-authentication' ) . '</p>';
    }

    echo '</div>';
}

/* -----------------------------------------------------------------------
 * Confirmation notice — shown above the Account form after the action runs
 * -------------------------------------------------------------------- */
add_action( 'zenlogau_before_form_account', 'zenlogau_sessions_notice' );

function zenlogau_sessions_notice(): void {
    if ( ! is_user_logged_in() ) {
        return;
    }
    $key = 'zenlogau_sessions_notice_' . get_current_user_id();
    if ( 'cleared' !== get_transient( $key ) ) {
        return;
    }
    delete_transient( $key );
    echo '<div class="fauth"><ul class="fauth-messages" role="status"><li class="fauth-message">'
        . esc_html__( 'You have been signed out of all other devices.', 'zen-login-authentication' )
        . '</li></ul></div>';
}

/* -----------------------------------------------------------------------
 * Link handler — terminate the user's other sessions
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'zenlogau_sessions_route', 1 );

function zenlogau_sessions_route(): void {
    if ( 'signout_others' !== sanitize_key( zenlogau_get_request_value( 'zenlogau_sessions_action', 'get' ) ) ) {
        return;
    }

    // Acting on the current user's own session only — login state IS the identity.
    if ( ! is_user_logged_in() ) {
        wp_safe_redirect( zenlogau_get_action_url( 'login' ) );
        exit;
    }

    // CSRF protection for a state-changing GET, same as core's logout link.
    $nonce = sanitize_key( zenlogau_get_request_value( '_wpnonce', 'get' ) );
    if ( ! wp_verify_nonce( $nonce, 'zenlogau_signout_others' ) ) {
        wp_die(
            esc_html__( 'Security check failed. Please try again.', 'zen-login-authentication' ),
            esc_html__( 'Security Error', 'zen-login-authentication' ),
            [ 'response' => 403 ]
        );
    }

    // Ends every session for this user except the one making the request.
    wp_destroy_other_sessions();
    do_action( 'zenlogau_signed_out_other_sessions', get_current_user_id() );

    // Flash the confirmation via a one-time transient (consumed on display) so
    // it shows once and does not survive a refresh.
    set_transient( 'zenlogau_sessions_notice_' . get_current_user_id(), 'cleared', MINUTE_IN_SECONDS );

    // Return to the page the link was clicked from.
    $redirect = zenlogau_validate_redirect( (string) wp_get_referer() );
    if ( '' === $redirect ) {
        $redirect = zenlogau_get_action_url( 'account' );
    }
    $redirect = remove_query_arg( [ 'zenlogau_sessions_action', '_wpnonce', 'zenlogau_sessions' ], $redirect );

    wp_safe_redirect( $redirect );
    exit;
}

/**
 * Number of active sessions for the user OTHER than the current one.
 */
function zenlogau_other_sessions_count( int $user_id ): int {
    if ( ! class_exists( 'WP_Session_Tokens' ) ) {
        return 0;
    }
    $sessions = WP_Session_Tokens::get_instance( $user_id )->get_all();
    $total    = count( $sessions );

    // The current session is one of the stored tokens, so "others" = total − 1.
    return max( 0, $total - 1 );
}

/**
 * Render the list of devices/sessions currently signed in to the account.
 */
function zenlogau_sessions_render_list( int $user_id ): void {
    if ( ! class_exists( 'WP_Session_Tokens' ) ) {
        return;
    }
    $manager  = WP_Session_Tokens::get_instance( $user_id );
    $sessions = $manager->get_all();
    if ( empty( $sessions ) ) {
        return;
    }
    $current = $manager->get( wp_get_session_token() );

    echo '<ul class="fauth-session-items">';
    foreach ( $sessions as $session ) {
        $ua    = isset( $session['ua'] ) ? (string) $session['ua'] : '';
        $ip    = isset( $session['ip'] ) ? (string) $session['ip'] : '';
        $login = ! empty( $session['login'] ) ? wp_date( get_option( 'date_format' ), (int) $session['login'] ) : '';
        // Identify the current session by matching its login time and user agent.
        $is_self = is_array( $current )
            && (int) ( $session['login'] ?? 0 ) === (int) ( $current['login'] ?? -1 )
            && ( $session['ua'] ?? '' ) === ( $current['ua'] ?? "\0" );
        $meta = array_filter( [ $ip, $login ] );

        echo '<li class="fauth-session-item">';
        echo '<span class="fauth-session-device">' . esc_html( zenlogau_sessions_device_label( $ua ) );
        if ( $is_self ) {
            echo ' <span class="fauth-session-current">' . esc_html__( 'this device', 'zen-login-authentication' ) . '</span>';
        }
        echo '</span>';
        if ( $meta ) {
            echo '<span class="fauth-session-meta">' . esc_html( implode( ' · ', $meta ) ) . '</span>';
        }
        echo '</li>';
    }
    echo '</ul>';
}

/**
 * Best-effort friendly "Browser on OS" label from a user-agent string.
 */
function zenlogau_sessions_device_label( string $ua ): string {
    if ( '' === $ua ) {
        return __( 'Unknown device', 'zen-login-authentication' );
    }
    $browser = __( 'Browser', 'zen-login-authentication' );
    foreach ( [ 'Edg' => 'Edge', 'OPR' => 'Opera', 'Chrome' => 'Chrome', 'Firefox' => 'Firefox', 'Safari' => 'Safari' ] as $needle => $name ) {
        if ( false !== strpos( $ua, $needle ) ) {
            $browser = $name;
            break;
        }
    }
    $os = '';
    foreach ( [ 'Windows' => 'Windows', 'Mac OS X' => 'macOS', 'iPhone' => 'iPhone', 'iPad' => 'iPad', 'Android' => 'Android', 'Linux' => 'Linux' ] as $needle => $name ) {
        if ( false !== strpos( $ua, $needle ) ) {
            $os = $name;
            break;
        }
    }
    if ( '' === $os ) {
        return $browser;
    }
    /* translators: 1: browser name, 2: operating system. */
    return sprintf( __( '%1$s on %2$s', 'zen-login-authentication' ), $browser, $os );
}

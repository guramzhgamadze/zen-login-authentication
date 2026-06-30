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

    // The "sign out everywhere else" action is offered only when there is
    // actually another active session to end (its presence tells the user they
    // are signed in elsewhere).
    $signout_url = '';
    if ( $others > 0 ) {
        $signout_url = add_query_arg(
            [
                'zenlogau_sessions_action' => 'signout_others',
                '_wpnonce'                 => wp_create_nonce( 'zenlogau_signout_others' ),
            ],
            zenlogau_get_action_url( 'account' )
        );
    }

    // Log Out / Sign-out-others render as ACTION LINKS (not buttons). They share
    // the plugin's .fauth-link-button class so they inherit link styling and are
    // covered by the Elementor "Action Links" style controls; .fauth-session-action
    // lets those controls target the session links specifically.
    echo '<p class="fauth-links fauth-sessions-links">';
    echo '<a class="fauth-link-button fauth-session-action" href="' . esc_url( $logout_url ) . '">'
        . esc_html__( 'Log Out', 'zen-login-authentication' ) . '</a>';
    if ( '' !== $signout_url ) {
        echo '<span class="fauth-links-sep" aria-hidden="true"> &middot; </span>';
        echo '<a class="fauth-link-button fauth-session-action" href="' . esc_url( $signout_url ) . '">'
            . esc_html__( 'Sign out of all other devices', 'zen-login-authentication' ) . '</a>';
    }
    echo '</p>';
    if ( '' !== $signout_url ) {
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

    // Collapse repeated logins from the same device/browser: key by user agent
    // and keep only the most recent session for each, so the list shows one row
    // per device instead of one per login.
    $by_device = [];
    foreach ( $sessions as $session ) {
        $ua  = isset( $session['ua'] ) ? (string) $session['ua'] : '';
        $key = '' !== $ua ? $ua : '__unknown__';
        if ( ! isset( $by_device[ $key ] ) || (int) ( $session['login'] ?? 0 ) > (int) ( $by_device[ $key ]['login'] ?? 0 ) ) {
            $by_device[ $key ] = $session;
        }
    }
    // Most recently used device first.
    uasort( $by_device, static function ( $a, $b ): int {
        return (int) ( $b['login'] ?? 0 ) <=> (int) ( $a['login'] ?? 0 );
    } );

    $current_ua = is_array( $current ) ? (string) ( $current['ua'] ?? "\0" ) : "\0";

    echo '<ul class="fauth-session-items">';
    foreach ( $by_device as $session ) {
        $ua      = isset( $session['ua'] ) ? (string) $session['ua'] : '';
        $ip      = isset( $session['ip'] ) ? (string) $session['ip'] : '';
        $login   = ! empty( $session['login'] ) ? wp_date( get_option( 'date_format' ), (int) $session['login'] ) : '';
        $browser = zenlogau_sessions_browser_label( $ua );
        // The current device is the group whose user agent matches this session.
        $is_self = ( $ua === $current_ua );
        $meta    = array_filter( [ $browser, $ip, $login ] );

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
 * Best-effort recognisable device name from a user-agent string. A website can't
 * read the OS-given device name (privacy), so we lead with the platform — the
 * closest thing to a name. The browser is shown separately in the meta line.
 */
function zenlogau_sessions_device_label( string $ua ): string {
    if ( '' === $ua ) {
        return __( 'Unknown device', 'zen-login-authentication' );
    }
    // Order matters: iPhone/iPad UAs also contain "Mac OS X"; Android and
    // Chromebook UAs also contain "Linux" — so the more specific tokens win.
    $devices = [
        'iPhone'   => __( 'iPhone', 'zen-login-authentication' ),
        'iPad'     => __( 'iPad', 'zen-login-authentication' ),
        'CrOS'     => __( 'Chromebook', 'zen-login-authentication' ),
        'Android'  => __( 'Android device', 'zen-login-authentication' ),
        'Mac OS X' => __( 'Mac', 'zen-login-authentication' ),
        'Windows'  => __( 'Windows PC', 'zen-login-authentication' ),
        'Linux'    => __( 'Linux PC', 'zen-login-authentication' ),
    ];
    foreach ( $devices as $needle => $name ) {
        if ( false !== strpos( $ua, $needle ) ) {
            return $name;
        }
    }
    return __( 'Unknown device', 'zen-login-authentication' );
}

/**
 * Best-effort browser name from a user-agent string (shown in the meta line).
 */
function zenlogau_sessions_browser_label( string $ua ): string {
    // Order matters: Edge and Opera UAs also contain "Chrome"; Chrome's also
    // contains "Safari" — so check the more specific tokens first.
    foreach ( [ 'Edg' => 'Edge', 'OPR' => 'Opera', 'Chrome' => 'Chrome', 'Firefox' => 'Firefox', 'Safari' => 'Safari' ] as $needle => $name ) {
        if ( false !== strpos( $ua, $needle ) ) {
            return $name;
        }
    }
    return '';
}

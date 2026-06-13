<?php
/**
 * Zen Login & Authentication – Multisite Hooks
 *
 * The plugin declares Network: true but previously had zero multisite code.
 * This file handles the multisite registration flow correctly.
 *
 * On multisite, user registration goes through wp-signup.php which FAUTH
 * now rewrites to the 'register' action URL via fauth_filter_site_url().
 * The signup/activation emails contain links that must resolve correctly,
 * so we intercept the signup URL and the activation URL filters.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

if ( ! is_multisite() ) {
    return;
}

/* -----------------------------------------------------------------------
 * Rewrite wp-signup.php links to the frontend register page
 * -------------------------------------------------------------------- */
add_filter( 'signup_url', 'fauth_ms_filter_signup_url', 10 );

function fauth_ms_filter_signup_url( string $url ): string {
    if ( fauth_is_elementor_context() ) {
        return $url;
    }
    if ( ! fauth()->get_action( 'register' ) ) {
        return $url;
    }
    return fauth_get_action_url( 'register', true );
}

/* -----------------------------------------------------------------------
 * Redirect network-level wp-activate.php to the frontend login page
 * after successful activation, with a success notice.
 * -------------------------------------------------------------------- */
add_filter( 'wpmu_activate_redirect', 'fauth_ms_activation_redirect', 10 );

function fauth_ms_activation_redirect( string $location ): string {
    return add_query_arg( 'activated', '1', fauth_get_action_url( 'login', true ) );
}

/* -----------------------------------------------------------------------
 * Show an activation-success notice on the login page
 * -------------------------------------------------------------------- */
add_action( 'init', 'fauth_ms_maybe_show_activation_notice' );

function fauth_ms_maybe_show_activation_notice(): void {
    // BUG-4 fix: sanitize the GET param and check for the specific value '1'
    // to avoid false triggers from other plugins using the same param name.
    $activated = isset( $_GET['activated'] ) && is_string( $_GET['activated'] ) ? sanitize_key( wp_unslash( $_GET['activated'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display flag on the signup-activation landing page; shows a notice, changes no state.
    if ( '1' !== $activated ) {
        return;
    }
    $form = fauth()->get_form( 'login' );
    if ( $form ) {
        $form->add_message(
            'ms_activated',
            __( 'Your account has been activated. You can now log in.', 'zen-login-authentication' )
        );
    }
}

/* -----------------------------------------------------------------------
 * On network-activated installations, make sure each sub-site's options
 * are seeded with defaults the first time the plugin runs there.
 *
 * BUG-3 fix: 'wpmu_new_blog' was deprecated in WP 5.1. The correct hook
 * is 'wp_initialize_site' with signature (WP_Site $new_site, array $args).
 * wpmu_new_blog still fires for back-compat but is scheduled for removal.
 * -------------------------------------------------------------------- */
add_action( 'wp_initialize_site', 'fauth_ms_new_blog_defaults', 10, 1 );

function fauth_ms_new_blog_defaults( WP_Site $new_site ): void {
    switch_to_blog( (int) $new_site->blog_id );
    if ( false === get_option( 'fauth_version' ) ) {
        add_option( 'fauth_rate_limit',        10   );
        add_option( 'fauth_rate_limit_window', 15   );
        add_option( 'fauth_use_ajax',          false );
        add_option( 'fauth_user_passwords',    false );
        add_option( 'fauth_auto_login',        false );
        add_option( 'fauth_honeypot',          true  );
        add_option( 'fauth_login_type',        'default' );
        add_option( 'fauth_use_permalinks',    true  );
        add_option( 'fauth_version',           FAUTH_VERSION );
    }
    restore_current_blog();
}

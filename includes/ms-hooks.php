<?php
/**
 * Frontend Auth – Multisite Hooks
 *
 * The plugin declares Network: true but previously had zero multisite code.
 * This file handles the multisite registration flow correctly.
 *
 * On multisite, user registration goes through wp-signup.php which WPFA
 * now rewrites to the 'register' action URL via wpfa_filter_site_url().
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
add_filter( 'signup_url', 'wpfa_ms_filter_signup_url', 10 );

function wpfa_ms_filter_signup_url( string $url ): string {
    if ( wpfa_is_elementor_context() ) {
        return $url;
    }
    if ( ! wpfa()->get_action( 'register' ) ) {
        return $url;
    }
    return wpfa_get_action_url( 'register', true );
}

/* -----------------------------------------------------------------------
 * Redirect network-level wp-activate.php to the frontend login page
 * after successful activation, with a success notice.
 * -------------------------------------------------------------------- */
add_filter( 'wpmu_activate_redirect', 'wpfa_ms_activation_redirect', 10 );

function wpfa_ms_activation_redirect( string $location ): string {
    return add_query_arg( 'activated', '1', wpfa_get_action_url( 'login', true ) );
}

/* -----------------------------------------------------------------------
 * Show an activation-success notice on the login page
 * -------------------------------------------------------------------- */
add_action( 'init', 'wpfa_ms_maybe_show_activation_notice' );

function wpfa_ms_maybe_show_activation_notice(): void {
    // BUG-4 fix: sanitize the GET param and check for the specific value '1'
    // to avoid false triggers from other plugins using the same param name.
    $activated = isset( $_GET['activated'] ) && is_string( $_GET['activated'] ) ? sanitize_key( wp_unslash( $_GET['activated'] ) ) : '';
    if ( '1' !== $activated ) {
        return;
    }
    $form = wpfa()->get_form( 'login' );
    if ( $form ) {
        $form->add_message(
            'ms_activated',
            __( 'Your account has been activated. You can now log in.', 'frontend-auth' )
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
add_action( 'wp_initialize_site', 'wpfa_ms_new_blog_defaults', 10, 1 );

function wpfa_ms_new_blog_defaults( WP_Site $new_site ): void {
    switch_to_blog( (int) $new_site->blog_id );
    if ( false === get_option( 'wpfa_version' ) ) {
        add_option( 'wpfa_rate_limit',        10   );
        add_option( 'wpfa_rate_limit_window', 15   );
        add_option( 'wpfa_use_ajax',          false );
        add_option( 'wpfa_user_passwords',    false );
        add_option( 'wpfa_auto_login',        false );
        add_option( 'wpfa_honeypot',          true  );
        add_option( 'wpfa_login_type',        'default' );
        add_option( 'wpfa_use_permalinks',    true  );
        add_option( 'wpfa_version',           WPFA_VERSION );
    }
    restore_current_blog();
}

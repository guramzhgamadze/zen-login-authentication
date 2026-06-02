<?php
/**
 * WP Frontend Auth – Uninstall
 *
 * Runs when the plugin is deleted (not just deactivated).
 * Removes all plugin options and only auto-created pages that have
 * never been edited by the user (no Elementor data, no post content).
 *
 * @package WP_Frontend_Auth
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$options = [
    'wpfa_version',
    'wpfa_rate_limit',
    'wpfa_rate_limit_window',
    'wpfa_use_ajax',
    'wpfa_user_passwords',
    'wpfa_auto_login',
    'wpfa_honeypot',
    'wpfa_login_type',
    'wpfa_use_permalinks',
    'wpfa_slug_login',
    'wpfa_slug_logout',
    'wpfa_slug_register',
    'wpfa_slug_lostpassword',
    'wpfa_slug_resetpass',
];

$page_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];

if ( is_multisite() ) {
    $sites = get_sites( [ 'fields' => 'ids', 'number' => 0 ] );
    foreach ( $sites as $site_id ) {
        switch_to_blog( $site_id );
        wpfa_uninstall_site( $options, $page_actions );
        restore_current_blog();
    }
} else {
    wpfa_uninstall_site( $options, $page_actions );
}

function wpfa_uninstall_site( array $options, array $page_actions ): void {
    global $wpdb;

    foreach ( $options as $option ) {
        delete_option( $option );
    }

    // Catch any orphaned wpfa_slug_* options.
    $like     = $wpdb->esc_like( 'wpfa_slug_' ) . '%';
    $orphaned = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );
    foreach ( $orphaned as $opt ) {
        delete_option( $opt );
    }

    // Delete auto-created pages — but ONLY if:
    //   1. The plugin created it (has _wpfa_auto_created meta).
    //   2. The user has never edited it in Elementor (no _elementor_edit_mode meta).
    //   3. The page has no post_content (user never added anything manually).
    // If any of these conditions fail, we leave the page intact and just
    // remove our stored page ID option — the user owns that page now.
    foreach ( $page_actions as $action ) {
        $opt     = "wpfa_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );

        if ( $page_id ) {
            $post        = get_post( $page_id );
            $is_auto     = (bool) get_post_meta( $page_id, '_wpfa_auto_created', true );
            $has_el      = (bool) get_post_meta( $page_id, '_elementor_edit_mode', true );
            $has_content = $post instanceof WP_Post && '' !== trim( $post->post_content );

            if ( $is_auto && ! $has_el && ! $has_content ) {
                // Truly untouched auto-created page — safe to delete.
                wp_delete_post( $page_id, true );
            }
            // Whether deleted or not, always remove our stored reference.
        }

        delete_option( $opt );
    }

    // Per-action rate limit options (v1.4.18).
    foreach ( [ 'login', 'register', 'lostpassword', 'resetpass' ] as $action ) {
        delete_option( "wpfa_rl_enabled_{$action}" );
        delete_option( "wpfa_rl_max_{$action}" );
    }
    delete_option( 'wpfa_lostpassword_count_all' );
}

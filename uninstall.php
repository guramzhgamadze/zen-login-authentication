<?php
/**
 * Frontend Auth – Uninstall
 *
 * Runs when the plugin is deleted (not just deactivated).
 * Removes all plugin options, and deletes only the pages the plugin itself
 * auto-created that the user never edited (no Elementor data, no content).
 * Adopted pages (pre-existing pages the plugin reused) and edited pages are
 * always kept.
 *
 * @package Frontend_Auth
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
    'wpfa_subscriber_redirect',
    'wpfa_google_enabled',
    'wpfa_google_client_id',
    'wpfa_google_client_secret',
    'wpfa_google_allow_registration',
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

    // Delete pages the plugin created, but ONLY when they are still untouched:
    //   1. Created by the plugin    — has _wpfa_auto_created meta. Adopted pages
    //      (pre-existing pages the plugin merely reused) never get this flag, so
    //      they are always preserved.
    //   2. Never edited in Elementor — no _elementor_edit_mode meta.
    //   3. Empty                     — post_content is blank.
    // If any condition fails the page is kept. Either way the stored reference is
    // removed. These guards are what prevent the data loss seen in older builds,
    // which force-deleted every stored page — including ones edited in Elementor.
    foreach ( $page_actions as $action ) {
        $opt     = "wpfa_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );

        if ( $page_id ) {
            $post        = get_post( $page_id );
            $is_auto     = (bool) get_post_meta( $page_id, '_wpfa_auto_created', true );
            $has_el      = (bool) get_post_meta( $page_id, '_elementor_edit_mode', true );
            $has_content = $post instanceof WP_Post && '' !== trim( $post->post_content );

            if ( $is_auto && ! $has_el && ! $has_content ) {
                wp_delete_post( $page_id, true );
            }
        }

        delete_option( $opt );
    }

    // Per-action rate limit options (v1.4.18).
    foreach ( [ 'login', 'register', 'lostpassword', 'resetpass' ] as $action ) {
        delete_option( "wpfa_rl_enabled_{$action}" );
        delete_option( "wpfa_rl_max_{$action}" );
    }
    delete_option( 'wpfa_lostpassword_count_all' );

    // Google account links (v1.5.0). delete_all = true removes the meta for
    // every user; harmless to repeat per-site on multisite (users are global).
    delete_metadata( 'user', 0, 'wpfa_google_sub', '', true );
}

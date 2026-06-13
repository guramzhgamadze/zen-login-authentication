<?php
/**
 * Zen Login & Authentication – Uninstall
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

$fauth_options = [
    'fauth_version',
    'fauth_rate_limit',
    'fauth_rate_limit_window',
    'fauth_use_ajax',
    'fauth_user_passwords',
    'fauth_auto_login',
    'fauth_honeypot',
    'fauth_login_type',
    'fauth_use_permalinks',
    'fauth_subscriber_redirect',
    'fauth_google_enabled',
    'fauth_google_client_id',
    'fauth_google_client_secret',
    'fauth_google_allow_registration',
    'fauth_activity_log_enabled',
    'fauth_activity_retention_days',
    'fauth_activity_db_version',
    'fauth_slug_login',
    'fauth_slug_logout',
    'fauth_slug_register',
    'fauth_slug_lostpassword',
    'fauth_slug_resetpass',
    'fauth_slug_account',
];

$fauth_page_actions = [ 'login', 'register', 'lostpassword', 'resetpass', 'account' ];

if ( is_multisite() ) {
    $fauth_sites = get_sites( [ 'fields' => 'ids', 'number' => 0 ] );
    foreach ( $fauth_sites as $fauth_site_id ) {
        switch_to_blog( $fauth_site_id );
        fauth_uninstall_site( $fauth_options, $fauth_page_actions );
        restore_current_blog();
    }
} else {
    fauth_uninstall_site( $fauth_options, $fauth_page_actions );
}

function fauth_uninstall_site( array $options, array $page_actions ): void {
    global $wpdb;

    foreach ( $options as $option ) {
        delete_option( $option );
    }

    // Catch any orphaned fauth_slug_* options.
    // phpcs:disable WordPress.DB.DirectDatabaseQuery -- option-table maintenance at uninstall; no API exists for LIKE deletes and caching is irrelevant here.
    $like     = $wpdb->esc_like( 'fauth_slug_' ) . '%';
    $orphaned = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery
    foreach ( $orphaned as $opt ) {
        delete_option( $opt );
    }

    // Delete pages the plugin created, but ONLY when they are still untouched:
    //   1. Created by the plugin    — has _fauth_auto_created meta. Adopted pages
    //      (pre-existing pages the plugin merely reused) never get this flag, so
    //      they are always preserved.
    //   2. Never edited in Elementor — no _elementor_edit_mode meta.
    //   3. Empty                     — post_content is blank.
    // If any condition fails the page is kept. Either way the stored reference is
    // removed. These guards are what prevent the data loss seen in older builds,
    // which force-deleted every stored page — including ones edited in Elementor.
    foreach ( $page_actions as $action ) {
        $opt     = "fauth_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );

        if ( $page_id ) {
            $post        = get_post( $page_id );
            $is_auto     = (bool) get_post_meta( $page_id, '_fauth_auto_created', true );
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
        delete_option( "fauth_rl_enabled_{$action}" );
        delete_option( "fauth_rl_max_{$action}" );
    }
    delete_option( 'fauth_lostpassword_count_all' );

    // Per-widget availability toggles (v1.6.2).
    foreach ( [ 'login', 'register', 'lostpassword', 'resetpass', 'account' ] as $action ) {
        delete_option( "fauth_widget_enabled_{$action}" );
    }

    // Login-activity log table + its cached summary (v1.7.0).
    delete_transient( 'fauth_activity_summary' );
    // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- dropping the plugin's own table at uninstall; the name derives from $wpdb->prefix (never user input) and no core API exists.
    $fauth_activity_table = $wpdb->prefix . 'fauth_activity';
    $wpdb->query( "DROP TABLE IF EXISTS {$fauth_activity_table}" );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

    // Google account links (v1.5.0). delete_all = true removes the meta for
    // every user; harmless to repeat per-site on multisite (users are global).
    delete_metadata( 'user', 0, 'fauth_google_sub', '', true );

    // Legacy pre-release "wpfa" prefix leftovers, for installs that never ran
    // the wpfa -> fauth migration before being uninstalled.
    // phpcs:disable WordPress.DB.DirectDatabaseQuery -- uninstall-time cleanup of legacy rows; no API exists for LIKE deletes.
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
         WHERE option_name LIKE 'wpfa\\_%'
            OR option_name LIKE 'widget\\_wpfa\\_%'
            OR option_name LIKE '\\_transient\\_wpfa\\_%'
            OR option_name LIKE '\\_transient\\_timeout\\_wpfa\\_%'"
    );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery
    delete_metadata( 'user', 0, 'wpfa_google_sub', '', true );
}

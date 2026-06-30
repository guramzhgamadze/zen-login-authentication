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

$zenlogau_options = [
    'zenlogau_version',
    'zenlogau_rate_limit',
    'zenlogau_rate_limit_window',
    'zenlogau_use_ajax',
    'zenlogau_user_passwords',
    'zenlogau_auto_login',
    'zenlogau_honeypot',
    'zenlogau_login_type',
    'zenlogau_use_permalinks',
    'zenlogau_subscriber_redirect',
    'zenlogau_google_enabled',
    'zenlogau_google_client_id',
    'zenlogau_google_client_secret',
    'zenlogau_google_allow_registration',
    'zenlogau_activity_log_enabled',
    'zenlogau_activity_retention_days',
    'zenlogau_activity_db_version',
    'zenlogau_harden_enum',
    'zenlogau_generic_login_errors',
    'zenlogau_block_breached',
    'zenlogau_disable_xmlrpc',
    'zenlogau_turnstile_enabled',
    'zenlogau_turnstile_site_key',
    'zenlogau_turnstile_secret_key',
    'zenlogau_turnstile_login',
    'zenlogau_turnstile_register',
    'zenlogau_turnstile_lostpassword',
    'zenlogau_2fa_feature',
    'zenlogau_2fa_trusted_devices',
    'zenlogau_account_throttle',
    'zenlogau_new_device_email',
    'zenlogau_new_device_email_body',
    'zenlogau_passkeys_feature',
    'zenlogau_slug_login',
    'zenlogau_slug_logout',
    'zenlogau_slug_register',
    'zenlogau_slug_lostpassword',
    'zenlogau_slug_resetpass',
    'zenlogau_slug_account',
];

$zenlogau_page_actions = [ 'login', 'register', 'lostpassword', 'resetpass', 'account' ];

if ( is_multisite() ) {
    $zenlogau_sites = get_sites( [ 'fields' => 'ids', 'number' => 0 ] );
    foreach ( $zenlogau_sites as $zenlogau_site_id ) {
        switch_to_blog( $zenlogau_site_id );
        zenlogau_uninstall_site( $zenlogau_options, $zenlogau_page_actions );
        restore_current_blog();
    }
} else {
    zenlogau_uninstall_site( $zenlogau_options, $zenlogau_page_actions );
}

function zenlogau_uninstall_site( array $options, array $page_actions ): void {
    global $wpdb;

    foreach ( $options as $option ) {
        delete_option( $option );
    }

    // Catch any orphaned zenlogau_slug_* options.
    // phpcs:disable WordPress.DB.DirectDatabaseQuery -- option-table maintenance at uninstall; no API exists for LIKE deletes and caching is irrelevant here.
    $like     = $wpdb->esc_like( 'zenlogau_slug_' ) . '%';
    $orphaned = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery
    foreach ( $orphaned as $opt ) {
        delete_option( $opt );
    }

    // Delete pages the plugin created, but ONLY when they are still untouched:
    //   1. Created by the plugin    — has _zenlogau_auto_created meta. Adopted pages
    //      (pre-existing pages the plugin merely reused) never get this flag, so
    //      they are always preserved.
    //   2. Never edited in Elementor — no _elementor_edit_mode meta.
    //   3. Empty                     — post_content is blank.
    // If any condition fails the page is kept. Either way the stored reference is
    // removed. These guards are what prevent the data loss seen in older builds,
    // which force-deleted every stored page — including ones edited in Elementor.
    foreach ( $page_actions as $action ) {
        $opt     = "zenlogau_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );

        if ( $page_id ) {
            $post        = get_post( $page_id );
            $is_auto     = (bool) get_post_meta( $page_id, '_zenlogau_auto_created', true );
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
        delete_option( "zenlogau_rl_enabled_{$action}" );
        delete_option( "zenlogau_rl_max_{$action}" );
    }
    delete_option( 'zenlogau_lostpassword_count_all' );

    // Per-widget availability toggles (v1.6.2).
    foreach ( [ 'login', 'register', 'lostpassword', 'resetpass', 'account' ] as $action ) {
        delete_option( "zenlogau_widget_enabled_{$action}" );
    }

    // Login-activity log table + its cached summary (v1.7.0).
    delete_transient( 'zenlogau_activity_summary' );
    wp_clear_scheduled_hook( 'zenlogau_activity_prune_event' );
    // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- dropping the plugin's own table at uninstall; the name derives from $wpdb->prefix (never user input) and no core API exists.
    $zenlogau_activity_table = $wpdb->prefix . 'zenlogau_activity';
    $wpdb->query( "DROP TABLE IF EXISTS {$zenlogau_activity_table}" );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

    // Google account links (v1.5.0). delete_all = true removes the meta for
    // every user; harmless to repeat per-site on multisite (users are global).
    delete_metadata( 'user', 0, 'zenlogau_google_sub', '', true );

    // Indexed Google-sub reverse-lookup keys (v2.2.0): zenlogau_gsub_<hash>.
    // The key embeds a per-sub hash, so a LIKE delete clears them all.
    // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- uninstall-time LIKE cleanup of the plugin's own user meta; no core API does prefix-based meta deletion.
    $wpdb->query(
        "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'zenlogau\\_gsub\\_%'"
    );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

    // Two-factor authentication per-user data (v2.0.0; +trusted devices v2.2.0).
    foreach ( [ 'zenlogau_2fa_secret', 'zenlogau_2fa_pending_secret', 'zenlogau_2fa_enabled', 'zenlogau_2fa_recovery', 'zenlogau_2fa_last_step', 'zenlogau_2fa_trusted' ] as $zenlogau_2fa_meta ) {
        delete_metadata( 'user', 0, $zenlogau_2fa_meta, '', true );
    }

    // "No local password" flag for Google-only accounts (v2.2.0).
    delete_metadata( 'user', 0, 'zenlogau_no_local_password', '', true );

    // Known-device list for new-device login alerts (v2.1.0).
    delete_metadata( 'user', 0, 'zenlogau_known_devices', '', true );

    // Registered passkeys / WebAuthn credentials (v2.1.0).
    delete_metadata( 'user', 0, 'zenlogau_passkeys', '', true );

    // Active plugin transients (rate-limit buckets + their _ts companions,
    // OAuth/2FA/passkey challenges, breached-password cache). No core API does
    // prefix-based transient deletion; most are short-lived, but a clean
    // uninstall should remove them. Object-cache transients aren't stored in
    // the options table and expire on their own.
    // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- uninstall-time LIKE cleanup of the plugin's own transients; no core API exists.
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
         WHERE option_name LIKE '\\_transient\\_zenlogau\\_%'
            OR option_name LIKE '\\_transient\\_timeout\\_zenlogau\\_%'"
    );
    // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

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

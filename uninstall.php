<?php
/**
 * WP Frontend Auth – Uninstall
 *
 * Runs when the plugin is deleted (not just deactivated).
 * Removes all plugin options and the stored page-ID references, but never
 * deletes the auth pages themselves — those are user-owned content. Users who
 * want the auto-created pages removed can use the "Delete Auto-Created Pages"
 * button on the settings screen before deleting the plugin.
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
    'wpfa_subscriber_redirect',
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

    // Pages are NEVER deleted on uninstall — we only remove the plugin's stored
    // page-ID references. Deleting pages here previously caused data loss when a
    // user "replaced" the plugin via deactivate → delete → reinstall: the delete
    // step ran uninstall.php and force-removed their auth pages, including ones
    // built in Elementor. Auth pages are user-owned content; a user who genuinely
    // wants the auto-created pages gone can use the "Delete Auto-Created Pages"
    // button on the settings screen *before* deleting the plugin.
    foreach ( $page_actions as $action ) {
        delete_option( "wpfa_page_id_{$action}" );
    }

    // Per-action rate limit options (v1.4.18).
    foreach ( [ 'login', 'register', 'lostpassword', 'resetpass' ] as $action ) {
        delete_option( "wpfa_rl_enabled_{$action}" );
        delete_option( "wpfa_rl_max_{$action}" );
    }
    delete_option( 'wpfa_lostpassword_count_all' );
}

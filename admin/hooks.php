<?php
/**
 * Zen Login & Authentication – Admin Hooks
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/**
 * Add a "Settings" link on the plugins list page.
 */
add_filter( 'plugin_action_links_' . plugin_basename( ZENLOGAU_PATH . 'zen-login-authentication.php' ), 'zenlogau_plugin_action_links' );

function zenlogau_plugin_action_links( array $links ): array {
    array_unshift(
        $links,
        '<a href="' . esc_url( admin_url( 'admin.php?page=zen-login-authentication' ) ) . '">'
            . esc_html__( 'Settings', 'zen-login-authentication' )
        . '</a>'
    );
    return $links;
}

/**
 * When a slug option is saved:
 *  1. Update the real WP page's post_name to match the new slug.
 *  2. Flush rewrite rules so new URL takes effect immediately.
 *
 * Without step 1, zenlogau_get_action_url() returns get_permalink() of the
 * real page — which still has the OLD slug. The option value is ignored.
 *
 * Hook signature: update_option_{option}( $old_value, $new_value, $option )
 */
add_action( 'update_option_zenlogau_slug_login',        'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_slug_logout',       'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_slug_register',     'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_slug_lostpassword', 'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_slug_resetpass',    'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_slug_account',      'zenlogau_admin_on_slug_change', 10, 3 );
add_action( 'update_option_zenlogau_use_permalinks',    'zenlogau_admin_on_slug_change', 10, 3 );

function zenlogau_admin_on_slug_change( $old_value, $new_value, $option ): void {
    // Extract the action name from the option: "zenlogau_slug_lostpassword" → "lostpassword"
    $action = str_replace( 'zenlogau_slug_', '', $option );

    // Update the real page's slug if one exists for this action.
    $page_id = zenlogau_get_page_id( $action );
    if ( $page_id && get_post( $page_id ) instanceof WP_Post ) {
        $new_slug = sanitize_title( $new_value );
        if ( '' !== $new_slug ) {
            wp_update_post( [
                'ID'        => $page_id,
                'post_name' => $new_slug,
            ] );
        }
    }

    zenlogau_flush_rewrite_rules();
}

/* -----------------------------------------------------------------------
 * Admin CSS — enqueued (not inline) per WordPress.org guidelines.
 * Loads on the plugin's settings page and on the dashboard (for the
 * Login Activity widget). Replaces the former inline <style> blocks.
 * -------------------------------------------------------------------- */
add_action( 'admin_enqueue_scripts', 'zenlogau_admin_enqueue_assets' );

function zenlogau_admin_enqueue_assets( $hook_suffix ): void {
    // toplevel_page_{slug} is this plugin's settings screen; index.php is the dashboard.
    $screens = [ 'toplevel_page_zen-login-authentication', 'index.php' ];
    if ( ! in_array( (string) $hook_suffix, $screens, true ) ) {
        return;
    }
    wp_enqueue_style(
        'zen-login-authentication-admin',
        ZENLOGAU_URL . 'assets/styles/frontend-auth-admin.css',
        [],
        ZENLOGAU_VERSION
    );
}

/* -----------------------------------------------------------------------
 * Fix #11 — Enqueue editor-only CSS for the Reset Password preview wrapper.
 * Replaces hardcoded hex colours with CSS-variable-driven classes.
 * -------------------------------------------------------------------- */
add_action( 'elementor/editor/after_enqueue_styles', 'zenlogau_enqueue_elementor_editor_styles' );

function zenlogau_enqueue_elementor_editor_styles(): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    wp_enqueue_style(
        'zen-login-authentication-editor',
        ZENLOGAU_URL . 'assets/styles/frontend-auth-editor.css',
        [],
        ZENLOGAU_VERSION
    );
}

/* -----------------------------------------------------------------------
 * Manual page creation / deletion handlers
 *
 * FIX: Pages are no longer auto-created on activation. These admin-post
 * handlers give the user explicit manual control via the settings page.
 * -------------------------------------------------------------------- */

add_action( 'admin_post_zenlogau_create_pages', 'zenlogau_admin_handle_create_pages' );

function zenlogau_admin_handle_create_pages(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'zen-login-authentication' ), 403 );
    }
    check_admin_referer( 'zenlogau_create_pages', 'zenlogau_pages_nonce' );
    zenlogau_create_action_pages();
    zenlogau_flush_rewrite_rules();
    wp_safe_redirect( add_query_arg( 'zenlogau_notice', 'pages_created', admin_url( 'admin.php?page=zen-login-authentication' ) ) );
    exit;
}

add_action( 'admin_post_zenlogau_delete_pages', 'zenlogau_admin_handle_delete_pages' );

function zenlogau_admin_handle_delete_pages(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'zen-login-authentication' ), 403 );
    }
    check_admin_referer( 'zenlogau_delete_pages', 'zenlogau_pages_nonce' );

    foreach ( array_keys( zenlogau_get_page_actions() ) as $action ) {
        $opt     = "zenlogau_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );
        if ( ! $page_id ) {
            continue;
        }
        // Only delete pages that the plugin auto-created (not user-adopted pages).
        // zenlogau_create_action_pages() sets this meta flag on every page it inserts.
        if ( get_post_meta( $page_id, '_zenlogau_auto_created', true ) ) {
            wp_delete_post( $page_id, true );
        }
        delete_option( $opt );
    }

    zenlogau_flush_rewrite_rules();
    wp_safe_redirect( add_query_arg( 'zenlogau_notice', 'pages_deleted', admin_url( 'admin.php?page=zen-login-authentication' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Admin notices for page management actions
 * -------------------------------------------------------------------- */
add_action( 'admin_notices', 'zenlogau_admin_page_notices' );

function zenlogau_admin_page_notices(): void {
    if ( ! isset( $_GET['zenlogau_notice'] ) || ! is_string( $_GET['zenlogau_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
        return;
    }
    $notice = sanitize_key( wp_unslash( $_GET['zenlogau_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
    $messages = [
        'pages_created'    => __( 'Auth pages have been created successfully.', 'zen-login-authentication' ),
        'pages_deleted'    => __( 'Auto-created auth pages have been deleted.', 'zen-login-authentication' ),
        'activity_cleared' => __( 'Login activity log cleared.', 'zen-login-authentication' ),
    ];
    if ( isset( $messages[ $notice ] ) ) {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $messages[ $notice ] ) . '</p></div>';
    }
}

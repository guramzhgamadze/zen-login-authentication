<?php
/**
 * WP Frontend Auth – Admin Hooks
 *
 * @package WP_Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/**
 * Add a "Settings" link on the plugins list page.
 */
add_filter( 'plugin_action_links_wp-frontend-auth/wp-frontend-auth.php', 'wpfa_plugin_action_links' );

function wpfa_plugin_action_links( array $links ): array {
    array_unshift(
        $links,
        '<a href="' . esc_url( admin_url( 'admin.php?page=wp-frontend-auth' ) ) . '">'
            . esc_html__( 'Settings', 'wp-frontend-auth' )
        . '</a>'
    );
    return $links;
}

/**
 * When a slug option is saved:
 *  1. Update the real WP page's post_name to match the new slug.
 *  2. Flush rewrite rules so new URL takes effect immediately.
 *
 * Without step 1, wpfa_get_action_url() returns get_permalink() of the
 * real page — which still has the OLD slug. The option value is ignored.
 *
 * Hook signature: update_option_{option}( $old_value, $new_value, $option )
 */
add_action( 'update_option_wpfa_slug_login',        'wpfa_admin_on_slug_change', 10, 3 );
add_action( 'update_option_wpfa_slug_logout',       'wpfa_admin_on_slug_change', 10, 3 );
add_action( 'update_option_wpfa_slug_register',     'wpfa_admin_on_slug_change', 10, 3 );
add_action( 'update_option_wpfa_slug_lostpassword', 'wpfa_admin_on_slug_change', 10, 3 );
add_action( 'update_option_wpfa_slug_resetpass',    'wpfa_admin_on_slug_change', 10, 3 );
add_action( 'update_option_wpfa_use_permalinks',    'wpfa_admin_on_slug_change', 10, 3 );

function wpfa_admin_on_slug_change( $old_value, $new_value, $option ): void {
    // Extract the action name from the option: "wpfa_slug_lostpassword" → "lostpassword"
    $action = str_replace( 'wpfa_slug_', '', $option );

    // Update the real page's slug if one exists for this action.
    $page_id = wpfa_get_page_id( $action );
    if ( $page_id && get_post( $page_id ) instanceof WP_Post ) {
        $new_slug = sanitize_title( $new_value );
        if ( '' !== $new_slug ) {
            wp_update_post( [
                'ID'        => $page_id,
                'post_name' => $new_slug,
            ] );
        }
    }

    wpfa_flush_rewrite_rules();
}

/* -----------------------------------------------------------------------
 * Fix #11 — Enqueue editor-only CSS for the Reset Password preview wrapper.
 * Replaces hardcoded hex colours with CSS-variable-driven classes.
 * -------------------------------------------------------------------- */
add_action( 'elementor/editor/after_enqueue_styles', 'wpfa_enqueue_elementor_editor_styles' );

function wpfa_enqueue_elementor_editor_styles(): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    wp_enqueue_style(
        'wp-frontend-auth-editor',
        WPFA_URL . 'assets/styles/wp-frontend-auth-editor.css',
        [],
        WPFA_VERSION
    );
}

/* -----------------------------------------------------------------------
 * Manual page creation / deletion handlers
 *
 * FIX: Pages are no longer auto-created on activation. These admin-post
 * handlers give the user explicit manual control via the settings page.
 * -------------------------------------------------------------------- */

add_action( 'admin_post_wpfa_create_pages', 'wpfa_admin_handle_create_pages' );

function wpfa_admin_handle_create_pages(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'wp-frontend-auth' ), 403 );
    }
    check_admin_referer( 'wpfa_create_pages', 'wpfa_pages_nonce' );
    wpfa_create_action_pages();
    wpfa_flush_rewrite_rules();
    wp_safe_redirect( add_query_arg( 'wpfa_notice', 'pages_created', admin_url( 'admin.php?page=wp-frontend-auth' ) ) );
    exit;
}

add_action( 'admin_post_wpfa_delete_pages', 'wpfa_admin_handle_delete_pages' );

function wpfa_admin_handle_delete_pages(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Unauthorized.', 'wp-frontend-auth' ), 403 );
    }
    check_admin_referer( 'wpfa_delete_pages', 'wpfa_pages_nonce' );

    foreach ( array_keys( wpfa_get_page_actions() ) as $action ) {
        $opt     = "wpfa_page_id_{$action}";
        $page_id = (int) get_option( $opt, 0 );
        if ( ! $page_id ) {
            continue;
        }
        // Only delete pages that the plugin auto-created (not user-adopted pages).
        // wpfa_create_action_pages() sets this meta flag on every page it inserts.
        if ( get_post_meta( $page_id, '_wpfa_auto_created', true ) ) {
            wp_delete_post( $page_id, true );
        }
        delete_option( $opt );
    }

    wpfa_flush_rewrite_rules();
    wp_safe_redirect( add_query_arg( 'wpfa_notice', 'pages_deleted', admin_url( 'admin.php?page=wp-frontend-auth' ) ) );
    exit;
}

/* -----------------------------------------------------------------------
 * Admin notices for page management actions
 * -------------------------------------------------------------------- */
add_action( 'admin_notices', 'wpfa_admin_page_notices' );

function wpfa_admin_page_notices(): void {
    if ( ! isset( $_GET['wpfa_notice'] ) || ! is_string( $_GET['wpfa_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
        return;
    }
    $notice = sanitize_key( wp_unslash( $_GET['wpfa_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
    $messages = [
        'pages_created' => __( 'Auth pages have been created successfully.', 'wp-frontend-auth' ),
        'pages_deleted' => __( 'Auto-created auth pages have been deleted.', 'wp-frontend-auth' ),
    ];
    if ( isset( $messages[ $notice ] ) ) {
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $messages[ $notice ] ) . '</p></div>';
    }
}

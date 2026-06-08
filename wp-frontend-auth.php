<?php
/**
 * Plugin Name:       WP Frontend Auth
 * Plugin URI:        https://github.com/guramzhgamadze/Frontend-Auth
 * Description:       Secure, accessible frontend login, registration, and password recovery forms — with rate limiting, honeypot protection, AJAX support, and native Elementor widgets.
 * Version:           1.4.19
 * Requires at least: 6.5
 * Requires PHP:      8.0
 * Author:            Guram Zhgamadze
 * Author URI:        https://github.com/guramzhgamadze
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-frontend-auth
 * Domain Path:       /languages
 * Network:           true
 */

// No "Requires Plugins: elementor" header — this plugin works without Elementor
// for classic WP_Widget sidebar use. Elementor widgets are loaded conditionally
// only when Elementor is active.

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Prevent fatal error if two copies of this plugin exist in /plugins/.
 * If another copy already defined WPFA_VERSION, bail silently.
 * -------------------------------------------------------------------- */
if ( defined( 'WPFA_VERSION' ) ) {
    return;
}

/* -----------------------------------------------------------------------
 * Runtime PHP version guard
 *
 * The header "Requires PHP: 8.0" tells WordPress to block activation on
 * older versions, but some hosts bypass this check (e.g. WP-CLI, mu-plugins
 * that pre-load, or outdated WP installs that ignore the header). This
 * guard catches those edge cases with a graceful admin notice instead of
 * a fatal parse error from str_contains() / union types / typed properties.
 * -------------------------------------------------------------------- */
if ( version_compare( PHP_VERSION, '8.0.0', '<' ) ) {
    add_action( 'admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>WP Frontend Auth</strong> requires PHP 8.0 or higher. ';
        printf(
            esc_html__( 'Your server is running PHP %s. Please upgrade to PHP 8.0 or higher, or deactivate the plugin.', 'wp-frontend-auth' ),
            esc_html( PHP_VERSION )
        );
        echo '</p></div>';
    } );
    return; // Stop loading — nothing below is PHP 7.x safe.
}

/* -----------------------------------------------------------------------
 * WordPress version guard (runtime)
 *
 * wp_send_new_user_notification_to_user/to_admin filters require WP 6.1+.
 * sanitize_url() restored (un-deprecated) since WP 5.9. We target 6.5+.
 * -------------------------------------------------------------------- */
if ( version_compare( get_bloginfo( 'version' ), '6.5', '<' ) ) {
    add_action( 'admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p>';
        echo '<strong>' . esc_html__( 'WP Frontend Auth', 'wp-frontend-auth' ) . '</strong> ';
        echo esc_html__( 'requires WordPress 6.5 or higher. Please update WordPress or deactivate the plugin.', 'wp-frontend-auth' );
        echo '</p></div>';
    } );
    return;
}

define( 'WPFA_VERSION', '1.4.19' );
define( 'WPFA_PATH',    plugin_dir_path( __FILE__ ) );
define( 'WPFA_URL',     plugin_dir_url( __FILE__ ) );

/* -----------------------------------------------------------------------
 * Translations — must run on 'init' so WP locale is finalised first.
 * -------------------------------------------------------------------- */
// Translations are loaded automatically by WordPress since v4.6 (JIT loader).
// load_plugin_textdomain() is no longer necessary for plugins on WordPress.org
// and was made redundant by WP 6.7's deferred translation loading system
// (make.wordpress.org/core/2024/10/21/i18n-improvements-6-7/).
// The .mo/.po files in /languages/ are auto-discovered from WP_LANG_DIR.

/* -----------------------------------------------------------------------
 * Core files — always loaded
 * -------------------------------------------------------------------- */
require WPFA_PATH . 'includes/options.php';
require WPFA_PATH . 'includes/helpers.php';
require WPFA_PATH . 'includes/rate-limit.php';
require WPFA_PATH . 'includes/class-wpfa.php';
require WPFA_PATH . 'includes/class-wpfa-form.php';
require WPFA_PATH . 'includes/forms.php';
require WPFA_PATH . 'includes/handlers.php';
require WPFA_PATH . 'includes/widgets.php';
require WPFA_PATH . 'includes/hooks.php';
require WPFA_PATH . 'includes/ms-hooks.php';

/* -----------------------------------------------------------------------
 * Admin files
 * -------------------------------------------------------------------- */
if ( is_admin() ) {
    require WPFA_PATH . 'admin/settings.php';
    require WPFA_PATH . 'admin/hooks.php';
}

/* -----------------------------------------------------------------------
 * Upgrade routine — runs on init, flushes rewrite rules when stored
 * version != current version.
 *
 * Critical because replacing plugin files via FTP/zip does NOT trigger
 * the activation hook — rewrite rules must be flushed on version change.
 * -------------------------------------------------------------------- */
add_action( 'init', 'wpfa_maybe_upgrade', 2 );

function wpfa_maybe_upgrade(): void {
    $stored = get_option( 'wpfa_version', '' );
    if ( WPFA_VERSION === $stored ) {
        return;
    }

    // Seed default options if missing (first install via FTP, not activation hook).
    if ( '' === $stored ) {
        $defaults = [
            'wpfa_rate_limit'        => 10,
            'wpfa_rate_limit_window' => 15,
            'wpfa_use_ajax'          => false,
            'wpfa_user_passwords'    => false,
            'wpfa_auto_login'        => false,
            'wpfa_honeypot'          => true,
            'wpfa_login_type'        => 'default',
            'wpfa_use_permalinks'    => true,
        ];
        foreach ( $defaults as $key => $val ) {
            if ( null === get_option( $key, null ) ) {
                add_option( $key, $val );
            }
        }
    }

    /* -------------------------------------------------------------------
     * v1.4.17: One-time database cleanup.
     *
     * 1. Delete orphaned wpfa_slug_* options that don't belong to any
     *    known action (e.g. wpfa_slug_dashboard from earlier experiments).
     * 2. Prune excessive post revisions on auth pages — keep latest 5,
     *    delete the rest. On a busy Elementor site this can remove a few
     *    hundred revisions and reclaim a meaningful chunk of wp_postmeta data
     *    (each Elementor revision stores a full copy of _elementor_data).
     *
     * Both operations are idempotent and version-gated so they only run
     * once during the upgrade from any earlier version to 1.4.17+.
     * ---------------------------------------------------------------- */
    if ( version_compare( $stored, '1.4.17', '<' ) && '' !== $stored ) {
        wpfa_upgrade_cleanup_1_4_17();
    }

    update_option( 'wpfa_version', WPFA_VERSION );

    // FIX (v1.4.16): Flush at init priority 99 — after wpfa_add_rewrite_rules()
    // (priority 10) has registered all rules, but still within the same init cycle.
    // Previously this was scheduled on 'shutdown', meaning the flush only took
    // effect on the NEXT request: /login/ would 404 on the first load after upgrade.
    add_action( 'init', 'wpfa_flush_rewrite_rules', 99 );

    // Purge cached 404s for auth pages from LiteSpeed Cache, Super Page Cache, etc.
    // Must run after init so wpfa_get_action_url() can build correct URLs.
    add_action( 'init', 'wpfa_purge_auth_page_cache', 100 );
}

/**
 * v1.4.17 upgrade cleanup: orphaned options + auth page revision pruning.
 *
 * @access private — called only from wpfa_maybe_upgrade().
 */
function wpfa_upgrade_cleanup_1_4_17(): void {
    global $wpdb;

    /* ----- 1. Delete orphaned wpfa_slug_* options ----- */
    $known_slugs = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass' ];
    $like        = $wpdb->esc_like( 'wpfa_slug_' ) . '%';

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $all_slug_opts = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );

    foreach ( $all_slug_opts as $opt_name ) {
        $action = str_replace( 'wpfa_slug_', '', $opt_name );
        if ( ! in_array( $action, $known_slugs, true ) ) {
            delete_option( $opt_name );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'WPFA 1.4.17 cleanup: deleted orphaned option ' . $opt_name );
            }
        }
    }

    /* ----- 2. Prune auth page revisions (keep 5 newest) ----- */
    $page_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];

    foreach ( $page_actions as $action ) {
        $page_id = (int) get_option( "wpfa_page_id_{$action}", 0 );
        if ( ! $page_id ) {
            continue;
        }

        // wp_get_post_revisions returns WP_Post[] keyed by ID, newest first.
        $revisions = wp_get_post_revisions( $page_id, [ 'order' => 'DESC' ] );
        $rev_ids   = array_keys( $revisions );

        if ( count( $rev_ids ) <= 5 ) {
            continue;
        }

        $to_delete = array_slice( $rev_ids, 5 );
        $deleted   = 0;

        foreach ( $to_delete as $rev_id ) {
            if ( wp_delete_post_revision( $rev_id ) ) {
                $deleted++;
            }
        }

        if ( defined( 'WP_DEBUG' ) && WP_DEBUG && $deleted > 0 ) {
            error_log( sprintf(
                'WPFA 1.4.17 cleanup: pruned %d revisions from %s page (ID %d), kept 5',
                $deleted,
                $action,
                $page_id
            ) );
        }
    }
}

/* -----------------------------------------------------------------------
 * Elementor integration — loaded only when Elementor is active.
 *
 * FIX: Removed \Elementor\* type hints from these callback signatures.
 * While PHP resolves type hints lazily (no fatal at definition time),
 * some opcache/preloading configurations and static analysis tools can
 * trigger issues. The hooks are Elementor-specific — if they fire,
 * Elementor is loaded. We validate with class_exists() inside instead.
 *
 * FIX: Added class_exists() guard before require_once to prevent fatal
 * "Class Elementor\Widget_Base not found" if Elementor's autoloader
 * hasn't registered the base class yet when the hook fires.
 * -------------------------------------------------------------------- */

// Register the custom widget category in the Elementor panel sidebar.
add_action( 'elementor/elements/categories_registered', 'wpfa_maybe_register_elementor_category' );

/**
 * @param \Elementor\Elements_Manager $elements_manager (type hint omitted — see note above)
 */
function wpfa_maybe_register_elementor_category( $elements_manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once WPFA_PATH . 'includes/elementor/class-wpfa-elementor-widgets.php';
    if ( function_exists( 'wpfa_register_elementor_category' ) ) {
        wpfa_register_elementor_category( $elements_manager );
    }
}

// Register the widgets themselves.
add_action( 'elementor/widgets/register', 'wpfa_load_elementor_widgets' );

/**
 * @param \Elementor\Widgets_Manager $manager (type hint omitted — see note above)
 */
function wpfa_load_elementor_widgets( $manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once WPFA_PATH . 'includes/elementor/class-wpfa-elementor-widgets.php';
    if ( function_exists( 'wpfa_register_elementor_widgets' ) ) {
        wpfa_register_elementor_widgets( $manager );
    }
}

/* -----------------------------------------------------------------------
 * Activation / Deactivation
 * -------------------------------------------------------------------- */
register_activation_hook( __FILE__, 'wpfa_activate' );
register_deactivation_hook( __FILE__, 'wpfa_deactivate' );

function wpfa_activate(): void {
    // get_option() returns false for missing options AND for options stored as false.
    // null is never stored by add_option/update_option so === null is unambiguous.
    if ( null === get_option( 'wpfa_rate_limit', null ) ) {
        add_option( 'wpfa_rate_limit',        10      );
        add_option( 'wpfa_rate_limit_window', 15      );
        add_option( 'wpfa_use_ajax',          false   );
        add_option( 'wpfa_user_passwords',    false   );
        add_option( 'wpfa_auto_login',        false   );
        add_option( 'wpfa_honeypot',          true    );
        add_option( 'wpfa_login_type',        'default' );
        add_option( 'wpfa_use_permalinks',    true    );
    }
    update_option( 'wpfa_version', WPFA_VERSION );

    // FIX: Removed automatic wpfa_create_action_pages() call.
    //
    // Previously, the plugin auto-created 4 real WP pages (Login, Register,
    // Lost Password, Reset Password) every time it was activated — including
    // deactivate→reactivate cycles. This caused unwanted page proliferation
    // and surprised users who expected manual control over their page structure.
    //
    // Page creation is now manual via the "Create Pages" button on the
    // Frontend Auth settings screen (Settings → Frontend Auth → Page Management).
    // The virtual-page rewrite system (wpfa_the_posts filter) provides fallback
    // URLs for all actions even without real pages, so the plugin works out of
    // the box. Real pages are only needed for Elementor Theme Builder targeting.

    wpfa_flush_rewrite_rules();
}

function wpfa_deactivate(): void {
    wpfa_flush_rewrite_rules();
}

<?php
/**
 * Plugin Name:       Zen Login & Authentication
 * Plugin URI:        https://github.com/guramzhgamadze/zen-login-authentication
 * Description:       Secure, accessible frontend login, registration, and password recovery forms — with rate limiting, honeypot protection, AJAX support, and native Elementor widgets.
 * Version:           2.1.5
 * Requires at least: 6.5
 * Requires PHP:      8.0
 * Author:            Guram Zhgamadze
 * Author URI:        https://github.com/guramzhgamadze
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       zen-login-authentication
 * Domain Path:       /languages
 * Network:           true
 */

// No "Requires Plugins: elementor" header — this plugin works without Elementor
// for classic WP_Widget sidebar use. Elementor widgets are loaded conditionally
// only when Elementor is active.

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Prevent fatal error if two copies of this plugin exist in /plugins/.
 * If another copy already defined ZENLOGAU_VERSION, bail silently.
 * -------------------------------------------------------------------- */
if ( defined( 'ZENLOGAU_VERSION' ) ) {
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
        echo '<strong>Zen Login & Authentication</strong> requires PHP 8.0 or higher. ';
        printf(
            /* translators: %s: the PHP version the server is currently running. */
            esc_html__( 'Your server is running PHP %s. Please upgrade to PHP 8.0 or higher, or deactivate the plugin.', 'zen-login-authentication' ),
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
        echo '<strong>' . esc_html__( 'Zen Login & Authentication', 'zen-login-authentication' ) . '</strong> ';
        echo esc_html__( 'requires WordPress 6.5 or higher. Please update WordPress or deactivate the plugin.', 'zen-login-authentication' );
        echo '</p></div>';
    } );
    return;
}

define( 'ZENLOGAU_VERSION', '2.1.5' );
define( 'ZENLOGAU_PATH',    plugin_dir_path( __FILE__ ) );
define( 'ZENLOGAU_URL',     plugin_dir_url( __FILE__ ) );

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
require ZENLOGAU_PATH . 'includes/options.php';
require ZENLOGAU_PATH . 'includes/helpers.php';
require ZENLOGAU_PATH . 'includes/rate-limit.php';
require ZENLOGAU_PATH . 'includes/security-hardening.php';
require ZENLOGAU_PATH . 'includes/breached-password.php';
require ZENLOGAU_PATH . 'includes/turnstile.php';
require ZENLOGAU_PATH . 'includes/totp.php';
require ZENLOGAU_PATH . 'includes/two-factor.php';
require ZENLOGAU_PATH . 'includes/account-sessions.php';
require ZENLOGAU_PATH . 'includes/new-device-email.php';
require ZENLOGAU_PATH . 'includes/passkeys.php';
require ZENLOGAU_PATH . 'includes/activity-log.php';
require ZENLOGAU_PATH . 'includes/privacy.php';
require ZENLOGAU_PATH . 'includes/class-fauth.php';
require ZENLOGAU_PATH . 'includes/class-fauth-form.php';
require ZENLOGAU_PATH . 'includes/forms.php';
require ZENLOGAU_PATH . 'includes/handlers.php';
require ZENLOGAU_PATH . 'includes/crypto.php';
require ZENLOGAU_PATH . 'includes/google-login.php';
require ZENLOGAU_PATH . 'includes/widgets.php';
require ZENLOGAU_PATH . 'includes/hooks.php';
require ZENLOGAU_PATH . 'includes/ms-hooks.php';

/* -----------------------------------------------------------------------
 * Admin files
 * -------------------------------------------------------------------- */
if ( is_admin() ) {
    require ZENLOGAU_PATH . 'admin/settings.php';
    require ZENLOGAU_PATH . 'admin/hooks.php';
    require ZENLOGAU_PATH . 'admin/dashboard.php';
    require ZENLOGAU_PATH . 'admin/user-security.php';
}

/* -----------------------------------------------------------------------
 * Upgrade routine — runs on init, flushes rewrite rules when stored
 * version != current version.
 *
 * Critical because replacing plugin files via FTP/zip does NOT trigger
 * the activation hook — rewrite rules must be flushed on version change.
 * -------------------------------------------------------------------- */
add_action( 'init', 'zenlogau_maybe_upgrade', 2 );

function zenlogau_maybe_upgrade(): void {
    $stored = get_option( 'zenlogau_version', '' );
    if ( ZENLOGAU_VERSION === $stored ) {
        return;
    }

    // Seed default options if missing (first install via FTP, not activation hook).
    if ( '' === $stored ) {
        $defaults = [
            'zenlogau_rate_limit'        => 10,
            'zenlogau_rate_limit_window' => 15,
            'zenlogau_use_ajax'          => false,
            'zenlogau_user_passwords'    => false,
            'zenlogau_auto_login'        => false,
            'zenlogau_honeypot'          => true,
            'zenlogau_login_type'        => 'default',
            'zenlogau_use_permalinks'    => true,
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
     * 1. Delete orphaned zenlogau_slug_* options that don't belong to any
     *    known action (e.g. zenlogau_slug_dashboard from earlier experiments).
     * 2. Prune excessive post revisions on auth pages — keep latest 5,
     *    delete the rest. On a busy Elementor site this can remove a few
     *    hundred revisions and reclaim a meaningful chunk of wp_postmeta data
     *    (each Elementor revision stores a full copy of _elementor_data).
     *
     * Both operations are idempotent and version-gated so they only run
     * once during the upgrade from any earlier version to 1.4.17+.
     * ---------------------------------------------------------------- */
    if ( version_compare( $stored, '1.4.17', '<' ) && '' !== $stored ) {
        zenlogau_upgrade_cleanup_1_4_17();
    }

    /* -------------------------------------------------------------------
     * v1.6.0: the Account page (frontend profile editing) is new. Adopt or
     * create it on upgraded sites — zenlogau_create_action_pages() is fully
     * idempotent (existing pages are adopted by slug, stored IDs are kept),
     * so the four original auth pages are untouched.
     * ---------------------------------------------------------------- */
    if ( version_compare( $stored, '1.6.0', '<' ) && '' !== $stored ) {
        zenlogau_create_action_pages();
    }

    // v1.7.0: ensure the login-activity table exists (covers FTP updates and,
    // since zenlogau_maybe_upgrade runs per-blog on init, every multisite site).
    zenlogau_activity_maybe_create_table();

    update_option( 'zenlogau_version', ZENLOGAU_VERSION );

    // FIX (v1.4.16): Flush at init priority 99 — after zenlogau_add_rewrite_rules()
    // (priority 10) has registered all rules, but still within the same init cycle.
    // Previously this was scheduled on 'shutdown', meaning the flush only took
    // effect on the NEXT request: /login/ would 404 on the first load after upgrade.
    add_action( 'init', 'zenlogau_flush_rewrite_rules', 99 );

    // Purge cached 404s for auth pages from LiteSpeed Cache, Super Page Cache, etc.
    // Must run after init so zenlogau_get_action_url() can build correct URLs.
    add_action( 'init', 'zenlogau_purge_auth_page_cache', 100 );
}

/**
 * v1.4.17 upgrade cleanup: orphaned options + auth page revision pruning.
 *
 * @access private — called only from zenlogau_maybe_upgrade().
 */
function zenlogau_upgrade_cleanup_1_4_17(): void {
    global $wpdb;

    /* ----- 1. Delete orphaned zenlogau_slug_* options ----- */
    $known_slugs = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass', 'account' ];
    $like        = $wpdb->esc_like( 'zenlogau_slug_' ) . '%';

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $all_slug_opts = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );

    foreach ( $all_slug_opts as $opt_name ) {
        $action = str_replace( 'zenlogau_slug_', '', $opt_name );
        if ( ! in_array( $action, $known_slugs, true ) ) {
            delete_option( $opt_name );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'ZENLOGAU 1.4.17 cleanup: deleted orphaned option ' . $opt_name ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WP_DEBUG-gated diagnostic.
            }
        }
    }

    /* ----- 2. Prune auth page revisions (keep 5 newest) ----- */
    $page_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];

    foreach ( $page_actions as $action ) {
        $page_id = (int) get_option( "zenlogau_page_id_{$action}", 0 );
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
            error_log( sprintf( // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WP_DEBUG-gated diagnostic.
                'ZENLOGAU 1.4.17 cleanup: pruned %d revisions from %s page (ID %d), kept 5',
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
add_action( 'elementor/elements/categories_registered', 'zenlogau_maybe_register_elementor_category' );

/**
 * @param \Elementor\Elements_Manager $elements_manager (type hint omitted — see note above)
 */
function zenlogau_maybe_register_elementor_category( $elements_manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once ZENLOGAU_PATH . 'includes/elementor/class-fauth-elementor-widgets.php';
    if ( function_exists( 'zenlogau_register_elementor_category' ) ) {
        zenlogau_register_elementor_category( $elements_manager );
    }
}

// Register the widgets themselves.
add_action( 'elementor/widgets/register', 'zenlogau_load_elementor_widgets' );

/**
 * @param \Elementor\Widgets_Manager $manager (type hint omitted — see note above)
 */
function zenlogau_load_elementor_widgets( $manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once ZENLOGAU_PATH . 'includes/elementor/class-fauth-elementor-widgets.php';
    if ( function_exists( 'zenlogau_register_elementor_widgets' ) ) {
        zenlogau_register_elementor_widgets( $manager );
    }
}

/* -----------------------------------------------------------------------
 * Activation / Deactivation
 * -------------------------------------------------------------------- */
register_activation_hook( __FILE__, 'zenlogau_activate' );
register_deactivation_hook( __FILE__, 'zenlogau_deactivate' );

function zenlogau_activate(): void {
    // get_option() returns false for missing options AND for options stored as false.
    // null is never stored by add_option/update_option so === null is unambiguous.
    if ( null === get_option( 'zenlogau_rate_limit', null ) ) {
        add_option( 'zenlogau_rate_limit',        10      );
        add_option( 'zenlogau_rate_limit_window', 15      );
        add_option( 'zenlogau_use_ajax',          false   );
        add_option( 'zenlogau_user_passwords',    false   );
        add_option( 'zenlogau_auto_login',        false   );
        add_option( 'zenlogau_honeypot',          true    );
        add_option( 'zenlogau_login_type',        'default' );
        add_option( 'zenlogau_use_permalinks',    true    );
    }
    update_option( 'zenlogau_version', ZENLOGAU_VERSION );

    // Adopt-or-create the real auth pages (Login, Register, Lost Password,
    // Reset Password). For each action zenlogau_create_action_pages() checks the
    // configured/default slug:
    //   • a page already exists at that slug → it is reused as-is and left
    //     unflagged, so uninstall will never delete it;
    //   • no page exists → a new one is created and flagged _zenlogau_auto_created,
    //     so uninstall can remove it later *only while it stays empty/unedited*.
    //
    // The routine is idempotent — it skips any action that already has a stored,
    // published page — so repeated activate/deactivate cycles never duplicate
    // pages (the duplication bug that affected pre-1.4.16 builds, before the
    // stored-ID check and slug adoption were added). Manual control remains via
    // the "Create Missing Pages" / "Delete Auto-Created Pages" buttons on the
    // settings screen, and the plugin still works with no real pages at all via
    // its virtual URL-rewrite fallback.
    zenlogau_create_action_pages();

    // Create the login-activity table (idempotent — dbDelta is version-gated).
    zenlogau_activity_maybe_create_table();

    zenlogau_flush_rewrite_rules();
}

function zenlogau_deactivate(): void {
    wp_clear_scheduled_hook( 'zenlogau_activity_prune_event' );
    zenlogau_flush_rewrite_rules();
}

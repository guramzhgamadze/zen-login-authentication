<?php
/**
 * Plugin Name:       Zen Login & Authentication
 * Plugin URI:        https://github.com/guramzhgamadze/zen-login-authentication
 * Description:       Secure, accessible frontend login, registration, and password recovery forms — with rate limiting, honeypot protection, AJAX support, and native Elementor widgets.
 * Version:           1.7.1
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
 * If another copy already defined FAUTH_VERSION, bail silently.
 * -------------------------------------------------------------------- */
if ( defined( 'FAUTH_VERSION' ) ) {
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

define( 'FAUTH_VERSION', '1.7.1' );
define( 'FAUTH_PATH',    plugin_dir_path( __FILE__ ) );
define( 'FAUTH_URL',     plugin_dir_url( __FILE__ ) );

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
require FAUTH_PATH . 'includes/options.php';
require FAUTH_PATH . 'includes/helpers.php';
require FAUTH_PATH . 'includes/rate-limit.php';
require FAUTH_PATH . 'includes/activity-log.php';
require FAUTH_PATH . 'includes/class-fauth.php';
require FAUTH_PATH . 'includes/class-fauth-form.php';
require FAUTH_PATH . 'includes/forms.php';
require FAUTH_PATH . 'includes/handlers.php';
require FAUTH_PATH . 'includes/crypto.php';
require FAUTH_PATH . 'includes/google-login.php';
require FAUTH_PATH . 'includes/widgets.php';
require FAUTH_PATH . 'includes/hooks.php';
require FAUTH_PATH . 'includes/ms-hooks.php';

/* -----------------------------------------------------------------------
 * Admin files
 * -------------------------------------------------------------------- */
if ( is_admin() ) {
    require FAUTH_PATH . 'admin/settings.php';
    require FAUTH_PATH . 'admin/hooks.php';
    require FAUTH_PATH . 'admin/dashboard.php';
}

/* -----------------------------------------------------------------------
 * Upgrade routine — runs on init, flushes rewrite rules when stored
 * version != current version.
 *
 * Critical because replacing plugin files via FTP/zip does NOT trigger
 * the activation hook — rewrite rules must be flushed on version change.
 * -------------------------------------------------------------------- */
add_action( 'init', 'fauth_maybe_upgrade', 2 );

function fauth_maybe_upgrade(): void {
    $stored = get_option( 'fauth_version', '' );
    if ( FAUTH_VERSION === $stored ) {
        return;
    }

    // One-time migration from the pre-release "wpfa" internal prefix (the
    // plugin was renamed for its WordPress.org release). Self-guarded: no-op
    // unless the legacy wpfa_version option exists. The default seeding below
    // is add-if-missing, so migrated values are never overwritten, and this
    // version-mismatch path already flushes rewrites and purges page caches.
    fauth_migrate_legacy_wpfa_prefix();

    // Seed default options if missing (first install via FTP, not activation hook).
    if ( '' === $stored ) {
        $defaults = [
            'fauth_rate_limit'        => 10,
            'fauth_rate_limit_window' => 15,
            'fauth_use_ajax'          => false,
            'fauth_user_passwords'    => false,
            'fauth_auto_login'        => false,
            'fauth_honeypot'          => true,
            'fauth_login_type'        => 'default',
            'fauth_use_permalinks'    => true,
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
     * 1. Delete orphaned fauth_slug_* options that don't belong to any
     *    known action (e.g. fauth_slug_dashboard from earlier experiments).
     * 2. Prune excessive post revisions on auth pages — keep latest 5,
     *    delete the rest. On a busy Elementor site this can remove a few
     *    hundred revisions and reclaim a meaningful chunk of wp_postmeta data
     *    (each Elementor revision stores a full copy of _elementor_data).
     *
     * Both operations are idempotent and version-gated so they only run
     * once during the upgrade from any earlier version to 1.4.17+.
     * ---------------------------------------------------------------- */
    if ( version_compare( $stored, '1.4.17', '<' ) && '' !== $stored ) {
        fauth_upgrade_cleanup_1_4_17();
    }

    /* -------------------------------------------------------------------
     * v1.6.0: the Account page (frontend profile editing) is new. Adopt or
     * create it on upgraded sites — fauth_create_action_pages() is fully
     * idempotent (existing pages are adopted by slug, stored IDs are kept),
     * so the four original auth pages are untouched.
     * ---------------------------------------------------------------- */
    if ( version_compare( $stored, '1.6.0', '<' ) && '' !== $stored ) {
        fauth_create_action_pages();
    }

    // v1.7.0: ensure the login-activity table exists (covers FTP updates and,
    // since fauth_maybe_upgrade runs per-blog on init, every multisite site).
    fauth_activity_maybe_create_table();

    update_option( 'fauth_version', FAUTH_VERSION );

    // FIX (v1.4.16): Flush at init priority 99 — after fauth_add_rewrite_rules()
    // (priority 10) has registered all rules, but still within the same init cycle.
    // Previously this was scheduled on 'shutdown', meaning the flush only took
    // effect on the NEXT request: /login/ would 404 on the first load after upgrade.
    add_action( 'init', 'fauth_flush_rewrite_rules', 99 );

    // Purge cached 404s for auth pages from LiteSpeed Cache, Super Page Cache, etc.
    // Must run after init so fauth_get_action_url() can build correct URLs.
    add_action( 'init', 'fauth_purge_auth_page_cache', 100 );
}

/**
 * One-time migration from the pre-release "wpfa" internal prefix to "fauth"
 * (the plugin was renamed for its WordPress.org release; no public version
 * ever shipped with the old prefix). Renames every stored artifact in place:
 *
 *  - options:          wpfa_*             -> fauth_*
 *  - widget instances: widget_wpfa_*      -> widget_fauth_* (+ sidebar ids)
 *  - page meta:        _wpfa_auto_created -> _fauth_auto_created
 *  - user meta:        wpfa_google_sub    -> fauth_google_sub
 *  - Elementor data:   "widgetType":"wpfa-*" -> "fauth-*" (+ CSS cache purge)
 *  - transients:       deleted (they regenerate; rate-limit windows reset)
 *
 * Guarded by the presence of the legacy wpfa_version option, so it runs at
 * most once per site and is a no-op on every fresh install.
 *
 * @access private — called only from fauth_maybe_upgrade().
 */
function fauth_migrate_legacy_wpfa_prefix(): void {
    global $wpdb;

    if ( false === get_option( 'wpfa_version', false ) ) {
        return; // nothing to migrate
    }

    // phpcs:disable WordPress.DB.DirectDatabaseQuery -- one-time schema-level
    // rename of this plugin's own rows; no API exists for renaming option/meta
    // keys, and caches are flushed at the end of the migration.

    // 1. Options: wpfa_* -> fauth_* and widget_wpfa_* -> widget_fauth_*.
    //    Row by row via add_option() so a pre-existing fauth_* row (unique
    //    key) can never abort the rename half-way.
    $rows = $wpdb->get_results(
        "SELECT option_name, option_value FROM {$wpdb->options}
         WHERE option_name LIKE 'wpfa\\_%' OR option_name LIKE 'widget\\_wpfa\\_%'"
    );
    foreach ( $rows as $row ) {
        $new = ( 0 === strpos( $row->option_name, 'widget_' ) )
            ? 'widget_fauth_' . substr( $row->option_name, strlen( 'widget_wpfa_' ) )
            : 'fauth_' . substr( $row->option_name, strlen( 'wpfa_' ) );
        if ( null === get_option( $new, null ) ) {
            add_option( $new, maybe_unserialize( $row->option_value ), '', false );
        }
        delete_option( $row->option_name );
    }

    // 2. Classic-widget ids inside sidebars_widgets (handled unserialized,
    //    so string lengths in the stored value stay consistent).
    $sidebars = get_option( 'sidebars_widgets' );
    if ( is_array( $sidebars ) ) {
        $migrated = [];
        foreach ( $sidebars as $sidebar => $widgets ) {
            if ( is_array( $widgets ) ) {
                foreach ( $widgets as $i => $id ) {
                    if ( is_string( $id ) && 0 === strpos( $id, 'wpfa_' ) ) {
                        $widgets[ $i ] = 'fauth_' . substr( $id, strlen( 'wpfa_' ) );
                    }
                }
            }
            $migrated[ $sidebar ] = $widgets;
        }
        if ( $migrated !== $sidebars ) {
            update_option( 'sidebars_widgets', $migrated );
        }
    }

    // 3. Meta keys.
    $wpdb->query( "UPDATE {$wpdb->postmeta} SET meta_key = '_fauth_auto_created' WHERE meta_key = '_wpfa_auto_created'" );
    $wpdb->query( "UPDATE {$wpdb->usermeta} SET meta_key = 'fauth_google_sub' WHERE meta_key = 'wpfa_google_sub'" );

    // 4. Elementor widget types stored in _elementor_data (exact JSON tokens
    //    only — no blanket replace on user content).
    foreach ( [ 'login', 'register', 'lost-password', 'reset-password' ] as $widget ) {
        $wpdb->query( $wpdb->prepare(
            "UPDATE {$wpdb->postmeta} SET meta_value = REPLACE( meta_value, %s, %s )
             WHERE meta_key = '_elementor_data' AND meta_value LIKE %s",
            '"widgetType":"wpfa-' . $widget . '"',
            '"widgetType":"fauth-' . $widget . '"',
            '%' . $wpdb->esc_like( '"widgetType":"wpfa-' . $widget . '"' ) . '%'
        ) );
    }
    // Make Elementor regenerate its CSS files with the new selectors.
    if ( class_exists( '\Elementor\Plugin' ) && isset( \Elementor\Plugin::$instance->files_manager ) ) {
        \Elementor\Plugin::$instance->files_manager->clear_cache();
    }

    // 5. Stale transients (rate-limit windows + OAuth state) — they regenerate.
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
         WHERE option_name LIKE '\\_transient\\_wpfa\\_%'
            OR option_name LIKE '\\_transient\\_timeout\\_wpfa\\_%'"
    );

    // Old per-user dismissals or caches under the legacy prefix, if any.
    wp_cache_flush();
    // phpcs:enable WordPress.DB.DirectDatabaseQuery
}

/**
 * v1.4.17 upgrade cleanup: orphaned options + auth page revision pruning.
 *
 * @access private — called only from fauth_maybe_upgrade().
 */
function fauth_upgrade_cleanup_1_4_17(): void {
    global $wpdb;

    /* ----- 1. Delete orphaned fauth_slug_* options ----- */
    $known_slugs = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass', 'account' ];
    $like        = $wpdb->esc_like( 'fauth_slug_' ) . '%';

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
    $all_slug_opts = $wpdb->get_col( $wpdb->prepare(
        "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
        $like
    ) );

    foreach ( $all_slug_opts as $opt_name ) {
        $action = str_replace( 'fauth_slug_', '', $opt_name );
        if ( ! in_array( $action, $known_slugs, true ) ) {
            delete_option( $opt_name );
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'FAUTH 1.4.17 cleanup: deleted orphaned option ' . $opt_name ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WP_DEBUG-gated diagnostic.
            }
        }
    }

    /* ----- 2. Prune auth page revisions (keep 5 newest) ----- */
    $page_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];

    foreach ( $page_actions as $action ) {
        $page_id = (int) get_option( "fauth_page_id_{$action}", 0 );
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
                'FAUTH 1.4.17 cleanup: pruned %d revisions from %s page (ID %d), kept 5',
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
add_action( 'elementor/elements/categories_registered', 'fauth_maybe_register_elementor_category' );

/**
 * @param \Elementor\Elements_Manager $elements_manager (type hint omitted — see note above)
 */
function fauth_maybe_register_elementor_category( $elements_manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once FAUTH_PATH . 'includes/elementor/class-fauth-elementor-widgets.php';
    if ( function_exists( 'fauth_register_elementor_category' ) ) {
        fauth_register_elementor_category( $elements_manager );
    }
}

// Register the widgets themselves.
add_action( 'elementor/widgets/register', 'fauth_load_elementor_widgets' );

/**
 * @param \Elementor\Widgets_Manager $manager (type hint omitted — see note above)
 */
function fauth_load_elementor_widgets( $manager ): void {
    if ( ! did_action( 'elementor/loaded' ) ) {
        return;
    }
    if ( ! class_exists( '\Elementor\Widget_Base' ) ) {
        return;
    }
    require_once FAUTH_PATH . 'includes/elementor/class-fauth-elementor-widgets.php';
    if ( function_exists( 'fauth_register_elementor_widgets' ) ) {
        fauth_register_elementor_widgets( $manager );
    }
}

/* -----------------------------------------------------------------------
 * Activation / Deactivation
 * -------------------------------------------------------------------- */
register_activation_hook( __FILE__, 'fauth_activate' );
register_deactivation_hook( __FILE__, 'fauth_deactivate' );

function fauth_activate(): void {
    // get_option() returns false for missing options AND for options stored as false.
    // null is never stored by add_option/update_option so === null is unambiguous.
    if ( null === get_option( 'fauth_rate_limit', null ) ) {
        add_option( 'fauth_rate_limit',        10      );
        add_option( 'fauth_rate_limit_window', 15      );
        add_option( 'fauth_use_ajax',          false   );
        add_option( 'fauth_user_passwords',    false   );
        add_option( 'fauth_auto_login',        false   );
        add_option( 'fauth_honeypot',          true    );
        add_option( 'fauth_login_type',        'default' );
        add_option( 'fauth_use_permalinks',    true    );
    }
    update_option( 'fauth_version', FAUTH_VERSION );

    // Adopt-or-create the real auth pages (Login, Register, Lost Password,
    // Reset Password). For each action fauth_create_action_pages() checks the
    // configured/default slug:
    //   • a page already exists at that slug → it is reused as-is and left
    //     unflagged, so uninstall will never delete it;
    //   • no page exists → a new one is created and flagged _fauth_auto_created,
    //     so uninstall can remove it later *only while it stays empty/unedited*.
    //
    // The routine is idempotent — it skips any action that already has a stored,
    // published page — so repeated activate/deactivate cycles never duplicate
    // pages (the duplication bug that affected pre-1.4.16 builds, before the
    // stored-ID check and slug adoption were added). Manual control remains via
    // the "Create Missing Pages" / "Delete Auto-Created Pages" buttons on the
    // settings screen, and the plugin still works with no real pages at all via
    // its virtual URL-rewrite fallback.
    fauth_create_action_pages();

    // Create the login-activity table (idempotent — dbDelta is version-gated).
    fauth_activity_maybe_create_table();

    fauth_flush_rewrite_rules();
}

function fauth_deactivate(): void {
    fauth_flush_rewrite_rules();
}

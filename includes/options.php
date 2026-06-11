<?php
/**
 * Frontend Auth – Options & Page Management
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * General option accessors
 * -------------------------------------------------------------------- */

function fauth_use_permalinks(): bool {
    global $wp_rewrite;
    if ( ! $wp_rewrite instanceof WP_Rewrite ) {
        $wp_rewrite = new WP_Rewrite();
    }
    $wp_has_permalinks = $wp_rewrite->using_permalinks();
    $option            = (bool) get_option( 'fauth_use_permalinks', true );
    return (bool) apply_filters( 'fauth_use_permalinks', $wp_has_permalinks && $option );
}

function fauth_use_ajax(): bool {
    return (bool) apply_filters( 'fauth_use_ajax', get_option( 'fauth_use_ajax', false ) );
}

function fauth_get_login_type(): string {
    return (string) apply_filters( 'fauth_get_login_type', get_option( 'fauth_login_type', 'default' ) );
}

function fauth_is_email_login_type(): bool    { return 'email'    === fauth_get_login_type(); }
function fauth_is_username_login_type(): bool { return 'username' === fauth_get_login_type(); }

function fauth_allow_user_passwords(): bool {
    return (bool) apply_filters( 'fauth_allow_user_passwords', get_option( 'fauth_user_passwords', false ) );
}

function fauth_allow_auto_login(): bool {
    return (bool) apply_filters( 'fauth_allow_auto_login', get_option( 'fauth_auto_login', false ) );
}

function fauth_use_honeypot(): bool {
    return (bool) apply_filters( 'fauth_use_honeypot', get_option( 'fauth_honeypot', true ) );
}

function fauth_get_rate_limit(): int {
    return (int) apply_filters( 'fauth_rate_limit', get_option( 'fauth_rate_limit', 10 ) );
}

function fauth_get_rate_limit_window(): int {
    return (int) apply_filters( 'fauth_rate_limit_window', get_option( 'fauth_rate_limit_window', 15 ) );
}

/**
 * Resolve where subscribers (and other non-admin users with no wp-admin access)
 * should land after logging in.
 *
 * Configurable via Settings → Frontend Auth → "Subscriber redirect". The stored
 * value (option fauth_subscriber_redirect) may be:
 *   - empty       → the site home page (default)
 *   - a slug/path → resolved against home_url(), e.g. "dashboard" → https://site/dashboard/
 *   - a full URL  → used as-is (still passed through wp_safe_redirect() at the call
 *                   site, so only same-host destinations are honoured)
 *
 * The legacy 'fauth_subscriber_redirect' filter still works and wraps the resolved
 * default, so any code already overriding it keeps functioning.
 */
function fauth_get_subscriber_redirect(): string {
    $value = trim( (string) get_option( 'fauth_subscriber_redirect', '' ) );

    if ( '' === $value ) {
        $default = home_url();
    } elseif ( preg_match( '#^https?://#i', $value ) ) {
        $default = $value;
    } else {
        // Treat the value as a site-relative slug/path.
        $default = home_url( user_trailingslashit( '/' . ltrim( $value, '/' ) ) );
    }

    return (string) apply_filters( 'fauth_subscriber_redirect', $default );
}

/**
 * Whether a user should be treated as a "restricted subscriber" — a front-end-only
 * account that is kept out of wp-admin and sent to the Subscriber redirect.
 *
 * Default: users with the 'subscriber' role and no post-editing or admin
 * capabilities. Filterable so membership/LMS setups can widen or narrow it.
 *
 * @param mixed $user A WP_User (anything else returns false).
 */
function fauth_user_is_restricted_subscriber( $user ): bool {
    if ( ! ( $user instanceof WP_User ) || ! $user->exists() ) {
        return false;
    }
    $restricted = in_array( 'subscriber', (array) $user->roles, true )
        && ! user_can( $user, 'edit_posts' )
        && ! user_can( $user, 'manage_options' );

    return (bool) apply_filters( 'fauth_is_restricted_subscriber', $restricted, $user );
}

/* -----------------------------------------------------------------------
 * Slug helpers
 * -------------------------------------------------------------------- */

function fauth_get_action_slug_default( string $action ): string {
    $defaults = [
        'login'        => 'login',
        'logout'       => 'logout',
        'register'     => 'register',
        'lostpassword' => 'lost-password',
        'resetpass'    => 'reset-password',
    ];
    return $defaults[ $action ] ?? $action;
}

/* -----------------------------------------------------------------------
 * Real page management
 *
 * CRITICAL FIX: The old approach injected a virtual WP_Post via the_posts filter.
 * Virtual posts have ID = -1, so Elementor's Theme Builder condition system never
 * matches them — no header, footer, or template is applied.
 *
 * The correct approach: create real WordPress pages on activation. Elementor can
 * then target these pages normally via Theme Builder conditions ("Singular" > "Page"
 * or by specific page ID). The plugin stores each page's ID in wp_options.
 *
 * If the user already has pages with the matching slugs (e.g. pre-existing Elementor
 * pages), those are detected and stored instead of creating duplicates.
 * -------------------------------------------------------------------- */

/**
 * Return a valid author user ID for auto-created pages.
 *
 * BUG FIX (v1.4.5) — Hardcoded post_author => 1:
 *
 * The previous code used 'post_author' => 1 unconditionally. On many sites
 * — multisite sub-sites, headless installs, or sites where the first admin
 * was deleted and recreated — user ID 1 does not exist. WordPress silently
 * stores the invalid ID, which can break capability checks and author archives.
 *
 * Fix: prefer the currently logged-in user (during activation), then fall back
 * to the first administrator user found in the database.
 *
 * Source: developer.wordpress.org/reference/functions/get_users/
 *         developer.wordpress.org/reference/functions/get_current_user_id/
 *
 * @return int  A valid existing user ID, or 0 if no users exist (edge case).
 */
function fauth_get_page_author_id(): int {
    // During manual activation the site admin is logged in — use their ID.
    $current = (int) get_current_user_id();
    if ( $current > 0 && user_can( $current, 'manage_options' ) ) {
        return $current;
    }

    // During automatic activation (e.g. WP-CLI, auto-update) no one is logged in.
    // Fall back to the first administrator account found.
    $admins = get_users( [
        'role'    => 'administrator',
        'number'  => 1,
        'orderby' => 'ID',
        'order'   => 'ASC',
        'fields'  => 'ID',
    ] );

    return ! empty( $admins ) ? (int) $admins[0] : 0;
}

/**
 * Actions that need a real page (excludes logout and dashboard which don't have forms).
 *
 * @return array<string,string>  action => page title
 */
function fauth_get_page_actions(): array {
    return apply_filters( 'fauth_page_actions', [
        'login'        => __( 'Login',         'frontend-auth' ),
        'register'     => __( 'Register',       'frontend-auth' ),
        'lostpassword' => __( 'Lost Password',  'frontend-auth' ),
        'resetpass'    => __( 'Reset Password', 'frontend-auth' ),
    ] );
}

/**
 * Create real WP pages for each auth action, or adopt existing pages with matching slugs.
 * Called on plugin activation. Safe to call multiple times (idempotent).
 */
function fauth_create_action_pages(): void {
    foreach ( fauth_get_page_actions() as $action => $title ) {
        $opt  = "fauth_page_id_{$action}";
        // Use the user's configured slug (from settings), falling back to default.
        $slug = function_exists( 'fauth_get_action_slug' )
            ? fauth_get_action_slug( $action )
            : fauth_get_action_slug_default( $action );

        // Check if we already have a stored page ID that still exists and is published.
        $stored_id = (int) get_option( $opt, 0 );
        if ( $stored_id ) {
            $stored_post = get_post( $stored_id );
            if ( $stored_post instanceof WP_Post && 'publish' === $stored_post->post_status ) {
                continue;
            }
            // Page exists but is trashed/draft — republish it.
            if ( $stored_post instanceof WP_Post ) {
                wp_update_post( [ 'ID' => $stored_id, 'post_status' => 'publish' ] );
                continue;
            }
            // Page no longer exists — clear the stale option so we recreate below.
            delete_option( $opt );
        }

        // Check if a page with this slug already exists (user may have created one).
        $existing = get_page_by_path( $slug, OBJECT, 'page' );
        if ( $existing instanceof WP_Post ) {
            update_option( $opt, $existing->ID );
            continue;
        }

        // Create a new page with an empty body — user drops the widget in via Elementor.
        $page_id = wp_insert_post( [
            'post_title'   => $title,
            'post_name'    => $slug,
            'post_status'  => 'publish',
            'post_type'    => 'page',
            'post_content' => '',
            'post_author'  => fauth_get_page_author_id(),
        ], true );

        if ( $page_id instanceof WP_Error ) {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                error_log( 'FAUTH: failed to create page for action ' . $action . ': ' . $page_id->get_error_message() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- WP_DEBUG-gated diagnostic.
            }
            continue;
        }

        // FIX: Mark this page as auto-created by the plugin so the uninstaller
        // and the "Delete Auto-Created Pages" button know it is safe to delete.
        // Pages adopted from existing user content do NOT get this flag.
        update_post_meta( (int) $page_id, '_fauth_auto_created', '1' );

        update_option( $opt, (int) $page_id );
    }
}

/**
 * Return the stored page ID for a given action, or 0 if not found.
 *
 * BUG FIX (v1.4.16): Previously this returned the raw stored integer even when
 * the page had been deleted (trashed or permanently removed). Callers that use
 * this value to decide whether to add rewrite rules or inject virtual posts would
 * then skip both paths — no rewrite rule was registered AND no virtual post was
 * injected — leaving the /login/ URL as a hard 404.
 *
 * Fix: verify the stored ID refers to an existing published page. If the page no
 * longer exists, clear the stale option and return 0 so the rewrite/virtual-page
 * fallback can take over.
 */
function fauth_get_page_id( string $action ): int {
    $id = (int) get_option( "fauth_page_id_{$action}", 0 );
    if ( ! $id ) {
        return 0;
    }
    $post = get_post( $id );
    if ( ! $post instanceof WP_Post || 'publish' !== $post->post_status ) {
        // Stale option — clear it so callers don't keep trusting this dead ID.
        delete_option( "fauth_page_id_{$action}" );
        return 0;
    }
    return $id;
}

/**
 * Return true if the current page is one of the FAUTH action pages.
 */
function fauth_is_fauth_page(): bool {
    // Virtual pages (rewrite-rule mode, no Elementor).
    if ( get_query_var( 'fauth_action', false ) ) {
        return true;
    }
    // Real page mode (Elementor sites).
    $page_id = (int) get_queried_object_id();
    if ( ! $page_id ) {
        return false;
    }
    foreach ( array_keys( fauth_get_page_actions() ) as $action ) {
        if ( fauth_get_page_id( $action ) === $page_id ) {
            return true;
        }
    }
    return false;
}

/**
 * Return the current FAUTH action name, or empty string.
 * Works for both virtual (query var) and real (page ID lookup) pages.
 */
function fauth_get_current_action(): string {
    $from_qv = get_query_var( 'fauth_action', '' );
    if ( $from_qv ) {
        return sanitize_key( $from_qv );
    }
    $page_id = (int) get_queried_object_id();
    if ( ! $page_id ) {
        return '';
    }
    foreach ( array_keys( fauth_get_page_actions() ) as $action ) {
        if ( fauth_get_page_id( $action ) === $page_id ) {
            return $action;
        }
    }
    return '';
}

/* -----------------------------------------------------------------------
 * Flush helper
 * INFO fix: use flush_rewrite_rules(false) for reliable immediate flush.
 * -------------------------------------------------------------------- */

function fauth_flush_rewrite_rules(): void {
    flush_rewrite_rules( false );
}

<?php
/**
 * WP Frontend Auth – Hooks
 *
 * @package WP_Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Init
 * -------------------------------------------------------------------- */
add_action( 'init', 'wpfa_register_default_forms', 1 );
add_action( 'init', 'wpfa_add_rewrite_tags' );
add_action( 'init', 'wpfa_add_rewrite_rules' );

/* -----------------------------------------------------------------------
 * Classic sidebar widgets
 * -------------------------------------------------------------------- */
add_action( 'widgets_init', 'wpfa_register_widgets' );

/* -----------------------------------------------------------------------
 * Elementor assets — register only (not enqueue); Elementor pulls them
 * via get_script_depends() / get_style_depends() on each widget.
 * -------------------------------------------------------------------- */
add_action( 'wp_enqueue_scripts', 'wpfa_register_assets', 5 );

/* -----------------------------------------------------------------------
 * Frontend assets enqueue for non-Elementor / virtual-page contexts
 * -------------------------------------------------------------------- */
add_action( 'wp_enqueue_scripts', 'wpfa_enqueue_assets', 10 );
add_action( 'wp',                 'wpfa_remove_unneeded_head_items' );

/* -----------------------------------------------------------------------
 * Redirect logged-in users away from login/register
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'wpfa_maybe_redirect_logged_in_user', 1 );

/* -----------------------------------------------------------------------
 * Cache exclusion — auth pages must never be served from cache.
 *
 * FIX (v1.4.16): LiteSpeed Cache and Super Page Cache were caching 404
 * responses for /log-in/ etc. before rewrite rules were in place.
 * After rules are flushed the pages work, but the cached 404 keeps
 * being served. We now tell every major caching plugin to skip these
 * URLs and we send no-store headers as a universal fallback.
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'wpfa_exclude_from_cache', 0 );

/* -----------------------------------------------------------------------
 * URL rewrites
 * -------------------------------------------------------------------- */
add_filter( 'site_url',         'wpfa_filter_site_url',         10, 3 );
add_filter( 'network_site_url', 'wpfa_filter_site_url',         10, 3 );
add_filter( 'login_url',        'wpfa_filter_login_url',        10, 3 );
add_filter( 'logout_url',       'wpfa_filter_logout_url',       10, 2 );
add_filter( 'lostpassword_url', 'wpfa_filter_lostpassword_url', 10, 2 );

/* -----------------------------------------------------------------------
 * Virtual page support (for non-Elementor / plain-permalink installs)
 * These are no-ops when real pages exist with the same slug.
 * -------------------------------------------------------------------- */
add_filter( 'the_posts',          'wpfa_the_posts',      10, 2 );
add_filter( 'the_content',        'wpfa_maybe_inject_form', 20  );
add_filter( 'page_template',      'wpfa_page_template',  10    );
add_filter( 'body_class',         'wpfa_body_class',     10    );
add_filter( 'get_edit_post_link', 'wpfa_no_edit_link',   10, 2 );
add_filter( 'comments_array',     'wpfa_no_comments',    10    );

/* -----------------------------------------------------------------------
 * Handler functions
 * -------------------------------------------------------------------- */

function wpfa_add_rewrite_tags(): void {
    add_rewrite_tag( '%wpfa_action%', '([^/]+)' );
}

function wpfa_add_rewrite_rules(): void {
    if ( ! wpfa_use_permalinks() ) {
        return;
    }
    foreach ( wpfa()->get_actions() as $name => $action ) {
        // Only add rewrite rules for actions that don't already have a real page.
        // If the user has a real page at /login/, WordPress's own routing handles it.
        if ( wpfa_get_page_id( $name ) ) {
            continue;
        }
        $slug = wpfa_get_action_slug( $name );
        add_rewrite_rule( $slug . '/?$', 'index.php?wpfa_action=' . $name, 'top' );
    }
}

/**
 * Register assets (CSS + JS) without enqueueing.
 * Elementor widgets declare dependencies via get_script_depends() / get_style_depends(),
 * which requires the handles to be registered before Elementor calls wp_enqueue_script().
 */
function wpfa_register_assets(): void {
    $suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';

    wp_register_style(
        'wp-frontend-auth',
        WPFA_URL . "assets/styles/wp-frontend-auth{$suffix}.css",
        [],
        WPFA_VERSION
    );

    // Script registration: no strategy:'defer' here because Elementor widgets
    // may need the script and Elementor's own scripts are not deferred.
    // We enqueue with defer only on non-Elementor pages (see wpfa_enqueue_assets).
    wp_register_script(
        'wp-frontend-auth',
        WPFA_URL . "assets/scripts/wp-frontend-auth{$suffix}.js",
        [ 'jquery' ],
        WPFA_VERSION,
        [ 'in_footer' => true ]
    );
}

/**
 * Enqueue assets on non-Elementor WPFA pages (virtual rewrite pages).
 * On Elementor pages, Elementor pulls assets via widget dependency declarations.
 */
function wpfa_enqueue_assets(): void {
    // Never enqueue inside the Elementor editor/preview/REST context.
    if ( wpfa_is_elementor_context() ) {
        return;
    }

    if ( ! wpfa_is_wpfa_page() ) {
        return;
    }

    wp_enqueue_style( 'wp-frontend-auth' );
    wp_enqueue_script( 'wp-frontend-auth' );

    /*
     * BUG FIX (v1.4.3): const wpFrontendAuth declared twice — SyntaxError
     *
     * Previously this function contained a copy of the inline-script block
     * that also lives in wpfa_maybe_add_inline_script(). On a real WordPress
     * page built with Elementor widgets (not a virtual rewrite page):
     *
     *   1. wpfa_enqueue_assets() runs on wp_enqueue_scripts (priority 10).
     *      wpfa_is_elementor_context() returns FALSE on the public frontend
     *      (it only returns true in the editor, preview, AJAX, or REST
     *      contexts). wpfa_is_wpfa_page() returns TRUE. So the old code
     *      called wp_add_inline_script() and output "const wpFrontendAuth".
     *
     *   2. Elementor then calls Widget_Base::render() for each WPFA widget.
     *      render() calls wpfa_maybe_add_inline_script(), whose static $done
     *      flag was never set by step 1, so it called wp_add_inline_script()
     *      again — producing a second "const wpFrontendAuth" declaration.
     *
     *   Result: browser throws "Identifier 'wpFrontendAuth' has already been
     *   declared" and the entire wp-frontend-auth.js file fails to execute.
     *
     * Fix: delegate to wpfa_maybe_add_inline_script() here. Its static $done
     * flag is the single source of truth. Whichever path fires first sets the
     * flag; the other path becomes a no-op. No double-declaration is possible.
     */
    wpfa_maybe_add_inline_script();

    do_action( 'login_enqueue_scripts' );
}

/**
 * Inline script data for Elementor pages — called by Elementor widget render().
 * Outputs the wpFrontendAuth config object via wp_add_inline_script on the
 * registered handle so it always precedes the script regardless of load order.
 */
function wpfa_maybe_add_inline_script(): void {
    static $done = false;
    if ( $done ) {
        return;
    }
    $done = true;

    $script_data = wp_json_encode( apply_filters( 'wpfa_script_data', [
        'useAjax' => wpfa_use_ajax(),
        'action'  => wpfa_get_current_action(),
        'i18n'    => [
            'genericError'       => __( 'An error occurred. Please try again.', 'wp-frontend-auth' ),
            'show'               => __( 'Show', 'wp-frontend-auth' ),
            'hide'               => __( 'Hide', 'wp-frontend-auth' ),
            'passwordToggle'     => __( 'Toggle password visibility', 'wp-frontend-auth' ),
            'strengthVeryWeak'   => __( 'Very weak', 'wp-frontend-auth' ),
            'strengthWeak'       => __( 'Weak', 'wp-frontend-auth' ),
            'strengthGood'       => __( 'Good', 'wp-frontend-auth' ),
            'strengthStrong'     => __( 'Strong', 'wp-frontend-auth' ),
            'msgRegistered'      => __( 'Registration successful! Please check your email for login instructions.', 'wp-frontend-auth' ),
            'msgCheckEmail'      => __( 'Check your email for a link to reset your password.', 'wp-frontend-auth' ),
            'msgPasswordChanged' => __( 'Your password has been reset. You can now log in.', 'wp-frontend-auth' ),
        ],
    ] ) );

    if ( $script_data ) {
        wp_add_inline_script( 'wp-frontend-auth', 'const wpFrontendAuth = ' . $script_data . ';', 'before' );
    }
}

function wpfa_remove_unneeded_head_items(): void {
    if ( ! wpfa_is_wpfa_page() ) {
        return;
    }
    // Only strip these on virtual pages — real pages have real content.
    if ( get_query_var( 'wpfa_action', '' ) ) {
        remove_action( 'wp_head', 'feed_links',                      2  );
        remove_action( 'wp_head', 'feed_links_extra',                3  );
        remove_action( 'wp_head', 'rsd_link',                        10 );
        remove_action( 'wp_head', 'wlwmanifest_link',                10 );
        remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
        remove_filter( 'template_redirect', 'redirect_canonical'        );
    }
}

function wpfa_maybe_redirect_logged_in_user(): void {
    if ( wpfa_is_elementor_context() ) {
        return;
    }
    if ( ! is_user_logged_in() ) {
        return;
    }
    $action = wpfa_get_current_action();
    if ( ! in_array( $action, [ 'login', 'register' ], true ) ) {
        return;
    }

    // FIX: Do NOT redirect when reauth=1 is present.
    //
    // WordPress sets reauth=1 when it needs the user to confirm their credentials
    // before accessing a sensitive area (e.g. the admin dashboard after a long idle).
    // The user IS logged in but WordPress requires a fresh password entry.
    // If we redirect them away from the login page, they cannot re-authenticate and
    // end up in a redirect loop: admin → login (reauth=1) → admin → login → …
    //
    // Source: developer.wordpress.org/reference/functions/auth_redirect/
    //         core.trac.wordpress.org/browser/tags/6.7/src/wp-login.php#L840
    if ( ! empty( $_GET['reauth'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
        return;
    }

    // 1. Honour an explicit redirect_to if present.
    $redirect_to = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification
        ? wpfa_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
        : '';

    $user              = wp_get_current_user();
    $is_subscriber     = count( $user->roles ) === 1 && in_array( 'subscriber', $user->roles, true );
    $subscriber_default = wpfa_get_subscriber_redirect();

    if ( $is_subscriber ) {
        // Subscribers must never reach wp-admin.
        if ( empty( $redirect_to ) || str_starts_with( $redirect_to, admin_url() ) ) {
            $redirect_to = $subscriber_default;
        }
    } else {
        // Privileged users: honour redirect_to if present, otherwise home_url().
        // Do NOT default to admin_url() — if they landed on the login page without
        // a redirect_to they came directly, not from an admin auth_redirect() call.
        if ( empty( $redirect_to ) ) {
            $redirect_to = home_url();
        }
    }

    $redirect = apply_filters( 'wpfa_logged_in_redirect', $redirect_to );
    wp_safe_redirect( $redirect );
    exit;
}

/* -----------------------------------------------------------------------
 * Virtual post injection — only fires when NO real page exists for the action.
 * On Elementor sites with real pages this is a no-op.
 * -------------------------------------------------------------------- */

function wpfa_the_posts( array $posts, WP_Query $wp_query ): array {
    if ( ! $wp_query->is_main_query() ) {
        return $posts;
    }
    $action = get_query_var( 'wpfa_action', '' );
    if ( empty( $action ) || ! wpfa()->get_action( $action ) ) {
        return $posts;
    }
    // If a real page exists for this action, don't inject — real page wins.
    if ( wpfa_get_page_id( $action ) ) {
        return $posts;
    }

    $post = new WP_Post( (object) [
        'ID'                => -1,
        'post_author'       => 0,
        'post_status'       => 'publish',
        'post_date'         => current_time( 'mysql' ),
        'post_date_gmt'     => current_time( 'mysql', true ),
        'post_modified'     => current_time( 'mysql' ),
        'post_modified_gmt' => current_time( 'mysql', true ),
        'post_type'         => 'page',
        'post_content'      => '',
        'post_title'        => wpfa()->get_action( $action )['title'] ?? ucfirst( $action ),
        'post_excerpt'      => '',
        'post_name'         => wpfa_get_action_slug( $action ),
        'ping_status'       => 'closed',
        'comment_status'    => 'closed',
        'filter'            => 'raw',
        'guid'              => wpfa_get_action_url( $action ),
    ] );

    return [ $post ];
}

/**
 * Auto-render the auth form inside virtual pages and empty real WPFA pages.
 *
 * FIX (v1.4.15): Virtual pages injected by wpfa_the_posts() have empty post_content.
 * Without this filter, the theme renders a blank page — the user never sees a login form.
 * This filter injects the appropriate form HTML into the_content so that:
 *
 *   1. Virtual pages (non-Elementor sites) display the form automatically.
 *   2. Real WPFA pages that haven't had an Elementor widget added yet still work.
 *   3. Real pages that DO have content (Elementor widgets, shortcodes, manual HTML)
 *      are left untouched — we only inject when content is empty.
 *
 * Priority 20 runs after Elementor's own the_content filter (priority 9) and
 * WordPress core's wpautop/shortcode filters (priority 10-11).
 */
function wpfa_maybe_inject_form( string $content ): string {
    if ( ! in_the_loop() || ! is_main_query() ) {
        return $content;
    }
    // If content already has substance, another renderer (Elementor, shortcode, editor)
    // owns this page — do not duplicate the form.
    //
    // BUG FIX (v1.4.16): Elementor outputs empty wrapper divs even for pages with no
    // widgets (e.g. a freshly-created WPFA page before the Login widget is added):
    //   <div class="elementor elementor-123">...</div>
    // This non-empty string caused the form to never be injected, leaving a blank page.
    //
    // We strip all HTML tags and check if there is any visible text or meaningful
    // content. If the visible text is empty (only whitespace), we treat it as empty
    // and inject the form — regardless of wrapper markup from Elementor or the theme.
    //
    // We intentionally do NOT strip shortcodes before this check — a page that has
    // a [login_form] shortcode or similar already produces output and should be left alone.
    if ( '' !== trim( wp_strip_all_tags( $content ) ) ) {
        return $content;
    }
    $action = wpfa_get_current_action();
    if ( ! $action ) {
        return $content;
    }

    // Login: hide form if user is already logged in (unless reauth).
    if ( 'login' === $action && is_user_logged_in() ) {
        $is_reauth = ! empty( $_GET['reauth'] ); // phpcs:ignore WordPress.Security.NonceVerification
        if ( ! $is_reauth ) {
            return $content;
        }
    }

    // Register: show message if registration is disabled.
    if ( 'register' === $action && ! get_option( 'users_can_register' ) ) {
        return '<p>' . esc_html__( 'User registration is currently not allowed.', 'wp-frontend-auth' ) . '</p>';
    }

    // Reset password: show error if key/login params are absent.
    if ( 'resetpass' === $action ) {
        $rp_key   = $_GET['key']   ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        $rp_login = $_GET['login'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        if ( ! is_string( $rp_key ) || ! is_string( $rp_login ) || '' === $rp_key || '' === $rp_login ) {
            return '<div class="wpfa wpfa-form wpfa-form-resetpass">'
                . '<ul class="wpfa-errors" role="alert">'
                . '<li class="wpfa-error">' . esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'wp-frontend-auth' ) . '</li>'
                . '</ul>'
                . '<p class="wpfa-links"><a href="' . esc_url( wpfa_get_action_url( 'lostpassword' ) ) . '">'
                . esc_html__( 'Request a new password reset link', 'wp-frontend-auth' ) . '</a></p>'
                . '</div>';
        }
    }

    return wpfa_render_form( $action, [
        // FIX (v1.4.16): Pass redirect_to from the current URL into the form so it is
        // written as a hidden field. Without this, the handler receives no redirect_to
        // on POST and falls back to home_url() — even when the user arrived via e.g.
        // /log-in/?redirect_to=/dashboard/.
        'redirect_to' => isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification
            ? wpfa_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
            : '',
    ] );
}

function wpfa_page_template( string $template ): string {
    if ( ! get_query_var( 'wpfa_action', '' ) ) {
        return $template;
    }
    if ( function_exists( 'wp_is_block_theme' ) && wp_is_block_theme() ) {
        return $template;
    }
    if ( ABSPATH . WPINC . '/template-canvas.php' === $template ) {
        return $template;
    }
    $action     = get_query_var( 'wpfa_action', '' );
    $candidates = [
        "wp-frontend-auth-{$action}.php",
        "wpfa-{$action}.php",
        'wp-frontend-auth.php',
        'wpfa.php',
        'page.php',
    ];
    $found = locate_template( $candidates );
    return $found ?: $template;
}

function wpfa_body_class( array $classes ): array {
    if ( wpfa_is_wpfa_page() ) {
        $classes[] = 'wpfa-page';
        $action    = wpfa_get_current_action();
        if ( $action ) {
            $classes[] = 'wpfa-action-' . sanitize_html_class( $action );
        }
    }
    return $classes;
}

function wpfa_no_edit_link( $link, $post_id ) {
    return ( get_query_var( 'wpfa_action', '' ) && -1 === (int) $post_id ) ? '' : $link;
}

function wpfa_no_comments( array $comments ): array {
    return get_query_var( 'wpfa_action', '' ) ? [] : $comments;
}

/* -----------------------------------------------------------------------
 * URL filters — exemption registry
 *
 * Third-party plugins that use wp_login_url() as part of an OAuth or
 * other authentication flow (e.g. WordPress MCP Bridge) need the native
 * /wp-login.php URL, not the WPFA frontend /log-in/ page, because they
 * control the redirect_to value themselves and expect WordPress core's
 * login handler to be at the other end.
 *
 * Usage — from another plugin:
 *
 *   // Tell WPFA not to intercept login_url() in this REST request context.
 *   add_filter( 'wpfa_login_url_exempt', '__return_true' );
 *   $login = wp_login_url( $return );
 *   remove_filter( 'wpfa_login_url_exempt', '__return_true' );
 *
 * Or permanently opt out of WPFA's login_url rewriting for a specific
 * callback by inspecting the $redirect parameter inside a higher-priority
 * filter on 'wpfa_login_url_exempt'.
 *
 * The filter also fires automatically when the current request is a
 * non-Elementor REST API call that includes an OAuth redirect_uri
 * parameter, because that signature unambiguously identifies an OAuth
 * authorization-server flow that needs the native WP login page.
 * -------------------------------------------------------------------- */

/**
 * Return true when WPFA's login_url filter should stand aside.
 *
 * Checks in order:
 *  1. 'wpfa_login_url_exempt' filter — other plugins can hook here.
 *  2. REST_REQUEST in a non-Elementor, non-WPFA REST context that
 *     carries an OAuth redirect_uri parameter (MCP bridge, WP OAuth
 *     Server, etc.).
 *  3. The redirect parameter itself already contains a REST API URL for
 *     this site (e.g. /wp-json/mcp/v1/oauth/authorize?...) — WPFA's
 *     page would not know how to handle it.
 *
 * @param string $redirect  The redirect_to value passed to wp_login_url().
 */
function wpfa_is_login_url_exempt( string $redirect ): bool {
    // 1. Explicit opt-out from another plugin.
    if ( apply_filters( 'wpfa_login_url_exempt', false, $redirect ) ) {
        return true;
    }

    // 2. The redirect target is a REST endpoint on this site (e.g. MCP OAuth authorize URL).
    if ( '' !== $redirect && str_starts_with( $redirect, rest_url() ) ) {
        return true;
    }

    // 3. BUG FIX (v1.4.16): The current request IS a REST request for a non-Elementor
    //    route (e.g. /wp-json/mcp/v1/...). In this context, any wp-login.php reference
    //    that wpfa_filter_site_url() intercepts should go to the native login handler,
    //    because the MCP bridge and other OAuth plugins control the redirect themselves.
    //    wpfa_is_elementor_context() already exempts Elementor REST routes; this covers
    //    all other REST routes (MCP, WooCommerce, custom plugins, etc.).
    if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
        $route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
        // Only exempt non-Elementor REST routes — Elementor REST was already handled above.
        if ( '' !== $route && ! str_contains( (string) $route, '/elementor/' ) ) {
            return true;
        }
    }

    return false;
}

/* -----------------------------------------------------------------------
 * URL filters
 * -------------------------------------------------------------------- */

function wpfa_filter_login_url( string $login_url, string $redirect, bool $force_reauth ): string {
    if ( wpfa_is_elementor_context() ) {
        return $login_url;
    }
    // Exempt OAuth flows and other REST-based auth handlers (e.g. MCP Bridge).
    // See wpfa_is_login_url_exempt() for the full decision tree.
    if ( wpfa_is_login_url_exempt( $redirect ) ) {
        return $login_url;
    }
    global $pagenow;
    if ( 'wp-login.php' === $pagenow || is_customize_preview() ) {
        return $login_url;
    }
    if ( ! wpfa()->get_action( 'login' ) ) {
        return $login_url;
    }
    $url = wpfa_get_action_url( 'login' );
    if ( ! empty( $redirect ) ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
    }
    if ( $force_reauth ) {
        $url = add_query_arg( 'reauth', '1', $url );
    }
    return $url;
}

function wpfa_filter_site_url( string $url, string $path, $scheme ): string {
    global $pagenow;
    if ( wpfa_is_elementor_context() ) {
        return $url;
    }
    if ( 'wp-login.php' === $pagenow || is_customize_preview() ) {
        return $url;
    }
    $parsed = parse_url( $url );
    $base   = ! empty( $parsed['path'] ) ? basename( trim( $parsed['path'], '/' ) ) : '';
    $query  = [];
    if ( ! empty( $parsed['query'] ) ) {
        parse_str( $parsed['query'], $query );
    }
    if ( isset( $query['interim-login'] ) ) {
        return $url;
    }
    $map = [
        'wp-login.php'  => 'login',
        'wp-signup.php' => 'register',
    ];
    if ( ! isset( $map[ $base ] ) ) {
        return $url;
    }

    // BUG FIX (v1.4.16): Apply the same MCP/REST exemption that wpfa_filter_login_url()
    // already had. The MCP Bridge plugin (and other OAuth handlers) call site_url('wp-login.php')
    // directly — NOT wp_login_url() — so the exemption in wpfa_filter_login_url() never fired.
    // Result: MCP OAuth redirects pointed to the WPFA /login/ page instead of /wp-login.php,
    // breaking the authorization flow.
    //
    // Build a synthetic redirect from the full URL so wpfa_is_login_url_exempt() can
    // inspect whether the destination is a REST endpoint on this site.
    $synthetic_redirect = $url;
    if ( wpfa_is_login_url_exempt( $synthetic_redirect ) ) {
        return $url;
    }
    $action_from_query = $query['action'] ?? '';
    if ( is_array( $action_from_query ) ) {
        return $url;
    }
    $action = 'wp-login.php' === $base
        ? ( '' !== $action_from_query ? $action_from_query : 'login' )
        : $map[ $base ];

    if ( 'retrievepassword' === $action ) {
        $action = 'lostpassword';
    } elseif ( 'rp' === $action ) {
        $action = 'resetpass';
    }
    if ( ! wpfa()->get_action( $action ) ) {
        return $url;
    }
    unset( $query['action'] );
    $new_url = wpfa_get_action_url( $action, 'network_site_url' === current_filter() );
    return add_query_arg( $query, $new_url );
}

function wpfa_filter_logout_url( string $url, string $redirect ): string {
    if ( ! wpfa()->get_action( 'logout' ) ) {
        return $url;
    }
    $url = wpfa_get_action_url( 'logout' );
    if ( ! empty( $redirect ) ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
    }
    return wp_nonce_url( $url, 'log-out' );
}

function wpfa_filter_lostpassword_url( string $url, string $redirect ): string {
    global $pagenow;
    if ( 'wp-login.php' === $pagenow ) {
        return $url;
    }
    if ( ! wpfa()->get_action( 'lostpassword' ) ) {
        return $url;
    }
    $url = wpfa_get_action_url( 'lostpassword' );
    if ( ! empty( $redirect ) ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
    }
    return $url;
}

/* -----------------------------------------------------------------------
 * Cache exclusion
 * -------------------------------------------------------------------- */

/**
 * Tell every known caching plugin not to cache the current page, and
 * emit no-store HTTP headers as a universal fallback.
 *
 * Called at template_redirect priority 0 — before WordPress decides on a
 * template, so caching plugins that hook template_redirect at priority 1
 * (e.g. LiteSpeed Cache, WP Rocket) see our opt-out first.
 */
function wpfa_exclude_from_cache(): void {
    if ( ! wpfa_is_wpfa_page() ) {
        return;
    }

    // ── Universal: HTTP headers ──────────────────────────────────────────
    // Sent before any output; tells CDNs, proxies, and browser caches
    // not to store the response.
    if ( ! headers_sent() ) {
        header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
        header( 'Pragma: no-cache' );
        header( 'Expires: Thu, 01 Jan 1970 00:00:00 GMT' );
    }

    // ── LiteSpeed Cache ──────────────────────────────────────────────────
    // The X-LiteSpeed-Cache-Control header tells the LiteSpeed server
    // (or OpenLiteSpeed) not to cache this response at the server level.
    // The do_action call tells the LiteSpeed Cache WordPress plugin.
    if ( ! headers_sent() ) {
        header( 'X-LiteSpeed-Cache-Control: no-cache' );
    }
    // LiteSpeed Cache plugin API (class_exists guard — plugin may not be active)
    if ( class_exists( 'LiteSpeed_Cache_API' ) && method_exists( 'LiteSpeed_Cache_API', 'no_cache' ) ) {
        LiteSpeed_Cache_API::no_cache( 'wpfa-auth-page' );
    }
    // Modern LiteSpeed Cache 4.x+ API
    do_action( 'litespeed_control_set_nocache', 'wpfa auth page' );

    // ── Super Page Cache ─────────────────────────────────────────────────
    // Super Page Cache checks for this constant to skip caching.
    if ( ! defined( 'DONOTCACHEPAGE' ) ) {
        define( 'DONOTCACHEPAGE', true );
    }

    // ── WP Rocket ────────────────────────────────────────────────────────
    if ( ! defined( 'DONOTROCKETOPTIMIZE' ) ) {
        define( 'DONOTROCKETOPTIMIZE', true );
    }

    // ── W3 Total Cache ───────────────────────────────────────────────────
    if ( ! defined( 'DONOTCACHEOBJECT' ) ) {
        define( 'DONOTCACHEOBJECT', true );
    }
    if ( ! defined( 'DONOTMINIFY' ) ) {
        define( 'DONOTMINIFY', true );
    }

    // ── WP Super Cache ───────────────────────────────────────────────────
    // (different plugin from Super Page Cache — both check DONOTCACHEPAGE)

    // ── Kinsta / Cloudflare / generic object cache bypass ────────────────
    do_action( 'wpfa_exclude_from_cache' ); // allow third-party hooks
}

/**
 * Purge cached versions of all WPFA pages from LiteSpeed Cache and
 * Super Page Cache when the plugin version changes (e.g. after update).
 *
 * Called from wpfa_maybe_upgrade() via the 'wpfa_after_upgrade' action.
 */
function wpfa_purge_auth_page_cache(): void {
    $urls = [];
    foreach ( array_keys( wpfa_get_page_actions() ) as $action ) {
        $urls[] = wpfa_get_action_url( $action );
    }

    // LiteSpeed Cache — purge by URL
    foreach ( $urls as $url ) {
        do_action( 'litespeed_purge_url', $url );
    }

    // Super Page Cache — purge all (no per-URL API in most versions)
    if ( function_exists( 'super_cache_purge_all' ) ) {
        super_cache_purge_all();
    }
    // WP Super Cache
    if ( function_exists( 'wp_cache_clean_cache' ) ) {
        global $file_prefix;
        wp_cache_clean_cache( $file_prefix ?? 'wp-cache-', true );
    }
    // WP Rocket
    if ( function_exists( 'rocket_clean_domain' ) ) {
        rocket_clean_domain();
    }
}

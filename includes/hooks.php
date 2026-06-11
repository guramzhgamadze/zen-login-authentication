<?php
/**
 * Frontend Auth – Hooks
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Init
 * -------------------------------------------------------------------- */
add_action( 'init', 'fauth_register_default_forms', 1 );
add_action( 'init', 'fauth_add_rewrite_tags' );
add_action( 'init', 'fauth_add_rewrite_rules' );

/* -----------------------------------------------------------------------
 * Classic sidebar widgets
 * -------------------------------------------------------------------- */
add_action( 'widgets_init', 'fauth_register_widgets' );

/* -----------------------------------------------------------------------
 * Elementor assets — register only (not enqueue); Elementor pulls them
 * via get_script_depends() / get_style_depends() on each widget.
 * -------------------------------------------------------------------- */
add_action( 'wp_enqueue_scripts', 'fauth_register_assets', 5 );

/* -----------------------------------------------------------------------
 * Frontend assets enqueue for non-Elementor / virtual-page contexts
 * -------------------------------------------------------------------- */
add_action( 'wp_enqueue_scripts', 'fauth_enqueue_assets', 10 );
add_action( 'wp',                 'fauth_remove_unneeded_head_items' );

/* -----------------------------------------------------------------------
 * Redirect logged-in users away from login/register
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'fauth_maybe_redirect_logged_in_user', 1 );

/* -----------------------------------------------------------------------
 * Subscriber containment — applies to ALL login paths (front-end form,
 * wp-login.php, third-party flows) and blocks wp-admin for subscribers.
 * -------------------------------------------------------------------- */
add_filter( 'login_redirect', 'fauth_subscriber_login_redirect', 100, 3 );
add_action( 'admin_init',     'fauth_block_subscriber_admin' );

/* -----------------------------------------------------------------------
 * Cache exclusion — auth pages must never be served from cache.
 *
 * FIX (v1.4.16): LiteSpeed Cache and Super Page Cache were caching 404
 * responses for /log-in/ etc. before rewrite rules were in place.
 * After rules are flushed the pages work, but the cached 404 keeps
 * being served. We now tell every major caching plugin to skip these
 * URLs and we send no-store headers as a universal fallback.
 * -------------------------------------------------------------------- */
add_action( 'template_redirect', 'fauth_exclude_from_cache', 0 );

/* -----------------------------------------------------------------------
 * URL rewrites
 * -------------------------------------------------------------------- */
add_filter( 'site_url',         'fauth_filter_site_url',         10, 3 );
add_filter( 'network_site_url', 'fauth_filter_site_url',         10, 3 );
add_filter( 'login_url',        'fauth_filter_login_url',        10, 3 );
add_filter( 'logout_url',       'fauth_filter_logout_url',       10, 2 );
add_filter( 'lostpassword_url', 'fauth_filter_lostpassword_url', 10, 2 );

/* -----------------------------------------------------------------------
 * Virtual page support (for non-Elementor / plain-permalink installs)
 * These are no-ops when real pages exist with the same slug.
 * -------------------------------------------------------------------- */
add_filter( 'the_posts',          'fauth_the_posts',      10, 2 );
add_filter( 'the_content',        'fauth_maybe_inject_form', 20  );
add_filter( 'page_template',      'fauth_page_template',  10    );
add_filter( 'body_class',         'fauth_body_class',     10    );
add_filter( 'get_edit_post_link', 'fauth_no_edit_link',   10, 2 );
add_filter( 'comments_array',     'fauth_no_comments',    10    );

/* -----------------------------------------------------------------------
 * Handler functions
 * -------------------------------------------------------------------- */

function fauth_add_rewrite_tags(): void {
    add_rewrite_tag( '%fauth_action%', '([^/]+)' );
}

function fauth_add_rewrite_rules(): void {
    if ( ! fauth_use_permalinks() ) {
        return;
    }
    foreach ( fauth()->get_actions() as $name => $action ) {
        // Only add rewrite rules for actions that don't already have a real page.
        // If the user has a real page at /login/, WordPress's own routing handles it.
        if ( fauth_get_page_id( $name ) ) {
            continue;
        }
        $slug = fauth_get_action_slug( $name );
        add_rewrite_rule( $slug . '/?$', 'index.php?fauth_action=' . $name, 'top' );
    }
}

/**
 * Register assets (CSS + JS) without enqueueing.
 * Elementor widgets declare dependencies via get_script_depends() / get_style_depends(),
 * which requires the handles to be registered before Elementor calls wp_enqueue_script().
 */
function fauth_register_assets(): void {
    $suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';

    wp_register_style(
        'frontend-auth',
        FAUTH_URL . "assets/styles/frontend-auth{$suffix}.css",
        [],
        FAUTH_VERSION
    );

    // Script registration: no strategy:'defer' here because Elementor widgets
    // may need the script and Elementor's own scripts are not deferred.
    // We enqueue with defer only on non-Elementor pages (see fauth_enqueue_assets).
    wp_register_script(
        'frontend-auth',
        FAUTH_URL . "assets/scripts/frontend-auth{$suffix}.js",
        [ 'jquery' ],
        FAUTH_VERSION,
        [ 'in_footer' => true ]
    );
}

/**
 * Enqueue assets on non-Elementor FAUTH pages (virtual rewrite pages).
 * On Elementor pages, Elementor pulls assets via widget dependency declarations.
 */
function fauth_enqueue_assets(): void {
    // Never enqueue inside the Elementor editor/preview/REST context.
    if ( fauth_is_elementor_context() ) {
        return;
    }

    if ( ! fauth_is_fauth_page() ) {
        return;
    }

    wp_enqueue_style( 'frontend-auth' );
    wp_enqueue_script( 'frontend-auth' );

    /*
     * BUG FIX (v1.4.3): const fauthConfig declared twice — SyntaxError
     *
     * Previously this function contained a copy of the inline-script block
     * that also lives in fauth_maybe_add_inline_script(). On a real WordPress
     * page built with Elementor widgets (not a virtual rewrite page):
     *
     *   1. fauth_enqueue_assets() runs on wp_enqueue_scripts (priority 10).
     *      fauth_is_elementor_context() returns FALSE on the public frontend
     *      (it only returns true in the editor, preview, AJAX, or REST
     *      contexts). fauth_is_fauth_page() returns TRUE. So the old code
     *      called wp_add_inline_script() and output "const fauthConfig".
     *
     *   2. Elementor then calls Widget_Base::render() for each FAUTH widget.
     *      render() calls fauth_maybe_add_inline_script(), whose static $done
     *      flag was never set by step 1, so it called wp_add_inline_script()
     *      again — producing a second "const fauthConfig" declaration.
     *
     *   Result: browser throws "Identifier 'fauthConfig' has already been
     *   declared" and the entire frontend-auth.js file fails to execute.
     *
     * Fix: delegate to fauth_maybe_add_inline_script() here. Its static $done
     * flag is the single source of truth. Whichever path fires first sets the
     * flag; the other path becomes a no-op. No double-declaration is possible.
     */
    fauth_maybe_add_inline_script();

    do_action( 'login_enqueue_scripts' );
}

/**
 * Inline script data for Elementor pages — called by Elementor widget render().
 * Outputs the fauthConfig config object via wp_add_inline_script on the
 * registered handle so it always precedes the script regardless of load order.
 */
function fauth_maybe_add_inline_script(): void {
    static $done = false;
    if ( $done ) {
        return;
    }
    $done = true;

    $script_data = wp_json_encode( apply_filters( 'fauth_script_data', [
        'useAjax' => fauth_use_ajax(),
        'action'  => fauth_get_current_action(),
        'i18n'    => [
            'genericError'       => __( 'An error occurred. Please try again.', 'frontend-auth' ),
            'show'               => __( 'Show', 'frontend-auth' ),
            'hide'               => __( 'Hide', 'frontend-auth' ),
            'passwordToggle'     => __( 'Toggle password visibility', 'frontend-auth' ),
            'strengthVeryWeak'   => __( 'Very weak', 'frontend-auth' ),
            'strengthWeak'       => __( 'Weak', 'frontend-auth' ),
            'strengthGood'       => __( 'Good', 'frontend-auth' ),
            'strengthStrong'     => __( 'Strong', 'frontend-auth' ),
            'msgRegistered'      => __( 'Registration successful! Please check your email for login instructions.', 'frontend-auth' ),
            'msgCheckEmail'      => __( 'Check your email for a link to reset your password.', 'frontend-auth' ),
            'msgPasswordChanged' => __( 'Your password has been reset. You can now log in.', 'frontend-auth' ),
        ],
    ] ) );

    if ( $script_data ) {
        wp_add_inline_script( 'frontend-auth', 'const fauthConfig = ' . $script_data . ';', 'before' );
    }
}

function fauth_remove_unneeded_head_items(): void {
    if ( ! fauth_is_fauth_page() ) {
        return;
    }
    // Only strip these on virtual pages — real pages have real content.
    if ( get_query_var( 'fauth_action', '' ) ) {
        remove_action( 'wp_head', 'feed_links',                      2  );
        remove_action( 'wp_head', 'feed_links_extra',                3  );
        remove_action( 'wp_head', 'rsd_link',                        10 );
        remove_action( 'wp_head', 'wlwmanifest_link',                10 );
        remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
        remove_filter( 'template_redirect', 'redirect_canonical'        );
    }
}

function fauth_maybe_redirect_logged_in_user(): void {
    if ( fauth_is_elementor_context() ) {
        return;
    }
    if ( ! is_user_logged_in() ) {
        return;
    }
    $action = fauth_get_current_action();
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
        ? fauth_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
        : '';

    $user              = wp_get_current_user();
    $is_subscriber     = fauth_user_is_restricted_subscriber( $user );
    $subscriber_default = fauth_get_subscriber_redirect();

    if ( $is_subscriber ) {
        // Subscribers always go to the configured Subscriber redirect (never
        // wp-admin, and overriding any redirect_to in the URL/form).
        $redirect_to = (string) apply_filters( 'fauth_subscriber_login_redirect_to', $subscriber_default, $redirect_to, $user );
    } elseif ( empty( $redirect_to ) ) {
        // Privileged users: honour redirect_to if present, otherwise home_url().
        // Do NOT default to admin_url() — if they landed on the login page without
        // a redirect_to they came directly, not from an admin auth_redirect() call.
        $redirect_to = home_url();
    }

    $redirect = apply_filters( 'fauth_logged_in_redirect', $redirect_to );
    wp_safe_redirect( $redirect );
    exit;
}

/**
 * Force restricted subscribers to the configured Subscriber redirect after login,
 * no matter which login form was used. Runs at priority 100 so it wins over other
 * plugins/themes that hook `login_redirect` (the usual reason a configured
 * subscriber destination "doesn't work").
 *
 * An explicit, non-admin destination the user actually requested is still honoured;
 * only an empty or wp-admin target is overridden.
 *
 * @param string $redirect_to           Destination WordPress resolved.
 * @param string $requested_redirect_to The requested redirect_to value.
 * @param mixed  $user                  WP_User on success, WP_Error otherwise.
 * @return string
 */
function fauth_subscriber_login_redirect( $redirect_to, $requested_redirect_to, $user ): string {
    if ( ! fauth_user_is_restricted_subscriber( $user ) ) {
        return (string) $redirect_to;
    }
    // Subscribers always go to the configured Subscriber redirect, overriding any
    // requested redirect_to (which is commonly hardcoded to the home URL by a
    // Login widget's "Redirect URL" control). Return $requested_redirect_to from
    // the filter to honour explicit per-login redirects for subscribers instead.
    return (string) apply_filters( 'fauth_subscriber_login_redirect_to', fauth_get_subscriber_redirect(), (string) $requested_redirect_to, $user );
}

/**
 * Keep restricted subscribers out of wp-admin: any wp-admin request from such a
 * user is redirected to the Subscriber redirect destination (the site home page
 * by default). admin-ajax.php is exempt so front-end AJAX keeps working.
 */
function fauth_block_subscriber_admin(): void {
    if ( wp_doing_ajax() ) {
        return; // never break admin-ajax.php
    }
    global $pagenow;
    // Never interfere with the wp-admin action endpoints used by logout handlers,
    // form processors, and other programmatic flows.
    if ( in_array( $pagenow, [ 'admin-post.php', 'admin-ajax.php' ], true ) ) {
        return;
    }
    // Always let a logout request complete.
    $req_action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) // phpcs:ignore WordPress.Security.NonceVerification
        ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) // phpcs:ignore WordPress.Security.NonceVerification
        : '';
    if ( 'logout' === $req_action || isset( $_GET['loggedout'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
        return;
    }
    if ( ! is_user_logged_in() ) {
        return;
    }
    if ( ! fauth_user_is_restricted_subscriber( wp_get_current_user() ) ) {
        return;
    }
    wp_safe_redirect( fauth_get_subscriber_redirect() );
    exit;
}

/* -----------------------------------------------------------------------
 * Virtual post injection — only fires when NO real page exists for the action.
 * On Elementor sites with real pages this is a no-op.
 * -------------------------------------------------------------------- */

function fauth_the_posts( array $posts, WP_Query $wp_query ): array {
    if ( ! $wp_query->is_main_query() ) {
        return $posts;
    }
    $action = get_query_var( 'fauth_action', '' );
    if ( empty( $action ) || ! fauth()->get_action( $action ) ) {
        return $posts;
    }
    // If a real page exists for this action, don't inject — real page wins.
    if ( fauth_get_page_id( $action ) ) {
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
        'post_title'        => fauth()->get_action( $action )['title'] ?? ucfirst( $action ),
        'post_excerpt'      => '',
        'post_name'         => fauth_get_action_slug( $action ),
        'ping_status'       => 'closed',
        'comment_status'    => 'closed',
        'filter'            => 'raw',
        'guid'              => fauth_get_action_url( $action ),
    ] );

    return [ $post ];
}

/**
 * Auto-render the auth form inside virtual pages and empty real FAUTH pages.
 *
 * FIX (v1.4.15): Virtual pages injected by fauth_the_posts() have empty post_content.
 * Without this filter, the theme renders a blank page — the user never sees a login form.
 * This filter injects the appropriate form HTML into the_content so that:
 *
 *   1. Virtual pages (non-Elementor sites) display the form automatically.
 *   2. Real FAUTH pages that haven't had an Elementor widget added yet still work.
 *   3. Real pages that DO have content (Elementor widgets, shortcodes, manual HTML)
 *      are left untouched — we only inject when content is empty.
 *
 * Priority 20 runs after Elementor's own the_content filter (priority 9) and
 * WordPress core's wpautop/shortcode filters (priority 10-11).
 */
function fauth_maybe_inject_form( string $content ): string {
    if ( ! in_the_loop() || ! is_main_query() ) {
        return $content;
    }
    // If content already has substance, another renderer (Elementor, shortcode, editor)
    // owns this page — do not duplicate the form.
    //
    // BUG FIX (v1.4.16): Elementor outputs empty wrapper divs even for pages with no
    // widgets (e.g. a freshly-created FAUTH page before the Login widget is added):
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
    $action = fauth_get_current_action();
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
        return '<p>' . esc_html__( 'User registration is currently not allowed.', 'frontend-auth' ) . '</p>';
    }

    // Reset password: show error if key/login params are absent.
    if ( 'resetpass' === $action ) {
        $rp_key   = $_GET['key']   ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        $rp_login = $_GET['login'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        if ( ! is_string( $rp_key ) || ! is_string( $rp_login ) || '' === $rp_key || '' === $rp_login ) {
            return '<div class="fauth fauth-form fauth-form-resetpass">'
                . '<ul class="fauth-errors" role="alert">'
                . '<li class="fauth-error">' . esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'frontend-auth' ) . '</li>'
                . '</ul>'
                . '<p class="fauth-links"><a href="' . esc_url( fauth_get_action_url( 'lostpassword' ) ) . '">'
                . esc_html__( 'Request a new password reset link', 'frontend-auth' ) . '</a></p>'
                . '</div>';
        }
    }

    return fauth_render_form( $action, [
        // FIX (v1.4.16): Pass redirect_to from the current URL into the form so it is
        // written as a hidden field. Without this, the handler receives no redirect_to
        // on POST and falls back to home_url() — even when the user arrived via e.g.
        // /log-in/?redirect_to=/dashboard/.
        'redirect_to' => isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification
            ? fauth_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
            : '',
    ] );
}

function fauth_page_template( string $template ): string {
    if ( ! get_query_var( 'fauth_action', '' ) ) {
        return $template;
    }
    if ( function_exists( 'wp_is_block_theme' ) && wp_is_block_theme() ) {
        return $template;
    }
    if ( ABSPATH . WPINC . '/template-canvas.php' === $template ) {
        return $template;
    }
    $action     = get_query_var( 'fauth_action', '' );
    $candidates = [
        "frontend-auth-{$action}.php",
        "fauth-{$action}.php",
        'frontend-auth.php',
        'fauth.php',
        'page.php',
    ];
    $found = locate_template( $candidates );
    return $found ?: $template;
}

function fauth_body_class( array $classes ): array {
    if ( fauth_is_fauth_page() ) {
        $classes[] = 'fauth-page';
        $action    = fauth_get_current_action();
        if ( $action ) {
            $classes[] = 'fauth-action-' . sanitize_html_class( $action );
        }
    }
    return $classes;
}

function fauth_no_edit_link( $link, $post_id ) {
    return ( get_query_var( 'fauth_action', '' ) && -1 === (int) $post_id ) ? '' : $link;
}

function fauth_no_comments( array $comments ): array {
    return get_query_var( 'fauth_action', '' ) ? [] : $comments;
}

/* -----------------------------------------------------------------------
 * URL filters — exemption registry
 *
 * Third-party plugins that use wp_login_url() as part of an OAuth or
 * other authentication flow (e.g. WordPress MCP Bridge) need the native
 * /wp-login.php URL, not the FAUTH frontend /log-in/ page, because they
 * control the redirect_to value themselves and expect WordPress core's
 * login handler to be at the other end.
 *
 * Usage — from another plugin:
 *
 *   // Tell FAUTH not to intercept login_url() in this REST request context.
 *   add_filter( 'fauth_login_url_exempt', '__return_true' );
 *   $login = wp_login_url( $return );
 *   remove_filter( 'fauth_login_url_exempt', '__return_true' );
 *
 * Or permanently opt out of FAUTH's login_url rewriting for a specific
 * callback by inspecting the $redirect parameter inside a higher-priority
 * filter on 'fauth_login_url_exempt'.
 *
 * The filter also fires automatically when the current request is a
 * non-Elementor REST API call that includes an OAuth redirect_uri
 * parameter, because that signature unambiguously identifies an OAuth
 * authorization-server flow that needs the native WP login page.
 * -------------------------------------------------------------------- */

/**
 * Return true when FAUTH's login_url filter should stand aside.
 *
 * Checks in order:
 *  1. 'fauth_login_url_exempt' filter — other plugins can hook here.
 *  2. REST_REQUEST in a non-Elementor, non-FAUTH REST context that
 *     carries an OAuth redirect_uri parameter (MCP bridge, WP OAuth
 *     Server, etc.).
 *  3. The redirect parameter itself already contains a REST API URL for
 *     this site (e.g. /wp-json/mcp/v1/oauth/authorize?...) — FAUTH's
 *     page would not know how to handle it.
 *
 * @param string $redirect  The redirect_to value passed to wp_login_url().
 */
function fauth_is_login_url_exempt( string $redirect ): bool {
    // 1. Explicit opt-out from another plugin.
    if ( apply_filters( 'fauth_login_url_exempt', false, $redirect ) ) {
        return true;
    }

    // 2. The redirect target is a REST endpoint on this site (e.g. MCP OAuth authorize URL).
    if ( '' !== $redirect && str_starts_with( $redirect, rest_url() ) ) {
        return true;
    }

    // 3. BUG FIX (v1.4.16): The current request IS a REST request for a non-Elementor
    //    route (e.g. /wp-json/mcp/v1/...). In this context, any wp-login.php reference
    //    that fauth_filter_site_url() intercepts should go to the native login handler,
    //    because the MCP bridge and other OAuth plugins control the redirect themselves.
    //    fauth_is_elementor_context() already exempts Elementor REST routes; this covers
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

function fauth_filter_login_url( string $login_url, string $redirect, bool $force_reauth ): string {
    if ( fauth_is_elementor_context() ) {
        return $login_url;
    }
    // Exempt OAuth flows and other REST-based auth handlers (e.g. MCP Bridge).
    // See fauth_is_login_url_exempt() for the full decision tree.
    if ( fauth_is_login_url_exempt( $redirect ) ) {
        return $login_url;
    }
    global $pagenow;
    if ( 'wp-login.php' === $pagenow || is_customize_preview() ) {
        return $login_url;
    }
    if ( ! fauth()->get_action( 'login' ) ) {
        return $login_url;
    }
    $url = fauth_get_action_url( 'login' );
    if ( ! empty( $redirect ) ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
    }
    if ( $force_reauth ) {
        $url = add_query_arg( 'reauth', '1', $url );
    }
    return $url;
}

function fauth_filter_site_url( string $url, string $path, $scheme ): string {
    global $pagenow;
    if ( fauth_is_elementor_context() ) {
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

    // BUG FIX (v1.4.16): Apply the same MCP/REST exemption that fauth_filter_login_url()
    // already had. The MCP Bridge plugin (and other OAuth handlers) call site_url('wp-login.php')
    // directly — NOT wp_login_url() — so the exemption in fauth_filter_login_url() never fired.
    // Result: MCP OAuth redirects pointed to the FAUTH /login/ page instead of /wp-login.php,
    // breaking the authorization flow.
    //
    // Build a synthetic redirect from the full URL so fauth_is_login_url_exempt() can
    // inspect whether the destination is a REST endpoint on this site.
    $synthetic_redirect = $url;
    if ( fauth_is_login_url_exempt( $synthetic_redirect ) ) {
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
    if ( ! fauth()->get_action( $action ) ) {
        return $url;
    }
    unset( $query['action'] );
    $new_url = fauth_get_action_url( $action, 'network_site_url' === current_filter() );
    return add_query_arg( $query, $new_url );
}

function fauth_filter_logout_url( string $url, string $redirect ): string {
    if ( ! fauth()->get_action( 'logout' ) ) {
        return $url;
    }
    $url = fauth_get_action_url( 'logout' );
    if ( ! empty( $redirect ) ) {
        $url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
    }
    return wp_nonce_url( $url, 'log-out' );
}

function fauth_filter_lostpassword_url( string $url, string $redirect ): string {
    global $pagenow;
    if ( 'wp-login.php' === $pagenow ) {
        return $url;
    }
    if ( ! fauth()->get_action( 'lostpassword' ) ) {
        return $url;
    }
    $url = fauth_get_action_url( 'lostpassword' );
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
function fauth_exclude_from_cache(): void {
    if ( ! fauth_is_fauth_page() ) {
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
        LiteSpeed_Cache_API::no_cache( 'fauth-auth-page' );
    }
    // Modern LiteSpeed Cache 4.x+ API
    do_action( 'litespeed_control_set_nocache', 'fauth auth page' );

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
    do_action( 'fauth_exclude_from_cache' ); // allow third-party hooks
}

/**
 * Purge cached versions of all FAUTH pages from LiteSpeed Cache and
 * Super Page Cache when the plugin version changes (e.g. after update).
 *
 * Called from fauth_maybe_upgrade() via the 'fauth_after_upgrade' action.
 */
function fauth_purge_auth_page_cache(): void {
    $urls = [];
    foreach ( array_keys( fauth_get_page_actions() ) as $action ) {
        $urls[] = fauth_get_action_url( $action );
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

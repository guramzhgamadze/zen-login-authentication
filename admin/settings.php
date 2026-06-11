<?php
/**
 * Frontend Auth – Admin Settings
 *
 * Modern admin panel with card-based layout.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Menu registration — top-level sidebar item
 * -------------------------------------------------------------------- */
add_action( 'admin_menu', 'wpfa_admin_add_menu' );

function wpfa_admin_add_menu(): void {
    add_menu_page(
        __( 'Frontend Auth', 'frontend-auth' ),
        __( 'Frontend Auth', 'frontend-auth' ),
        'manage_options',
        'frontend-auth',
        'wpfa_admin_settings_page',
        'dashicons-lock',
        71
    );
}

/* -----------------------------------------------------------------------
 * Register settings (WP Settings API — handles nonce + sanitization)
 * -------------------------------------------------------------------- */
add_action( 'admin_init',    'wpfa_admin_register_settings' );
// Fix 3 — register_setting() sanitize_callback applies on REST saves only when
// hooked to rest_api_init too. Source: developer.wordpress.org/reference/functions/register_setting/
add_action( 'rest_api_init', 'wpfa_admin_register_settings' );

function wpfa_admin_register_settings(): void {
    // General
    $general = [
        'wpfa_login_type'      => 'wpfa_sanitize_login_type',
        'wpfa_use_permalinks'  => 'absint',
        'wpfa_use_ajax'        => 'absint',
        'wpfa_user_passwords'  => 'absint',
        'wpfa_auto_login'      => 'absint',
        'wpfa_honeypot'        => 'absint',
    ];
    // Fix 7 — autoload:false (no need to load auth options on every page request).
    // Fix 9 — type declaration for proper schema and REST validation.
    foreach ( $general as $id => $sanitize ) {
        register_setting( 'frontend-auth', $id, [
            'sanitize_callback' => $sanitize,
            'type'              => 'string',
            'autoload'          => false,
        ] );
    }

    // Rate limiting
    register_setting( 'frontend-auth', 'wpfa_rate_limit',        [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    register_setting( 'frontend-auth', 'wpfa_rate_limit_window', [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );

    // Per-action rate-limit toggles + threshold overrides (v1.4.18).
    // Toggles default to true (rendered as checkbox: 1=on, missing=off).
    // Overrides default to 0 (means "use global default"); positive int wins.
    $rl_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];
    foreach ( $rl_actions as $action ) {
        register_setting( 'frontend-auth', "wpfa_rl_enabled_{$action}", [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
        register_setting( 'frontend-auth', "wpfa_rl_max_{$action}",     [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    }
    register_setting( 'frontend-auth', 'wpfa_lostpassword_count_all', [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );

    // Subscriber post-login redirect: page slug/path or full URL; empty = site home.
    register_setting( 'frontend-auth', 'wpfa_subscriber_redirect', [ 'sanitize_callback' => 'wpfa_sanitize_redirect_target', 'type' => 'string', 'autoload' => false ] );

    // Sign in with Google (v1.5.0).
    register_setting( 'frontend-auth', 'wpfa_google_enabled',            [ 'sanitize_callback' => 'absint',              'type' => 'integer', 'autoload' => false ] );
    register_setting( 'frontend-auth', 'wpfa_google_client_id',          [ 'sanitize_callback' => 'sanitize_text_field', 'type' => 'string',  'autoload' => false ] );
    register_setting( 'frontend-auth', 'wpfa_google_client_secret',      [ 'sanitize_callback' => 'wpfa_sanitize_google_secret', 'type' => 'string', 'autoload' => false ] );
    register_setting( 'frontend-auth', 'wpfa_google_allow_registration', [ 'sanitize_callback' => 'absint',              'type' => 'integer', 'autoload' => false ] );

    // Slugs
    $slug_actions = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass' ];
    foreach ( $slug_actions as $action ) {
        register_setting( 'frontend-auth', "wpfa_slug_{$action}", [ 'sanitize_callback' => 'sanitize_title', 'type' => 'string', 'autoload' => false ] );
    }
}

function wpfa_sanitize_login_type( $value ): string {
    $allowed = [ 'default', 'username', 'email' ];
    $value   = sanitize_text_field( (string) $value );
    return in_array( $value, $allowed, true ) ? $value : 'default';
}

/**
 * Sanitize the subscriber-redirect target. Accepts a slug/path or a full URL.
 * Stored as plain text; same-host safety is enforced at redirect time by
 * wpfa_get_subscriber_redirect() (home_url) and wp_safe_redirect().
 */
function wpfa_sanitize_redirect_target( $value ): string {
    return trim( sanitize_text_field( (string) $value ) );
}

/* -----------------------------------------------------------------------
 * Settings page HTML — modern card-based design
 * -------------------------------------------------------------------- */

function wpfa_admin_settings_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    ?>
    <style>
        .wpfa-admin { max-width: 780px; margin: 20px auto 40px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .wpfa-admin-header { display: flex; align-items: center; gap: 14px; margin-bottom: 28px; }
        .wpfa-admin-header h1 { font-size: 1.6rem; font-weight: 700; margin: 0; color: #1d2327; }
        .wpfa-admin-header .wpfa-ver { font-size: 0.78rem; background: #f0f6fc; color: #2271b1; padding: 3px 10px; border-radius: 12px; font-weight: 600; }
        .wpfa-card { background: #fff; border: 1px solid #e0e0e0; border-radius: 12px; padding: 28px 32px; margin-bottom: 20px; }
        .wpfa-card h2 { margin: 0 0 4px; font-size: 1.05rem; font-weight: 700; color: #1d2327; }
        .wpfa-card p.desc { margin: 0 0 20px; font-size: 0.88rem; color: #646970; }
        .wpfa-row { display: flex; align-items: center; gap: 16px; padding: 14px 0; border-bottom: 1px solid #f0f0f0; }
        .wpfa-row:last-child { border-bottom: none; padding-bottom: 0; }
        .wpfa-row:first-of-type { padding-top: 0; }
        .wpfa-row-label { flex: 0 0 220px; font-size: 0.9rem; font-weight: 600; color: #1d2327; }
        .wpfa-row-field { flex: 1; min-width: 0; }
        .wpfa-row-field select, .wpfa-row-field input[type="text"], .wpfa-row-field input[type="number"] {
            padding: 8px 12px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 0.9rem;
            color: #1d2327; background: #fff; width: 100%; max-width: 320px; transition: border-color 0.15s;
        }
        .wpfa-row-field input:focus, .wpfa-row-field select:focus { border-color: #2271b1; outline: none; box-shadow: 0 0 0 1px #2271b1; }
        .wpfa-row-field input[type="number"] { max-width: 100px; }
        .wpfa-toggle { position: relative; display: inline-block; width: 44px; height: 24px; }
        .wpfa-toggle input { opacity: 0; width: 0; height: 0; }
        .wpfa-toggle-slider { position: absolute; inset: 0; background: #ccc; border-radius: 24px; cursor: pointer; transition: 0.2s; }
        .wpfa-toggle-slider::before { content: ""; position: absolute; width: 18px; height: 18px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: 0.2s; }
        .wpfa-toggle input:checked + .wpfa-toggle-slider { background: #2271b1; }
        .wpfa-toggle input:checked + .wpfa-toggle-slider::before { transform: translateX(20px); }
        .wpfa-hint { font-size: 0.8rem; color: #888; margin-top: 4px; }
        .wpfa-slug-grid { display: grid; grid-template-columns: 140px 1fr; gap: 10px 16px; align-items: center; }
        .wpfa-slug-grid label { font-size: 0.88rem; font-weight: 600; color: #1d2327; text-transform: capitalize; }
        .wpfa-slug-grid input { padding: 8px 12px; border: 1px solid #d0d5dd; border-radius: 8px; font-size: 0.9rem; width: 100%; }
        .wpfa-slug-grid input:focus { border-color: #2271b1; outline: none; box-shadow: 0 0 0 1px #2271b1; }
        .wpfa-save-row { padding-top: 8px; }
        .wpfa-save-row .button-primary { padding: 8px 28px; font-size: 0.92rem; border-radius: 8px; }
        @media (max-width: 782px) {
            .wpfa-admin { margin: 10px; }
            .wpfa-row { flex-direction: column; align-items: stretch; gap: 6px; }
            .wpfa-row-label { flex: none; }
            .wpfa-slug-grid { grid-template-columns: 1fr; }
            .wpfa-card { padding: 20px; }
        }
    </style>

    <div class="wpfa-admin">
        <div class="wpfa-admin-header">
            <span class="dashicons dashicons-lock" style="font-size:28px;color:#2271b1;"></span>
            <h1><?php esc_html_e( 'Frontend Auth', 'frontend-auth' ); ?></h1>
            <span class="wpfa-ver">v<?php echo esc_html( WPFA_VERSION ); ?></span>
        </div>

        <form method="post" action="options.php">
            <?php settings_fields( 'frontend-auth' ); ?>

            <!-- General Settings -->
            <div class="wpfa-card">
                <h2><?php esc_html_e( 'General', 'frontend-auth' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Core authentication behavior.', 'frontend-auth' ); ?></p>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Login with', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <?php $lt = get_option( 'wpfa_login_type', 'default' ); ?>
                        <select name="wpfa_login_type">
                            <option value="default" <?php selected( $lt, 'default' ); ?>><?php esc_html_e( 'Username or Email', 'frontend-auth' ); ?></option>
                            <option value="username" <?php selected( $lt, 'username' ); ?>><?php esc_html_e( 'Username only', 'frontend-auth' ); ?></option>
                            <option value="email" <?php selected( $lt, 'email' ); ?>><?php esc_html_e( 'Email only', 'frontend-auth' ); ?></option>
                        </select>
                    </div>
                </div>

                <?php
                $toggles = [
                    [ 'wpfa_use_permalinks', __( 'Pretty URLs', 'frontend-auth' ), __( 'Use /login/ instead of ?action=login', 'frontend-auth' ), true ],
                    [ 'wpfa_use_ajax', __( 'AJAX forms', 'frontend-auth' ), __( 'Submit forms without a page reload', 'frontend-auth' ), false ],
                    [ 'wpfa_user_passwords', __( 'User-chosen passwords', 'frontend-auth' ), __( 'Show password field on registration', 'frontend-auth' ), false ],
                    [ 'wpfa_auto_login', __( 'Auto-login', 'frontend-auth' ), __( 'Log users in automatically after registration', 'frontend-auth' ), false ],
                    [ 'wpfa_honeypot', __( 'Honeypot protection', 'frontend-auth' ), __( 'Hidden field to catch spam bots', 'frontend-auth' ), true ],
                ];
                foreach ( $toggles as [ $opt, $label, $hint, $default ] ) :
                    $checked = (bool) get_option( $opt, $default );
                ?>
                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php echo esc_html( $label ); ?></div>
                    <div class="wpfa-row-field">
                        <label class="wpfa-toggle">
                            <input type="checkbox" name="<?php echo esc_attr( $opt ); ?>" value="1" <?php checked( $checked ); ?>>
                            <span class="wpfa-toggle-slider"></span>
                        </label>
                        <div class="wpfa-hint"><?php echo esc_html( $hint ); ?></div>
                    </div>
                </div>
                <?php endforeach; ?>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Subscriber redirect', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <input type="text" name="wpfa_subscriber_redirect" value="<?php echo esc_attr( (string) get_option( 'wpfa_subscriber_redirect', '' ) ); ?>" placeholder="<?php esc_attr_e( 'e.g. dashboard  (leave empty for home page)', 'frontend-auth' ); ?>">
                        <div class="wpfa-hint"><?php esc_html_e( 'Where subscribers land after logging in. Enter a page slug (e.g. dashboard) or a full URL. Leave empty to send them to the site home page. Admins and editors keep their normal redirect.', 'frontend-auth' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Sign in with Google -->
            <div class="wpfa-card">
                <h2><?php esc_html_e( 'Sign in with Google', 'frontend-auth' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Let users log in (and optionally register) with their Google account. Server-side flow — no Google JavaScript is loaded on your pages.', 'frontend-auth' ); ?></p>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Enable Google sign-in', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <label class="wpfa-toggle">
                            <input type="hidden" name="wpfa_google_enabled" value="0">
                            <input type="checkbox" name="wpfa_google_enabled" value="1" <?php checked( (bool) get_option( 'wpfa_google_enabled', false ) ); ?>>
                            <span class="wpfa-toggle-slider"></span>
                        </label>
                        <div class="wpfa-hint"><?php esc_html_e( 'Shows a "Continue with Google" button on the login and registration forms once the credentials below are filled in.', 'frontend-auth' ); ?></div>
                    </div>
                </div>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Client ID', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <input type="text" name="wpfa_google_client_id" value="<?php echo esc_attr( (string) get_option( 'wpfa_google_client_id', '' ) ); ?>" autocomplete="off" placeholder="xxxxxxxx.apps.googleusercontent.com">
                    </div>
                </div>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Client Secret', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <?php if ( defined( 'WPFA_GOOGLE_CLIENT_SECRET' ) ) : ?>
                            <input type="password" value="****************" disabled>
                            <div class="wpfa-hint"><?php esc_html_e( 'Defined as WPFA_GOOGLE_CLIENT_SECRET in wp-config.php — manage it there.', 'frontend-auth' ); ?></div>
                        <?php else : ?>
                            <?php $wpfa_has_secret = '' !== trim( (string) get_option( 'wpfa_google_client_secret', '' ) ); ?>
                            <input type="password" name="wpfa_google_client_secret" value="" autocomplete="new-password" placeholder="<?php echo esc_attr( $wpfa_has_secret ? __( 'Saved — leave blank to keep the current secret', 'frontend-auth' ) : '' ); ?>">
                            <div class="wpfa-hint"><?php esc_html_e( 'Stored encrypted (AES-256-GCM, keyed from your wp-config.php salts) and never shown again after saving. Tip: you can instead define WPFA_GOOGLE_CLIENT_ID and WPFA_GOOGLE_CLIENT_SECRET in wp-config.php to keep credentials out of the database entirely. If you rotate your salts, re-enter the secret.', 'frontend-auth' ); ?></div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Allow new accounts', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <label class="wpfa-toggle">
                            <input type="hidden" name="wpfa_google_allow_registration" value="0">
                            <input type="checkbox" name="wpfa_google_allow_registration" value="1" <?php checked( (bool) get_option( 'wpfa_google_allow_registration', true ) ); ?>>
                            <span class="wpfa-toggle-slider"></span>
                        </label>
                        <div class="wpfa-hint"><?php esc_html_e( 'Create an account automatically on first Google sign-in. Existing accounts with the same verified email are always linked. When off, only existing users can sign in with Google.', 'frontend-auth' ); ?></div>
                    </div>
                </div>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Authorized redirect URI', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <input type="text" readonly value="<?php echo esc_attr( wpfa_google_callback_url() ); ?>" onclick="this.select();">
                        <div class="wpfa-hint"><?php esc_html_e( 'Add this exact URL in Google Cloud Console → APIs & Services → Credentials → your OAuth 2.0 Client ID → Authorized redirect URIs.', 'frontend-auth' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Rate Limiting -->
            <div class="wpfa-card">
                <h2><?php esc_html_e( 'Rate Limiting', 'frontend-auth' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Limit failed attempts per IP address before a temporary lockout.', 'frontend-auth' ); ?></p>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Max attempts', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <input type="number" name="wpfa_rate_limit" value="<?php echo esc_attr( (string) get_option( 'wpfa_rate_limit', 10 ) ); ?>" min="0" max="100">
                        <div class="wpfa-hint"><?php esc_html_e( 'Set to 0 to disable.', 'frontend-auth' ); ?></div>
                    </div>
                </div>
                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Lockout window', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <input type="number" name="wpfa_rate_limit_window" value="<?php echo esc_attr( (string) get_option( 'wpfa_rate_limit_window', 15 ) ); ?>" min="1" max="1440"> <?php esc_html_e( 'minutes', 'frontend-auth' ); ?>
                    </div>
                </div>
            </div>

            <!-- Per-Form Rate Limiting (v1.4.18) -->
            <div class="wpfa-card">
                <h2><?php esc_html_e( 'Per-Form Rate Limiting', 'frontend-auth' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Enable or disable rate limiting per form, and override the global Max attempts threshold.', 'frontend-auth' ); ?></p>

                <?php
                $rl_global   = (int) get_option( 'wpfa_rate_limit', 10 );
                $rl_actions  = [
                    'login'        => __( 'Login',         'frontend-auth' ),
                    'register'     => __( 'Registration',  'frontend-auth' ),
                    'lostpassword' => __( 'Lost Password', 'frontend-auth' ),
                    'resetpass'    => __( 'Reset Password', 'frontend-auth' ),
                ];
                foreach ( $rl_actions as $rl_action => $rl_label ) :
                    $rl_enabled = (bool) get_option( "wpfa_rl_enabled_{$rl_action}", true );
                    $rl_max     = (int) get_option( "wpfa_rl_max_{$rl_action}", 0 );
                ?>
                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php echo esc_html( $rl_label ); ?></div>
                    <div class="wpfa-row-field" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
                        <label class="wpfa-toggle" title="<?php esc_attr_e( 'Enable rate limiting for this form', 'frontend-auth' ); ?>">
                            <input type="hidden" name="wpfa_rl_enabled_<?php echo esc_attr( $rl_action ); ?>" value="0">
                            <input type="checkbox" name="wpfa_rl_enabled_<?php echo esc_attr( $rl_action ); ?>" value="1" <?php checked( $rl_enabled ); ?>>
                            <span class="wpfa-toggle-slider"></span>
                        </label>
                        <span style="font-size:0.85rem;color:#646970;"><?php esc_html_e( 'Max attempts:', 'frontend-auth' ); ?></span>
                        <input type="number" name="wpfa_rl_max_<?php echo esc_attr( $rl_action ); ?>" value="<?php echo esc_attr( (string) $rl_max ); ?>" min="0" max="100" placeholder="<?php echo esc_attr( (string) $rl_global ); ?>" style="max-width:90px;">
                        <span class="wpfa-hint" style="margin-top:0;">
                            <?php
                            /* translators: %d = global default */
                            echo esc_html( sprintf( __( '0 = use global default (%d)', 'frontend-auth' ), $rl_global ) );
                            ?>
                        </span>
                    </div>
                </div>
                <?php endforeach; ?>

                <div class="wpfa-row">
                    <div class="wpfa-row-label"><?php esc_html_e( 'Count successful lost-password requests', 'frontend-auth' ); ?></div>
                    <div class="wpfa-row-field">
                        <label class="wpfa-toggle">
                            <input type="hidden" name="wpfa_lostpassword_count_all" value="0">
                            <input type="checkbox" name="wpfa_lostpassword_count_all" value="1" <?php checked( (bool) get_option( 'wpfa_lostpassword_count_all', false ) ); ?>>
                            <span class="wpfa-toggle-slider"></span>
                        </label>
                        <div class="wpfa-hint"><?php esc_html_e( 'Count every submission, not just failed ones. Prevents an attacker from spamming reset emails to a known-valid address.', 'frontend-auth' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Page Slugs -->
            <div class="wpfa-card">
                <h2><?php esc_html_e( 'Page Slugs', 'frontend-auth' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Customise the URL slug for each action page.', 'frontend-auth' ); ?></p>

                <div class="wpfa-slug-grid">
                    <?php
                    $slug_actions = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass' ];
                    foreach ( $slug_actions as $action ) :
                        $option = "wpfa_slug_{$action}";
                        $value  = get_option( $option, wpfa_get_action_slug_default( $action ) );
                    ?>
                    <label for="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( ucfirst( str_replace( 'pass', ' pass', $action ) ) ); ?></label>
                    <input type="text" id="<?php echo esc_attr( $option ); ?>" name="<?php echo esc_attr( $option ); ?>" value="<?php echo esc_attr( $value ); ?>">
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="wpfa-save-row">
                <?php submit_button( __( 'Save Changes', 'frontend-auth' ), 'primary', 'submit', false ); ?>
            </div>
        </form>

        <!-- Page Management — outside main <form> because it uses its own nonce + action -->
        <div class="wpfa-card" style="margin-top:20px;">
            <h2><?php esc_html_e( 'Page Management', 'frontend-auth' ); ?></h2>
            <p class="desc"><?php esc_html_e( 'Create or remove the real WordPress pages used by each auth action. Pages are only required for Elementor Theme Builder targeting — the plugin works without them via virtual URL rewrites.', 'frontend-auth' ); ?></p>

            <table class="widefat" style="border:none; box-shadow:none; background:transparent;">
                <thead>
                    <tr>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Action', 'frontend-auth' ); ?></th>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Page', 'frontend-auth' ); ?></th>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Status', 'frontend-auth' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    foreach ( wpfa_get_page_actions() as $action => $title ) :
                        $page_id   = wpfa_get_page_id( $action );
                        $page_post = $page_id ? get_post( $page_id ) : null;
                        $exists    = $page_post instanceof WP_Post && 'publish' === $page_post->post_status;
                        $slug      = wpfa_get_action_slug( $action );
                    ?>
                    <tr>
                        <td style="padding:10px 0;font-weight:600;"><?php echo esc_html( $title ); ?> <code>/<?php echo esc_html( $slug ); ?>/</code></td>
                        <td style="padding:10px 0;">
                            <?php if ( $exists ) : ?>
                                <a href="<?php echo esc_url( get_edit_post_link( $page_id ) ); ?>"><?php echo esc_html( get_the_title( $page_id ) ); ?></a>
                                <span style="color:#888;">(ID <?php echo esc_html( (string) $page_id ); ?>)</span>
                            <?php else : ?>
                                <span style="color:#888;">&mdash;</span>
                            <?php endif; ?>
                        </td>
                        <td style="padding:10px 0;">
                            <?php if ( $exists ) : ?>
                                <span style="color:#00a32a;">&#10003; <?php esc_html_e( 'Published', 'frontend-auth' ); ?></span>
                            <?php else : ?>
                                <span style="color:#996800;"><?php esc_html_e( 'Not created', 'frontend-auth' ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <div style="display:flex;gap:12px;margin-top:16px;">
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <?php wp_nonce_field( 'wpfa_create_pages', 'wpfa_pages_nonce' ); ?>
                    <input type="hidden" name="action" value="wpfa_create_pages">
                    <?php submit_button( __( 'Create Missing Pages', 'frontend-auth' ), 'secondary', 'submit', false ); ?>
                </form>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'This will permanently delete only the auto-created pages (not pages you created manually). Continue?', 'frontend-auth' ) ); ?>');">
                    <?php wp_nonce_field( 'wpfa_delete_pages', 'wpfa_pages_nonce' ); ?>
                    <input type="hidden" name="action" value="wpfa_delete_pages">
                    <?php submit_button( __( 'Delete Auto-Created Pages', 'frontend-auth' ), 'delete', 'submit', false ); ?>
                </form>
            </div>
        </div>
    </div>
    <?php
}

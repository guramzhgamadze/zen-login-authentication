<?php
/**
 * Zen Login & Authentication – Admin Settings
 *
 * Modern admin panel with card-based layout.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Menu registration — top-level sidebar item
 * -------------------------------------------------------------------- */
add_action( 'admin_menu', 'zenlogau_admin_add_menu' );

function zenlogau_admin_add_menu(): void {
    add_menu_page(
        __( 'Zen Login & Authentication', 'zen-login-authentication' ),
        __( 'Zen Login & Authentication', 'zen-login-authentication' ),
        'manage_options',
        'zen-login-authentication',
        'zenlogau_admin_settings_page',
        'dashicons-lock',
        71
    );
}

/* -----------------------------------------------------------------------
 * Register settings (WP Settings API — handles nonce + sanitization)
 * -------------------------------------------------------------------- */
add_action( 'admin_init',    'zenlogau_admin_register_settings' );
// Fix 3 — register_setting() sanitize_callback applies on REST saves only when
// hooked to rest_api_init too. Source: developer.wordpress.org/reference/functions/register_setting/
add_action( 'rest_api_init', 'zenlogau_admin_register_settings' );

function zenlogau_admin_register_settings(): void {
    // General
    $general = [
        'zenlogau_login_type'      => 'zenlogau_sanitize_login_type',
        'zenlogau_use_permalinks'  => 'absint',
        'zenlogau_use_ajax'        => 'absint',
        'zenlogau_user_passwords'  => 'absint',
        'zenlogau_auto_login'      => 'absint',
        'zenlogau_honeypot'        => 'absint',
    ];
    // Fix 7 — autoload:false (no need to load auth options on every page request).
    // Fix 9 — type declaration for proper schema and REST validation.
    foreach ( $general as $id => $sanitize ) {
        register_setting( 'zen-login-authentication', $id, [
            'sanitize_callback' => $sanitize,
            'type'              => 'string',
            'autoload'          => false,
        ] );
    }

    // Rate limiting
    register_setting( 'zen-login-authentication', 'zenlogau_rate_limit',        [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    register_setting( 'zen-login-authentication', 'zenlogau_rate_limit_window', [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );

    // Per-action rate-limit toggles + threshold overrides (v1.4.18).
    // Toggles default to true (rendered as checkbox: 1=on, missing=off).
    // Overrides default to 0 (means "use global default"); positive int wins.
    $rl_actions = [ 'login', 'register', 'lostpassword', 'resetpass' ];
    foreach ( $rl_actions as $action ) {
        register_setting( 'zen-login-authentication', "zenlogau_rl_enabled_{$action}", [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
        register_setting( 'zen-login-authentication', "zenlogau_rl_max_{$action}",     [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    }
    register_setting( 'zen-login-authentication', 'zenlogau_lostpassword_count_all', [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );

    // Subscriber post-login redirect: page slug/path or full URL; empty = site home.
    register_setting( 'zen-login-authentication', 'zenlogau_subscriber_redirect', [ 'sanitize_callback' => 'zenlogau_sanitize_redirect_target', 'type' => 'string', 'autoload' => false ] );

    // Sign in with Google (v1.5.0).
    register_setting( 'zen-login-authentication', 'zenlogau_google_enabled',            [ 'sanitize_callback' => 'absint',              'type' => 'integer', 'autoload' => false ] );
    register_setting( 'zen-login-authentication', 'zenlogau_google_client_id',          [ 'sanitize_callback' => 'sanitize_text_field', 'type' => 'string',  'autoload' => false ] );
    register_setting( 'zen-login-authentication', 'zenlogau_google_client_secret',      [ 'sanitize_callback' => 'zenlogau_sanitize_google_secret', 'type' => 'string', 'autoload' => false ] );
    register_setting( 'zen-login-authentication', 'zenlogau_google_allow_registration', [ 'sanitize_callback' => 'absint',              'type' => 'integer', 'autoload' => false ] );

    // Slugs
    $slug_actions = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass', 'account' ];
    foreach ( $slug_actions as $action ) {
        register_setting( 'zen-login-authentication', "zenlogau_slug_{$action}", [ 'sanitize_callback' => 'sanitize_title', 'type' => 'string', 'autoload' => false ] );
    }

    // Per-widget availability toggles (v1.6.2). Default on; rendered as
    // hidden-0 + checkbox-1 pairs so unchecked boxes save correctly.
    $widget_keys = [ 'login', 'register', 'lostpassword', 'resetpass', 'account' ];
    foreach ( $widget_keys as $widget ) {
        register_setting( 'zen-login-authentication', "zenlogau_widget_enabled_{$widget}", [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    }

    // Login-activity log (v1.7.0).
    register_setting( 'zen-login-authentication', 'zenlogau_activity_log_enabled',  [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
    register_setting( 'zen-login-authentication', 'zenlogau_activity_retention_days', [ 'sanitize_callback' => 'absint', 'type' => 'integer', 'autoload' => false ] );
}

function zenlogau_sanitize_login_type( $value ): string {
    $allowed = [ 'default', 'username', 'email' ];
    $value   = sanitize_text_field( (string) $value );
    return in_array( $value, $allowed, true ) ? $value : 'default';
}

/**
 * Sanitize the subscriber-redirect target. Accepts a slug/path or a full URL.
 * Stored as plain text; same-host safety is enforced at redirect time by
 * zenlogau_get_subscriber_redirect() (home_url) and wp_safe_redirect().
 */
function zenlogau_sanitize_redirect_target( $value ): string {
    return trim( sanitize_text_field( (string) $value ) );
}

/* -----------------------------------------------------------------------
 * Settings page HTML — modern card-based design
 * -------------------------------------------------------------------- */

function zenlogau_admin_settings_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    ?>
    <div class="fauth-admin">
        <div class="fauth-admin-header">
            <span class="dashicons dashicons-lock" style="font-size:28px;color:#2271b1;"></span>
            <h1><?php esc_html_e( 'Zen Login & Authentication', 'zen-login-authentication' ); ?></h1>
            <span class="fauth-ver">v<?php echo esc_html( ZENLOGAU_VERSION ); ?></span>
        </div>

        <form method="post" action="options.php">
            <?php settings_fields( 'zen-login-authentication' ); ?>

            <!-- General Settings -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'General', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Core authentication behavior.', 'zen-login-authentication' ); ?></p>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Login with', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <?php $lt = get_option( 'zenlogau_login_type', 'default' ); ?>
                        <select name="zenlogau_login_type">
                            <option value="default" <?php selected( $lt, 'default' ); ?>><?php esc_html_e( 'Username or Email', 'zen-login-authentication' ); ?></option>
                            <option value="username" <?php selected( $lt, 'username' ); ?>><?php esc_html_e( 'Username only', 'zen-login-authentication' ); ?></option>
                            <option value="email" <?php selected( $lt, 'email' ); ?>><?php esc_html_e( 'Email only', 'zen-login-authentication' ); ?></option>
                        </select>
                    </div>
                </div>

                <?php
                $toggles = [
                    [ 'zenlogau_use_permalinks', __( 'Pretty URLs', 'zen-login-authentication' ), __( 'Use /login/ instead of ?action=login', 'zen-login-authentication' ), true ],
                    [ 'zenlogau_use_ajax', __( 'AJAX forms', 'zen-login-authentication' ), __( 'Submit forms without a page reload', 'zen-login-authentication' ), false ],
                    [ 'zenlogau_user_passwords', __( 'User-chosen passwords', 'zen-login-authentication' ), __( 'Show password field on registration', 'zen-login-authentication' ), false ],
                    [ 'zenlogau_auto_login', __( 'Auto-login', 'zen-login-authentication' ), __( 'Log users in automatically after registration', 'zen-login-authentication' ), false ],
                    [ 'zenlogau_honeypot', __( 'Honeypot protection', 'zen-login-authentication' ), __( 'Hidden field to catch spam bots', 'zen-login-authentication' ), true ],
                ];
                foreach ( $toggles as [ $opt, $label, $hint, $default ] ) :
                    $checked = (bool) get_option( $opt, $default );
                ?>
                <div class="fauth-row">
                    <div class="fauth-row-label"><?php echo esc_html( $label ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="checkbox" name="<?php echo esc_attr( $opt ); ?>" value="1" <?php checked( $checked ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php echo esc_html( $hint ); ?></div>
                    </div>
                </div>
                <?php endforeach; ?>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Subscriber redirect', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="text" name="zenlogau_subscriber_redirect" value="<?php echo esc_attr( (string) get_option( 'zenlogau_subscriber_redirect', '' ) ); ?>" placeholder="<?php esc_attr_e( 'e.g. dashboard  (leave empty for home page)', 'zen-login-authentication' ); ?>">
                        <div class="fauth-hint"><?php esc_html_e( 'Where subscribers land after logging in. Enter a page slug (e.g. dashboard) or a full URL. Leave empty to send them to the site home page. Admins and editors keep their normal redirect.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Sign in with Google -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Sign in with Google', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Let users log in (and optionally register) with their Google account. Server-side flow — no Google JavaScript is loaded on your pages.', 'zen-login-authentication' ); ?></p>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Enable Google sign-in', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="hidden" name="zenlogau_google_enabled" value="0">
                            <input type="checkbox" name="zenlogau_google_enabled" value="1" <?php checked( (bool) get_option( 'zenlogau_google_enabled', false ) ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php esc_html_e( 'Shows a "Continue with Google" button on the login and registration forms once the credentials below are filled in.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Client ID', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="text" name="zenlogau_google_client_id" value="<?php echo esc_attr( (string) get_option( 'zenlogau_google_client_id', '' ) ); ?>" autocomplete="off" placeholder="xxxxxxxx.apps.googleusercontent.com">
                    </div>
                </div>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Client Secret', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <?php if ( defined( 'ZENLOGAU_GOOGLE_CLIENT_SECRET' ) ) : ?>
                            <input type="password" value="****************" disabled>
                            <div class="fauth-hint"><?php esc_html_e( 'Defined as ZENLOGAU_GOOGLE_CLIENT_SECRET in wp-config.php — manage it there.', 'zen-login-authentication' ); ?></div>
                        <?php else : ?>
                            <?php $zenlogau_has_secret = '' !== trim( (string) get_option( 'zenlogau_google_client_secret', '' ) ); ?>
                            <input type="password" name="zenlogau_google_client_secret" value="" autocomplete="new-password" placeholder="<?php echo esc_attr( $zenlogau_has_secret ? __( 'Saved — leave blank to keep the current secret', 'zen-login-authentication' ) : '' ); ?>">
                            <div class="fauth-hint"><?php esc_html_e( 'Stored encrypted (AES-256-GCM, keyed from your wp-config.php salts) and never shown again after saving. Tip: you can instead define ZENLOGAU_GOOGLE_CLIENT_ID and ZENLOGAU_GOOGLE_CLIENT_SECRET in wp-config.php to keep credentials out of the database entirely. If you rotate your salts, re-enter the secret.', 'zen-login-authentication' ); ?></div>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Allow new accounts', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="hidden" name="zenlogau_google_allow_registration" value="0">
                            <input type="checkbox" name="zenlogau_google_allow_registration" value="1" <?php checked( (bool) get_option( 'zenlogau_google_allow_registration', true ) ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php esc_html_e( 'Create an account automatically on first Google sign-in. Existing accounts with the same verified email are always linked. When off, only existing users can sign in with Google.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Authorized redirect URI', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="text" readonly value="<?php echo esc_attr( zenlogau_google_callback_url() ); ?>" onclick="this.select();">
                        <div class="fauth-hint"><?php esc_html_e( 'Add this exact URL in Google Cloud Console → APIs & Services → Credentials → your OAuth 2.0 Client ID → Authorized redirect URIs.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Widgets -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Widgets', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Choose which form widgets are available — in the Elementor panel and as classic sidebar widgets. Turning one off also stops it rendering on pages that already use it, so make sure your login page keeps a working login form.', 'zen-login-authentication' ); ?></p>

                <?php
                $zenlogau_widget_rows = [
                    'login'        => [ __( 'Login Form', 'zen-login-authentication' ),          __( 'The main sign-in form.', 'zen-login-authentication' ) ],
                    'register'     => [ __( 'Registration Form', 'zen-login-authentication' ),   __( 'New-account registration form.', 'zen-login-authentication' ) ],
                    'lostpassword' => [ __( 'Lost Password Form', 'zen-login-authentication' ),  __( 'Request a password-reset email.', 'zen-login-authentication' ) ],
                    'resetpass'    => [ __( 'Reset Password Form', 'zen-login-authentication' ), __( 'Set a new password from a reset-email link.', 'zen-login-authentication' ) ],
                    'account'      => [ __( 'Account Form', 'zen-login-authentication' ),        __( 'Frontend profile editing for logged-in users.', 'zen-login-authentication' ) ],
                ];
                foreach ( $zenlogau_widget_rows as $zenlogau_widget_key => [ $zenlogau_widget_label, $zenlogau_widget_hint ] ) :
                ?>
                <div class="fauth-row">
                    <div class="fauth-row-label"><?php echo esc_html( $zenlogau_widget_label ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="hidden" name="zenlogau_widget_enabled_<?php echo esc_attr( $zenlogau_widget_key ); ?>" value="0">
                            <input type="checkbox" name="zenlogau_widget_enabled_<?php echo esc_attr( $zenlogau_widget_key ); ?>" value="1" <?php checked( zenlogau_widget_enabled( $zenlogau_widget_key ) ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php echo esc_html( $zenlogau_widget_hint ); ?></div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>

            <!-- Rate Limiting -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Rate Limiting', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Limit failed attempts per IP address before a temporary lockout.', 'zen-login-authentication' ); ?></p>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Max attempts', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="number" name="zenlogau_rate_limit" value="<?php echo esc_attr( (string) get_option( 'zenlogau_rate_limit', 10 ) ); ?>" min="0" max="100">
                        <div class="fauth-hint"><?php esc_html_e( 'Set to 0 to disable.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>
                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Lockout window', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="number" name="zenlogau_rate_limit_window" value="<?php echo esc_attr( (string) get_option( 'zenlogau_rate_limit_window', 15 ) ); ?>" min="1" max="1440"> <?php esc_html_e( 'minutes', 'zen-login-authentication' ); ?>
                    </div>
                </div>
            </div>

            <!-- Per-Form Rate Limiting (v1.4.18) -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Per-Form Rate Limiting', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Enable or disable rate limiting per form, and override the global Max attempts threshold.', 'zen-login-authentication' ); ?></p>

                <?php
                $rl_global   = (int) get_option( 'zenlogau_rate_limit', 10 );
                $rl_actions  = [
                    'login'        => __( 'Login',         'zen-login-authentication' ),
                    'register'     => __( 'Registration',  'zen-login-authentication' ),
                    'lostpassword' => __( 'Lost Password', 'zen-login-authentication' ),
                    'resetpass'    => __( 'Reset Password', 'zen-login-authentication' ),
                ];
                foreach ( $rl_actions as $rl_action => $rl_label ) :
                    $rl_enabled = (bool) get_option( "zenlogau_rl_enabled_{$rl_action}", true );
                    $rl_max     = (int) get_option( "zenlogau_rl_max_{$rl_action}", 0 );
                ?>
                <div class="fauth-row">
                    <div class="fauth-row-label"><?php echo esc_html( $rl_label ); ?></div>
                    <div class="fauth-row-field" style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
                        <label class="fauth-toggle" title="<?php esc_attr_e( 'Enable rate limiting for this form', 'zen-login-authentication' ); ?>">
                            <input type="hidden" name="zenlogau_rl_enabled_<?php echo esc_attr( $rl_action ); ?>" value="0">
                            <input type="checkbox" name="zenlogau_rl_enabled_<?php echo esc_attr( $rl_action ); ?>" value="1" <?php checked( $rl_enabled ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <span style="font-size:0.85rem;color:#646970;"><?php esc_html_e( 'Max attempts:', 'zen-login-authentication' ); ?></span>
                        <input type="number" name="zenlogau_rl_max_<?php echo esc_attr( $rl_action ); ?>" value="<?php echo esc_attr( (string) $rl_max ); ?>" min="0" max="100" placeholder="<?php echo esc_attr( (string) $rl_global ); ?>" style="max-width:90px;">
                        <span class="fauth-hint" style="margin-top:0;">
                            <?php
                            /* translators: %d = global default */
                            echo esc_html( sprintf( __( '0 = use global default (%d)', 'zen-login-authentication' ), $rl_global ) );
                            ?>
                        </span>
                    </div>
                </div>
                <?php endforeach; ?>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Count successful lost-password requests', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="hidden" name="zenlogau_lostpassword_count_all" value="0">
                            <input type="checkbox" name="zenlogau_lostpassword_count_all" value="1" <?php checked( (bool) get_option( 'zenlogau_lostpassword_count_all', false ) ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php esc_html_e( 'Count every submission, not just failed ones. Prevents an attacker from spamming reset emails to a known-valid address.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Login Activity -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Login Activity', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Records successful logins, failed attempts, and rate-limit lockouts so you can review them in the "Login Activity" widget on your WordPress dashboard. IP addresses are stored anonymised.', 'zen-login-authentication' ); ?></p>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Log login activity', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <label class="fauth-toggle">
                            <input type="hidden" name="zenlogau_activity_log_enabled" value="0">
                            <input type="checkbox" name="zenlogau_activity_log_enabled" value="1" <?php checked( (bool) get_option( 'zenlogau_activity_log_enabled', true ) ); ?>>
                            <span class="fauth-toggle-slider"></span>
                        </label>
                        <div class="fauth-hint"><?php esc_html_e( 'Turn off to stop recording new events. Existing entries are kept until cleared or aged out.', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>

                <div class="fauth-row">
                    <div class="fauth-row-label"><?php esc_html_e( 'Keep history for', 'zen-login-authentication' ); ?></div>
                    <div class="fauth-row-field">
                        <input type="number" name="zenlogau_activity_retention_days" value="<?php echo esc_attr( (string) get_option( 'zenlogau_activity_retention_days', 30 ) ); ?>" min="0" max="365"> <?php esc_html_e( 'days', 'zen-login-authentication' ); ?>
                        <div class="fauth-hint"><?php esc_html_e( 'Older entries are deleted automatically. Set to 0 to keep entries indefinitely (not recommended).', 'zen-login-authentication' ); ?></div>
                    </div>
                </div>
            </div>

            <!-- Page Slugs -->
            <div class="fauth-card">
                <h2><?php esc_html_e( 'Page Slugs', 'zen-login-authentication' ); ?></h2>
                <p class="desc"><?php esc_html_e( 'Customise the URL slug for each action page.', 'zen-login-authentication' ); ?></p>

                <div class="fauth-slug-grid">
                    <?php
                    $slug_actions = [ 'login', 'logout', 'register', 'lostpassword', 'resetpass', 'account' ];
                    foreach ( $slug_actions as $action ) :
                        $option = "zenlogau_slug_{$action}";
                        $value  = get_option( $option, zenlogau_get_action_slug_default( $action ) );
                    ?>
                    <label for="<?php echo esc_attr( $option ); ?>"><?php echo esc_html( ucfirst( str_replace( 'pass', ' pass', $action ) ) ); ?></label>
                    <input type="text" id="<?php echo esc_attr( $option ); ?>" name="<?php echo esc_attr( $option ); ?>" value="<?php echo esc_attr( $value ); ?>">
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="fauth-save-row">
                <?php submit_button( __( 'Save Changes', 'zen-login-authentication' ), 'primary', 'submit', false ); ?>
            </div>
        </form>

        <!-- Login Activity maintenance — outside main <form> (own nonce + action) -->
        <div class="fauth-card" style="margin-top:20px;">
            <h2><?php esc_html_e( 'Login Activity Log', 'zen-login-authentication' ); ?></h2>
            <p class="desc"><?php esc_html_e( 'The recorded events power the "Login Activity" widget on your WordPress dashboard. Use the button below to erase all recorded events immediately.', 'zen-login-authentication' ); ?></p>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Permanently delete all recorded login-activity entries?', 'zen-login-authentication' ) ); ?>');">
                <?php wp_nonce_field( 'zenlogau_clear_activity', 'zenlogau_activity_nonce' ); ?>
                <input type="hidden" name="action" value="zenlogau_clear_activity">
                <?php submit_button( __( 'Clear Activity Log', 'zen-login-authentication' ), 'delete', 'submit', false ); ?>
            </form>
        </div>

        <!-- Page Management — outside main <form> because it uses its own nonce + action -->
        <div class="fauth-card" style="margin-top:20px;">
            <h2><?php esc_html_e( 'Page Management', 'zen-login-authentication' ); ?></h2>
            <p class="desc"><?php esc_html_e( 'Create or remove the real WordPress pages used by each auth action. Pages are only required for Elementor Theme Builder targeting — the plugin works without them via virtual URL rewrites.', 'zen-login-authentication' ); ?></p>

            <table class="widefat" style="border:none; box-shadow:none; background:transparent;">
                <thead>
                    <tr>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Action', 'zen-login-authentication' ); ?></th>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Page', 'zen-login-authentication' ); ?></th>
                        <th style="padding:8px 0;font-size:0.88rem;"><?php esc_html_e( 'Status', 'zen-login-authentication' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    foreach ( zenlogau_get_page_actions() as $action => $title ) :
                        $page_id   = zenlogau_get_page_id( $action );
                        $page_post = $page_id ? get_post( $page_id ) : null;
                        $exists    = $page_post instanceof WP_Post && 'publish' === $page_post->post_status;
                        $slug      = zenlogau_get_action_slug( $action );
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
                                <span style="color:#00a32a;">&#10003; <?php esc_html_e( 'Published', 'zen-login-authentication' ); ?></span>
                            <?php else : ?>
                                <span style="color:#996800;"><?php esc_html_e( 'Not created', 'zen-login-authentication' ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <div style="display:flex;gap:12px;margin-top:16px;">
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                    <?php wp_nonce_field( 'zenlogau_create_pages', 'zenlogau_pages_nonce' ); ?>
                    <input type="hidden" name="action" value="zenlogau_create_pages">
                    <?php submit_button( __( 'Create Missing Pages', 'zen-login-authentication' ), 'secondary', 'submit', false ); ?>
                </form>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'This will permanently delete only the auto-created pages (not pages you created manually). Continue?', 'zen-login-authentication' ) ); ?>');">
                    <?php wp_nonce_field( 'zenlogau_delete_pages', 'zenlogau_pages_nonce' ); ?>
                    <input type="hidden" name="action" value="zenlogau_delete_pages">
                    <?php submit_button( __( 'Delete Auto-Created Pages', 'zen-login-authentication' ), 'delete', 'submit', false ); ?>
                </form>
            </div>
        </div>
    </div>
    <?php
}

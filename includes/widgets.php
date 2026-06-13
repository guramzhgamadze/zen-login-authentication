<?php
/**
 * Frontend Auth – Widgets
 *
 * All frontend auth forms exposed as classic WP_Widget instances.
 *
 * Available widgets:
 *  - FAUTH_Login_Widget          — login form
 *  - FAUTH_Register_Widget       — registration form
 *  - FAUTH_Lost_Password_Widget  — lost-password form
 *  - FAUTH_Reset_Password_Widget — password reset form (reads rp_key/rp_login from URL)
 *
 * Audit fixes applied:
 *  [F1]  render_title_field() hardcoded 'Login' fallback for every subclass.
 *  [F2]  sanitize_instance() missing wp_unslash() before sanitize_text_field/sanitize_url.
 *  [F3]  sanitize_instance() used esc_url_raw() (escape fn) for INPUT sanitization.
 *  [F4]  render_content() used sanitize_url() at OUTPUT time; correct fn is esc_url().
 *  [F5]  get_avatar() echoed without a PHPCS escape annotation.
 *  [F6]  Missing $control_options 4th param; default 250px form width too narrow for URL fields.
 *  [F7]  register_widget() called with string class names (pre-4.9 pattern); use instances.
 *  [F8]  Missing show_instance_in_rest in widget options (required for WP 5.8+ REST/block editor).
 *  [F9]  Registration-disabled admin notice echoed inside render_content(), bypassing
 *        before_widget/after_widget — produced malformed widget-area HTML.
 *  [F10] parse_instance() / get_instance_defaults() pattern introduced so every widget
 *        merges defaults consistently instead of scattering wp_parse_args() calls.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Widget registration
 * Hooked to 'widgets_init' from hooks.php.
 * [F7] Pass instances, not string class names (WP 4.9+ preferred pattern).
 * -------------------------------------------------------------------- */

function fauth_register_widgets(): void {
    $widgets = [
        'login'        => FAUTH_Login_Widget::class,
        'register'     => FAUTH_Register_Widget::class,
        'lostpassword' => FAUTH_Lost_Password_Widget::class,
        'resetpass'    => FAUTH_Reset_Password_Widget::class,
        'account'      => FAUTH_Account_Widget::class,
    ];
    foreach ( $widgets as $key => $class ) {
        if ( fauth_widget_enabled( $key ) ) {
            register_widget( new $class() );
        }
    }
}

/* -----------------------------------------------------------------------
 * Shared rendering helpers
 * -------------------------------------------------------------------- */

/**
 * Render a named auth form, returning its HTML string.
 */
function fauth_render_form( string $form_name, array $render_args = [] ): string {
    $form = fauth()->get_form( $form_name );
    if ( ! $form ) {
        return '';
    }
    return (string) apply_filters( 'fauth_widget_form_output', $form->render( $render_args ), $form_name, $render_args );
}



/* -----------------------------------------------------------------------
 * Abstract base widget
 * -------------------------------------------------------------------- */

abstract class FAUTH_Abstract_Widget extends WP_Widget {

    /** @var string The FAUTH form name this widget renders (e.g. 'login') */
    protected string $form_name = '';

    /**
     * Shared constructor — all subclasses call this.
     *
     * [F6] 4th param $control_options sets admin form panel width.
     *      WP default is 250px — too narrow for URL fields + labels. Use 400px.
     * [F8] show_instance_in_rest exposes saved settings via the WP REST API,
     *      required for the WP 5.8+ block-editor Widgets screen.
     */
    protected function init_widget( string $id_base, string $name, array $widget_opts ): void {
        // [F8] Merge in REST exposure before passing to parent.
        $widget_opts = array_merge( [ 'show_instance_in_rest' => true ], $widget_opts );

        // [F6] Fourth param = control options; width 400 fits URL fields comfortably.
        parent::__construct( $id_base, $name, $widget_opts, [ 'width' => 400 ] );
    }

    /* -----------------------------------------------------------------------
     * widget() — front-end output
     * -------------------------------------------------------------------- */

    public function widget( $args, $instance ): void {
        $instance = $this->parse_instance( $instance );

        // widget_title is the canonical classic-widget filter (all 3 documented params).
        $title = apply_filters( 'widget_title', $instance['title'], $instance, $this->id_base );

        // $args values are trusted theme-registered HTML; annotate for WPCS.
        echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

        if ( ! empty( $title ) ) {
            echo $args['before_title'] . esc_html( $title ) . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }

        $this->render_content( $instance );

        echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    /**
     * Subclasses output their specific widget body here (already inside wrapper).
     */
    abstract protected function render_content( array $instance ): void;

    /**
     * Merge saved instance with widget-specific defaults.
     * [F10] Centralises defaults; subclasses override get_instance_defaults().
     */
    protected function parse_instance( array $instance ): array {
        return wp_parse_args( $instance, $this->get_instance_defaults() );
    }

    /**
     * Default instance values shared by all widgets.
     * Subclasses call parent::get_instance_defaults() and merge their own keys.
     */
    protected function get_instance_defaults(): array {
        return [
            'title'       => '',
            'redirect_to' => '',
            'show_links'  => 1,
        ];
    }

    /* -----------------------------------------------------------------------
     * update() — save widget settings
     * [F2] wp_unslash() BEFORE sanitize_*: WP magic-quotes all superglobals.
     *      Without unslash, "O'Brien" is stored as "O\'Brien".
     * [F3] sanitize_url() (canonical since WP 5.9) for URL input storage.
     *      esc_url_raw() is now just an alias for it, but WPCS flags esc_url_raw()
     *      when used as a sanitizer rather than an escaper.
     * -------------------------------------------------------------------- */

    public function update( $new_instance, $old_instance ): array {
        return $this->sanitize_instance( $new_instance );
    }

    protected function sanitize_instance( array $new_instance ): array {
        return [
            // [F2] wp_unslash() before sanitize_text_field.
            'title'       => sanitize_text_field( wp_unslash( $new_instance['title']       ?? '' ) ),
            // [F2][F3] wp_unslash() + sanitize_url() for URL input.
            'redirect_to' => sanitize_url( wp_unslash( $new_instance['redirect_to']        ?? '' ) ),
            'show_links'  => ! empty( $new_instance['show_links'] ) ? 1 : 0,
        ];
    }

    /* -----------------------------------------------------------------------
     * Shared admin form field partials
     * -------------------------------------------------------------------- */

    /**
     * Render the Title input.
     *
     * [F1] $default_title is now explicit — each subclass passes its own correct
     *      default string. The old code hardcoded 'Login' for every widget subclass.
     */
    protected function render_title_field( array $instance, string $default_title = '' ): void {
        $title = ( $instance['title'] !== '' ) ? $instance['title'] : $default_title;
        ?>
        <p>
            <label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
                <?php esc_html_e( 'Title:', 'frontend-auth' ); ?>
            </label>
            <input class="widefat"
                   id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"
                   name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>"
                   type="text"
                   value="<?php echo esc_attr( $title ); ?>">
        </p>
        <?php
    }

    /**
     * Render the Redirect URL input.
     */
    protected function render_redirect_field( array $instance, string $label = '' ): void {
        $label       = $label ?: __( 'Redirect URL after success:', 'frontend-auth' );
        $redirect_to = $instance['redirect_to'] ?? '';
        ?>
        <p>
            <label for="<?php echo esc_attr( $this->get_field_id( 'redirect_to' ) ); ?>">
                <?php echo esc_html( $label ); ?>
            </label>
            <input class="widefat"
                   id="<?php echo esc_attr( $this->get_field_id( 'redirect_to' ) ); ?>"
                   name="<?php echo esc_attr( $this->get_field_name( 'redirect_to' ) ); ?>"
                   type="text"
                   placeholder="<?php esc_attr_e( 'Default: admin dashboard', 'frontend-auth' ); ?>"
                   value="<?php echo esc_attr( $redirect_to ); ?>">
        </p>
        <?php
    }

    /**
     * Render the "Show action links" checkbox.
     */
    protected function render_show_links_field( array $instance ): void {
        $show_links = (bool) ( $instance['show_links'] ?? true );
        ?>
        <p>
            <label>
                <input type="checkbox"
                       name="<?php echo esc_attr( $this->get_field_name( 'show_links' ) ); ?>"
                       value="1"
                       <?php checked( $show_links ); ?>>
                <?php esc_html_e( 'Show action links below form', 'frontend-auth' ); ?>
            </label>
        </p>
        <?php
    }

    /**
     * Build render args array for fauth_render_form().
     *
     * [F4] redirect_to was already sanitized on save via sanitize_url().
     *      At output time the correct function is esc_url() (HTML attribute escaping),
     *      NOT sanitize_url() again. sanitize_url = input; esc_url = output.
     */
    protected function build_render_args( array $instance ): array {
        return [
            'show_links'  => (bool) ( $instance['show_links'] ?? true ),
            'redirect_to' => esc_url( $instance['redirect_to'] ?? '' ), // [F4]
        ];
    }
}

/* -----------------------------------------------------------------------
 * 1. Login Widget
 * -------------------------------------------------------------------- */

class FAUTH_Login_Widget extends FAUTH_Abstract_Widget {

    protected string $form_name = 'login';

    public function __construct() {
        $this->init_widget(
            'fauth_login_widget',
            __( 'Frontend Auth: Login', 'frontend-auth' ),
            [
                'description' => __( 'Displays the login form. Shows a welcome panel when the user is logged in.', 'frontend-auth' ),
                'classname'   => 'widget_fauth widget_fauth_login',
            ]
        );
    }

    protected function get_instance_defaults(): array {
        return array_merge( parent::get_instance_defaults(), [
            'title'          => __( 'Login', 'frontend-auth' ),
        ] );
    }

    protected function render_content( array $instance ): void {
        if ( is_user_logged_in() ) {
            return; // Logged-in state handled by external dashboard plugins.
        }
        echo fauth_render_form( 'login', $this->build_render_args( $instance ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function form( $instance ): void {
        $instance = $this->parse_instance( $instance );
        $this->render_title_field( $instance, __( 'Login', 'frontend-auth' ) ); // [F1]
        $this->render_redirect_field( $instance );
        $this->render_show_links_field( $instance );
        ?>
        <?php
    }

    public function update( $new_instance, $old_instance ): array {
        $sanitized                   = $this->sanitize_instance( $new_instance );
        return $sanitized;
    }
}

/* -----------------------------------------------------------------------
 * 2. Register Widget
 * -------------------------------------------------------------------- */

class FAUTH_Register_Widget extends FAUTH_Abstract_Widget {

    protected string $form_name = 'register';

    public function __construct() {
        $this->init_widget(
            'fauth_register_widget',
            __( 'Frontend Auth: Register', 'frontend-auth' ),
            [
                'description' => __( 'Displays the user registration form.', 'frontend-auth' ),
                'classname'   => 'widget_fauth widget_fauth_register',
            ]
        );
    }

    protected function get_instance_defaults(): array {
        return array_merge( parent::get_instance_defaults(), [
            'title' => __( 'Register', 'frontend-auth' ),
        ] );
    }

    /**
     * [F9] Override widget() entirely to handle the registration-disabled notice
     *      INSIDE before_widget / after_widget. The old render_content() echoed
     *      the notice raw before the wrapper opened, producing broken widget-area HTML.
     */
    public function widget( $args, $instance ): void {
        $instance = $this->parse_instance( $instance );

        if ( ! get_option( 'users_can_register' ) ) {
            // Non-admins: silently suppress the widget.
            if ( ! current_user_can( 'manage_options' ) ) {
                return;
            }
            // Admins: show the notice inside the theme wrapper. [F9]
            echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo '<p class="fauth-notice">'
                . esc_html__( 'User registration is currently disabled. Enable it under Settings → General.', 'frontend-auth' )
                . '</p>';
            echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            return;
        }

        // Normal path — delegate to parent.
        parent::widget( $args, $instance );
    }

    protected function render_content( array $instance ): void {
        if ( is_user_logged_in() ) {
            return;
        }
        echo fauth_render_form( 'register', $this->build_render_args( $instance ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function form( $instance ): void {
        $instance = $this->parse_instance( $instance );
        $this->render_title_field( $instance, __( 'Register', 'frontend-auth' ) ); // [F1]
        $this->render_redirect_field( $instance, __( 'Redirect URL after registration:', 'frontend-auth' ) );
        $this->render_show_links_field( $instance );
    }
}

/* -----------------------------------------------------------------------
 * 3. Lost Password Widget
 * -------------------------------------------------------------------- */

class FAUTH_Lost_Password_Widget extends FAUTH_Abstract_Widget {

    protected string $form_name = 'lostpassword';

    public function __construct() {
        $this->init_widget(
            'fauth_lost_password_widget',
            __( 'Frontend Auth: Lost Password', 'frontend-auth' ),
            [
                'description' => __( 'Displays the lost password / password reset form.', 'frontend-auth' ),
                'classname'   => 'widget_fauth widget_fauth_lostpassword',
            ]
        );
    }

    protected function get_instance_defaults(): array {
        return array_merge( parent::get_instance_defaults(), [
            'title' => __( 'Reset Password', 'frontend-auth' ),
        ] );
    }

    protected function render_content( array $instance ): void {
        if ( is_user_logged_in() ) {
            return;
        }
        echo fauth_render_form( 'lostpassword', $this->build_render_args( $instance ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function form( $instance ): void {
        $instance = $this->parse_instance( $instance );
        $this->render_title_field( $instance, __( 'Reset Password', 'frontend-auth' ) ); // [F1]
        $this->render_show_links_field( $instance );
    }
}

/* -----------------------------------------------------------------------
 * 5. Reset Password Widget
 *
 * Why this needs to be a widget and not just the automatic rewrite rule:
 * When an Elementor template is applied to a page, Elementor owns the
 * page canvas entirely. The virtual "post" injected by fauth_the_posts()
 * has no real WP page behind it, so Elementor's Theme Builder conditions
 * never match it and the template is not applied. The result is a bare
 * unstyled form with no header/footer.
 *
 * The correct solution for Elementor sites is:
 *  1. Create a real WordPress page (e.g. /reset-password/).
 *  2. Set that page's slug to match the fauth_slug_resetpass option.
 *  3. Drop this widget into any Elementor widget area on that page,
 *     OR use Elementor's Shortcode widget with [frontend-auth action="resetpass"].
 *  4. Apply any Elementor Theme Builder template to it normally.
 *
 * The widget reads rp_key and rp_login from the GET parameters that
 * WordPress puts in every password-reset email link. If either is absent
 * (e.g. someone navigates directly to the page without a reset link),
 * the widget shows a friendly "no valid reset link" message instead of
 * a broken form.
 * -------------------------------------------------------------------- */

class FAUTH_Reset_Password_Widget extends FAUTH_Abstract_Widget {

    protected string $form_name = 'resetpass';

    public function __construct() {
        $this->init_widget(
            'fauth_reset_password_widget',
            __( 'Frontend Auth: Reset Password', 'frontend-auth' ),
            [
                'description' => __( 'Displays the password reset form. Place on the page your reset-password email links point to.', 'frontend-auth' ),
                'classname'   => 'widget_fauth widget_fauth_resetpass',
            ]
        );
    }

    protected function get_instance_defaults(): array {
        return array_merge( parent::get_instance_defaults(), [
            'title'            => __( 'Reset Password', 'frontend-auth' ),
            'show_links'       => 0,   // links rarely make sense on a reset page
            'invalid_key_text' => '',  // empty = use built-in default message
        ] );
    }

    /**
     * Override widget() so we can seed the form's hidden fields from the
     * current request's GET params BEFORE render() is called.
     *
     * The resetpass form registered in forms.php already adds rp_key and
     * rp_login as hidden fields sourced from fauth_get_request_value('key','get')
     * and fauth_get_request_value('login','get'). That works correctly when the
     * form is rendered on the virtual rewrite-rule page. On a real WP page with
     * an Elementor template the same request params are present, so the form
     * fields are populated automatically — nothing extra needed at render time.
     *
     * What we DO need to handle here is the "no key in URL" case so the widget
     * shows a helpful message rather than a form that will always fail.
     */
    public function widget( $args, $instance ): void {
        $instance = $this->parse_instance( $instance );

        $raw_key   = $_GET['key']   ?? ''; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- type-checked and sanitized on the next line.
        $raw_login = $_GET['login'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- type-checked and sanitized on the next line.
        $rp_key   = is_string( $raw_key )   ? sanitize_text_field( wp_unslash( $raw_key ) )   : '';
        $rp_login = is_string( $raw_login ) ? sanitize_text_field( wp_unslash( $raw_login ) ) : '';

        echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

        $title = apply_filters( 'widget_title', $instance['title'], $instance, $this->id_base );
        if ( ! empty( $title ) ) {
            echo $args['before_title'] . esc_html( $title ) . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }

        if ( empty( $rp_key ) || empty( $rp_login ) ) {
            // No valid reset-link parameters in the URL.
            $invalid_text = ! empty( $instance['invalid_key_text'] )
                ? $instance['invalid_key_text']
                : __( 'This password reset link is invalid or has expired. Please request a new one.', 'frontend-auth' );

            echo '<div class="fauth fauth-form fauth-form-resetpass">'
                . '<ul class="fauth-errors" role="alert">'
                . '<li class="fauth-error">' . esc_html( $invalid_text ) . '</li>'
                . '</ul>'
                . '<p class="fauth-links"><a href="' . esc_url( fauth_get_action_url( 'lostpassword' ) ) . '">'
                . esc_html__( 'Request a new password reset link', 'frontend-auth' )
                . '</a></p>'
                . '</div>';
        } else {
            // Valid key + login present — render the form normally.
            // forms.php already wired rp_key/rp_login fields to read from GET,
            // so they will be populated correctly without any extra intervention.
            $this->render_content( $instance );
        }

        echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    protected function render_content( array $instance ): void {
        echo fauth_render_form( 'resetpass', $this->build_render_args( $instance ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function form( $instance ): void {
        $instance = $this->parse_instance( $instance );
        $this->render_title_field( $instance, __( 'Reset Password', 'frontend-auth' ) );
        $this->render_show_links_field( $instance );
        ?>
        <p>
            <label for="<?php echo esc_attr( $this->get_field_id( 'invalid_key_text' ) ); ?>">
                <?php esc_html_e( 'Message when reset link is missing or expired:', 'frontend-auth' ); ?>
            </label>
            <textarea class="widefat"
                      id="<?php echo esc_attr( $this->get_field_id( 'invalid_key_text' ) ); ?>"
                      name="<?php echo esc_attr( $this->get_field_name( 'invalid_key_text' ) ); ?>"
                      rows="3"
                      placeholder="<?php esc_attr_e( 'Leave empty to use the default message.', 'frontend-auth' ); ?>"><?php echo esc_textarea( $instance['invalid_key_text'] ); ?></textarea>
        </p>
        <p class="description">
            <?php esc_html_e( 'Place this widget on the page your reset-password email links point to. Make sure that page\'s slug matches the "resetpass slug" in Frontend Auth settings.', 'frontend-auth' ); ?>
        </p>
        <?php
    }

    public function update( $new_instance, $old_instance ): array {
        $sanitized                     = $this->sanitize_instance( $new_instance );
        // sanitize_textarea_field preserves newlines, strips tags — correct for freeform message text.
        $sanitized['invalid_key_text'] = sanitize_textarea_field( wp_unslash( $new_instance['invalid_key_text'] ?? '' ) );
        return $sanitized;
    }
}

/* -----------------------------------------------------------------------
 * 5. Account Widget
 *
 * Frontend profile editing for the logged-in user: display name, email,
 * and an optional password change. Renders nothing for guests — the
 * account page itself redirects guests to login (see hooks.php), and in
 * any other placement an account form for a guest is meaningless.
 * -------------------------------------------------------------------- */

class FAUTH_Account_Widget extends FAUTH_Abstract_Widget {

    protected string $form_name = 'account';

    public function __construct() {
        $this->init_widget(
            'fauth_account_widget',
            __( 'Frontend Auth: Account', 'frontend-auth' ),
            [
                'description' => __( 'Lets logged-in users edit their display name, email, and password from the frontend.', 'frontend-auth' ),
                'classname'   => 'widget_fauth widget_fauth_account',
            ]
        );
    }

    protected function get_instance_defaults(): array {
        return array_merge( parent::get_instance_defaults(), [
            'title' => __( 'My Account', 'frontend-auth' ),
        ] );
    }

    protected function render_content( array $instance ): void {
        if ( ! is_user_logged_in() ) {
            return;
        }
        echo fauth_render_form( 'account', $this->build_render_args( $instance ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    public function form( $instance ): void {
        $instance = $this->parse_instance( $instance );
        $this->render_title_field( $instance, __( 'My Account', 'frontend-auth' ) );
        $this->render_show_links_field( $instance );
        ?>
        <p class="description">
            <?php esc_html_e( 'Only visible to logged-in users. Guests visiting the Account page are redirected to the login form.', 'frontend-auth' ); ?>
        </p>
        <?php
    }
}

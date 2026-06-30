<?php
/**
 * Zen Login & Authentication – Elementor Widgets
 *
 * v1.4.8 — Second audit bug-fix release.
 *
 * Fixes applied in this version:
 *  #1  Register content_template() was missing password + confirm-password rows.
 *  #2  Group_Control_Box_Shadow wrapped in class_exists() guard for safety.
 *  #3  URL-purpose controls changed from TEXT to URL type; render methods updated
 *      to read the URL control's array format ['url' => ...].
 *  #4  $link_callback now initialised to null before if($form) in Register and
 *      Lost Password widgets; eliminates undefined-variable notice on null form.
 *  #5  render_form_title() uses add_render_attribute() + add_inline_editing_attributes().
 *  #6  'dynamic' => ['active' => true] added to every TEXT / TEXTAREA control.
 *  #7  Login widget link detection uses explicit URL checks for both links
 *      instead of fragile negation of the register check.
 *  #8  btn_width changed from responsive SELECT to CHOOSE + selectors_dictionary.
 *  #9  form_title_tag SELECT now includes 'span', matching the renderer allowlist.
 * #10  is_dynamic_content() overridden to false on Login, Register, Lost Password;
 *      true only on Reset Password which reads $_GET.
 * #11  Hardcoded hex colours in editor-only preview divs replaced with CSS classes
 *      enqueued via elementor/editor/after_enqueue_styles.
 *
 *
 * Audit-2 fixes (v1.4.8):
 *  A  Triple-brace in placeholder HTML attributes → escaped double-brace
 *  B  render_editor_placeholder() inline styles → CSS class
 *  C  class_exists() double-escaped backslash corrected
 *  D  bindPasswordToggle() + bindPasswordStrength() wired to element_ready lifecycle
 *  E  outline:none replaced with :focus/:focus-visible pair (WCAG 2.2)
 *  F  field_focus_shadow split into spread SLIDER + color controls
 *  G  Messages & Errors: added Group_Control_Typography for error + message text
 *  H  Remember Me: added dedicated style section (color, typography, gap)
 *  I  label_spacing, field_spacing, toggle_gap: added em/rem units
 *  J  Password toggle: flex layout via .fauth-field-wrap--password (CSS + JS)
 *  K  Action Links: added text-decoration SELECT control
 *  L  CSS: description + strength meter colors tokenised as custom properties
 *  M  Password strength meter: full style section (typography + 4-state colours)
 *  N  toggle_margin_top removed; replaced with toggle_gap targeting flex gap
 *  O  h_placeholders, h_toggle renamed to zenlogau_h_* to avoid cross-widget ID collision
 *
 * Audit-3 fixes (v2.1.2) — wp.org "escape on output" review:
 *  P  EVERY Backbone interpolation of a user setting in all content_template()
 *     previews switched from raw triple-brace to escaped double-brace {{ }}
 *     (form title text + tag, field labels, button/link/toggle text, passkey +
 *     Google button text, invalid-key message). Raw triple-brace emitted
 *     unescaped HTML into the editor preview — an editor-context XSS vector.
 *  Q  google_button_content_template() now echoes internally from string
 *     literals + esc_html__() (previously `echo $this->method()` behind a
 *     misleading "escaped during construction" phpcs:ignore). Editor-preview
 *     icons are static inline SVG literals (viewBox is case-sensitive, so
 *     wp_kses() is unsuitable), leaving no OutputNotEscaped suppression here.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* =======================================================================
 * Registration functions
 * ===================================================================== */

function zenlogau_register_elementor_category( $elements_manager ): void {
    $elements_manager->add_category( 'zen-login-authentication', [
        'title' => esc_html__( 'Zen Login & Authentication', 'zen-login-authentication' ),
        'icon'  => 'eicon-lock-user',
    ] );
}

function zenlogau_register_elementor_widgets( $manager ): void {
    $widgets = [
        'login'        => ZENLOGAU_Elementor_Login_Widget::class,
        'register'     => ZENLOGAU_Elementor_Register_Widget::class,
        'lostpassword' => ZENLOGAU_Elementor_Lost_Password_Widget::class,
        'resetpass'    => ZENLOGAU_Elementor_Reset_Password_Widget::class,
        'account'      => ZENLOGAU_Elementor_Account_Widget::class,
    ];
    foreach ( $widgets as $key => $class ) {
        if ( zenlogau_widget_enabled( $key ) ) {
            $manager->register( new $class() );
        }
    }
}

/* =======================================================================
 * Abstract base
 * ===================================================================== */

abstract class ZENLOGAU_Elementor_Base_Widget extends \Elementor\Widget_Base {

    public function get_categories(): array  { return [ 'zen-login-authentication' ]; }
    public function get_keywords(): array    { return [ 'login', 'auth', 'register', 'password', 'fauth' ]; }
    public function get_style_depends(): array  { return [ 'zen-login-authentication' ]; }
    public function get_script_depends(): array { return [ 'zen-login-authentication' ]; }
    public function has_widget_inner_wrapper(): bool { return false; }
    // Auth forms must NEVER be cached by Elementor's element cache: every form
    // carries a per-request nonce (a cached/stale nonce makes login fail with a
    // security error), and the login/register/lost-password widgets read
    // ?redirect_to= from the URL (a cached form freezes redirect_to, so users are
    // sent to a stale destination instead of where they were heading). Marking the
    // content dynamic forces Elementor to render these widgets fresh on every load.
    protected function is_dynamic_content(): bool { return true; }

    /* --- Shared content controls --- */

    protected function register_title_controls(): void {
        $this->add_control( 'form_title_text', [
            'label'       => esc_html__( 'Form Title', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Leave empty to hide', 'zen-login-authentication' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ], // Fix #6
        ] );
        $this->add_control( 'form_title_tag', [
            'label'   => esc_html__( 'Title HTML Tag', 'zen-login-authentication' ),
            'type'    => \Elementor\Controls_Manager::SELECT,
            'default' => 'h3',
            'options' => [ 'h1'=>'H1','h2'=>'H2','h3'=>'H3','h4'=>'H4','h5'=>'H5','h6'=>'H6','div'=>'div','span'=>'span','p'=>'p' ], // Fix #9 — matches renderer allowlist
            'condition' => [ 'form_title_text!' => '' ],
        ] );
    }

    protected function register_redirect_controls(): void {
        $this->add_control( 'redirect_to', [
            'label'       => esc_html__( 'Redirect URL', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::URL, // Fix #3
            'dynamic'     => [ 'active' => true ],              // Fix #6
            'default'     => [ 'url' => '' ],
            'placeholder' => esc_html__( 'Default: admin dashboard', 'zen-login-authentication' ),
            'label_block' => true,
            'separator'   => 'before',
        ] );
        $this->add_control( 'show_links', [
            'label'        => esc_html__( 'Show action links', 'zen-login-authentication' ),
            'type'         => \Elementor\Controls_Manager::SWITCHER,
            'label_on'     => esc_html__( 'Yes', 'zen-login-authentication' ),
            'label_off'    => esc_html__( 'No', 'zen-login-authentication' ),
            'return_value' => 'yes',
            'default'      => 'yes',
        ] );
    }

    /* --- Shared style controls --- */

    protected function register_form_style_controls(): void {
        // Form Container
        $this->start_controls_section( 'section_style_form', [
            'label' => esc_html__( 'Form Container', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_responsive_control( 'form_width', [
            'label'      => esc_html__( 'Width', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', '%', 'vw' ],
            'range'      => [
                'px' => [ 'min' => 200, 'max' => 1200, 'step' => 10 ],
                '%'  => [ 'min' => 10,  'max' => 100 ],
                'vw' => [ 'min' => 10,  'max' => 100 ],
            ],
            'selectors'  => [
                '{{WRAPPER}} .fauth-form-wrap' => 'width: {{SIZE}}{{UNIT}};',
            ],
        ] );

        $this->add_responsive_control( 'form_max_width', [
            'label'      => esc_html__( 'Max Width', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', '%', 'vw' ],
            'range'      => [
                'px' => [ 'min' => 200, 'max' => 1200, 'step' => 10 ],
                '%'  => [ 'min' => 10,  'max' => 100 ],
                'vw' => [ 'min' => 10,  'max' => 100 ],
            ],
            'selectors'  => [
                '{{WRAPPER}} .fauth-form-wrap' => 'max-width: {{SIZE}}{{UNIT}};',
            ],
        ] );

        /*
         * ALIGNMENT (v1.4.4):
         *
         * Alignment uses the standard CSS margin-auto technique.
         * This is identical to how Elementor's own image and button widgets
         * implement horizontal alignment.
         *
         * IMPORTANT: alignment is only VISIBLE when the Form Width control
         * (above) is set to a value smaller than the column width. Without a
         * constrained width the form fills 100 % of the column regardless of
         * alignment — this is correct CSS behaviour, not a bug.
         *
         * The v1.4.2 approach (display:flex on {{WRAPPER}}) was reverted
         * because adding flex to the widget root element conflicts with
         * Elementor's Flexbox Container layout: the widget is already a flex
         * item inside the column/container, and mutating its display property
         * causes unpredictable cross-axis stretching and breaking behaviour in
         * both legacy Section/Column and new Flexbox Container contexts.
         */
        $this->add_responsive_control( 'form_align', [
            'label'       => esc_html__( 'Alignment', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::CHOOSE,
            'options'     => [
                'left'   => [ 'title' => esc_html__( 'Left',   'zen-login-authentication' ), 'icon' => 'eicon-h-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-h-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right',  'zen-login-authentication' ), 'icon' => 'eicon-h-align-right' ],
            ],
            'description' => esc_html__( 'Requires a Form Width value smaller than the column width to be visible.', 'zen-login-authentication' ),
            'selectors_dictionary' => [
                'left'   => 'margin-left: 0; margin-right: auto;',
                'center' => 'margin-left: auto; margin-right: auto;',
                'right'  => 'margin-left: auto; margin-right: 0;',
            ],
            'selectors' => [
                '{{WRAPPER}} .fauth-form-wrap' => '{{VALUE}}',
            ],
            'separator' => 'after',
        ] );

        $this->add_control( 'form_bg_color', [
            'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-form-wrap' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'form_padding', [
            'label' => esc_html__( 'Padding', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em', '%' ],
            'selectors' => [ '{{WRAPPER}} .fauth-form-wrap' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'form_spacing_top', [
            'label' => esc_html__( 'Spacing Top', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range' => [ 'px' => [ 'min' => 0, 'max' => 100 ], 'em' => [ 'min' => 0, 'max' => 6 ] ],
            'selectors' => [ '{{WRAPPER}} .fauth-form-wrap' => 'margin-top: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'form_spacing_bottom', [
            'label' => esc_html__( 'Spacing Bottom', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range' => [ 'px' => [ 'min' => 0, 'max' => 100 ], 'em' => [ 'min' => 0, 'max' => 6 ] ],
            'selectors' => [ '{{WRAPPER}} .fauth-form-wrap' => 'margin-bottom: {{SIZE}}{{UNIT}};' ],
            'separator' => 'after',
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'form_border', 'selector' => '{{WRAPPER}} .fauth-form-wrap' ] );
        $this->add_responsive_control( 'form_border_radius', [
            'label' => esc_html__( 'Border Radius', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors' => [ '{{WRAPPER}} .fauth-form-wrap' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        // Fix #2 — class_exists() guard for safety across Elementor versions.
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'form_shadow', 'selector' => '{{WRAPPER}} .fauth-form-wrap' ] );
        }
        $this->end_controls_section();

        // Title
        $this->start_controls_section( 'section_style_title', [
            'label' => esc_html__( 'Form Title', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
            'condition' => [ 'form_title_text!' => '' ],
        ] );
        $this->add_control( 'title_color', [ 'label' => esc_html__( 'Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-form-title' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'title_typography', 'selector' => '{{WRAPPER}} .fauth-form-title' ] );
        $this->add_responsive_control( 'title_align', [
            'label' => esc_html__( 'Alignment', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::CHOOSE,
            'options' => [ 'left' => [ 'title' => 'Left', 'icon' => 'eicon-text-align-left' ], 'center' => [ 'title' => 'Center', 'icon' => 'eicon-text-align-center' ], 'right' => [ 'title' => 'Right', 'icon' => 'eicon-text-align-right' ] ],
            'selectors' => [ '{{WRAPPER}} .fauth-form-title' => 'text-align: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'title_spacing', [ 'label' => esc_html__( 'Bottom Spacing', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 60 ] ], 'selectors' => [ '{{WRAPPER}} .fauth-form-title' => 'margin-bottom: {{SIZE}}{{UNIT}};' ] ] );
        $this->end_controls_section();

        // Labels
        $this->start_controls_section( 'section_style_labels', [
            'label' => esc_html__( 'Labels', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'label_color', [ 'label' => esc_html__( 'Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-label' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'label_typography', 'selector' => '{{WRAPPER}} .fauth-label' ] );
        $this->add_responsive_control( 'label_spacing', [ 'label' => esc_html__( 'Bottom Spacing', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em', 'rem' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 30 ], 'em' => [ 'min' => 0, 'max' => 4 ], 'rem' => [ 'min' => 0, 'max' => 4 ] ], 'selectors' => [ '{{WRAPPER}} .fauth-label' => 'margin-bottom: {{SIZE}}{{UNIT}};' ] ] ); // Fix I
        $this->add_control( 'required_color', [ 'label' => esc_html__( 'Required Mark Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-required' => 'color: {{VALUE}};' ] ] );
        $this->end_controls_section();

        // Fields
        $this->start_controls_section( 'section_style_fields', [
            'label' => esc_html__( 'Input Fields', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'field_text_color', [ 'label' => esc_html__( 'Text Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-field' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'field_placeholder_color', [ 'label' => esc_html__( 'Placeholder Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-field::placeholder' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'field_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-field' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'field_typography', 'selector' => '{{WRAPPER}} .fauth-field' ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'field_border', 'selector' => '{{WRAPPER}} .fauth-field' ] );
        $this->add_responsive_control( 'field_border_radius', [ 'label' => esc_html__( 'Border Radius', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .fauth-field' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'field_padding', [ 'label' => esc_html__( 'Padding', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .fauth-field' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_control( 'heading_focus', [ 'label' => esc_html__( 'Focus State', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'field_focus_color', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-field:focus' => 'border-color: {{VALUE}};' ] ] );
        // Fix F — separated spread and color so both are independently adjustable
        $this->add_control( 'field_focus_shadow_spread', [
            'label'      => esc_html__( 'Glow Spread (px)', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 8, 'step' => 1 ] ],
            'default'    => [ 'size' => 1 ],
            'selectors'  => [],  // combined below via field_focus_shadow_color
        ] );
        $this->add_control( 'field_focus_shadow_color', [
            'label'       => esc_html__( 'Glow Color', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::COLOR,
            'description' => esc_html__( 'Set to transparent to remove the focus glow.', 'zen-login-authentication' ),
            'selectors'   => [
                // Uses spread from field_focus_shadow_spread. Elementor doesn't
                // cross-reference controls in selectors, so the spread is read
                // at render time via a CSS custom property injected below.
                '{{WRAPPER}} .fauth-field:focus' => 'box-shadow: 0 0 0 {{field_focus_shadow_spread.SIZE}}px {{VALUE}};',
            ],
        ] );
        $this->add_responsive_control( 'field_spacing', [ 'label' => esc_html__( 'Field Spacing', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em', 'rem' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 40 ], 'em' => [ 'min' => 0, 'max' => 5 ], 'rem' => [ 'min' => 0, 'max' => 5 ] ], 'selectors' => [ '{{WRAPPER}} .fauth-field-wrap' => 'margin-bottom: {{SIZE}}{{UNIT}};' ], 'separator' => 'before' ] ); // Fix I
        $this->add_control( 'heading_description', [ 'label' => esc_html__( 'Help Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'description_color', [ 'label' => esc_html__( 'Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-description' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'description_typography', 'selector' => '{{WRAPPER}} .fauth-description' ] );
        $this->end_controls_section();

        // Button
        $this->start_controls_section( 'section_style_button', [
            'label' => esc_html__( 'Button', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'btn_typography', 'selector' => '{{WRAPPER}} .fauth-submit-button' ] );
        // Fix #8 — CHOOSE + selectors_dictionary is the correct pattern for non-numeric CSS toggles.
        $this->add_responsive_control( 'btn_width', [
            'label'               => esc_html__( 'Width', 'zen-login-authentication' ),
            'type'                => \Elementor\Controls_Manager::CHOOSE,
            'options'             => [
                'auto' => [ 'title' => esc_html__( 'Auto',       'zen-login-authentication' ), 'icon' => 'eicon-fit-to-screen' ],
                'full' => [ 'title' => esc_html__( 'Full Width', 'zen-login-authentication' ), 'icon' => 'eicon-h-align-stretch' ],
            ],
            'default'             => 'full',
            'selectors_dictionary' => [
                'auto' => 'width: auto;',
                'full' => 'width: 100%;',
            ],
            'selectors'           => [
                '{{WRAPPER}} .fauth-submit-button' => '{{VALUE}}',
            ],
        ] );
        $this->add_responsive_control( 'btn_padding', [ 'label' => esc_html__( 'Padding', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .fauth-submit-button' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'btn_radius', [ 'label' => esc_html__( 'Border Radius', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .fauth-submit-button' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->start_controls_tabs( 'btn_tabs' );
        $this->start_controls_tab( 'btn_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'btn_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-submit-button' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-submit-button' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'btn_border', 'selector' => '{{WRAPPER}} .fauth-submit-button' ] );
        // Fix #2
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'btn_shadow', 'selector' => '{{WRAPPER}} .fauth-submit-button' ] );
        }
        $this->end_controls_tab();
        $this->start_controls_tab( 'btn_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'btn_color_h', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-submit-button:hover,{{WRAPPER}} .fauth-submit-button:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_bg_h', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-submit-button:hover,{{WRAPPER}} .fauth-submit-button:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_border_h', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-submit-button:hover,{{WRAPPER}} .fauth-submit-button:focus' => 'border-color: {{VALUE}};' ] ] );
        // Fix #2
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'btn_shadow_h', 'selector' => '{{WRAPPER}} .fauth-submit-button:hover,{{WRAPPER}} .fauth-submit-button:focus' ] );
        }
        $this->add_control( 'btn_transition', [ 'label' => esc_html__( 'Transition (ms)', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'range' => [ 'px' => [ 'min' => 0, 'max' => 1000, 'step' => 50 ] ], 'default' => [ 'size' => 200 ], 'selectors' => [ '{{WRAPPER}} .fauth-submit-button' => 'transition-duration: {{SIZE}}ms;' ] ] );
        $this->end_controls_tab();
        $this->end_controls_tabs();
        $this->end_controls_section();

        // Links
        $this->start_controls_section( 'section_style_links', [
            'label' => esc_html__( 'Action Links', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'links_color', [ 'label' => esc_html__( 'Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-links a' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'links_color_h', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-links a:hover' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'links_typography', 'selector' => '{{WRAPPER}} .fauth-links' ] );
        $this->add_responsive_control( 'links_align', [ 'label' => esc_html__( 'Alignment', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::CHOOSE, 'options' => [ 'left' => [ 'title' => 'Left', 'icon' => 'eicon-text-align-left' ], 'center' => [ 'title' => 'Center', 'icon' => 'eicon-text-align-center' ], 'right' => [ 'title' => 'Right', 'icon' => 'eicon-text-align-right' ] ], 'selectors' => [ '{{WRAPPER}} .fauth-links' => 'text-align: {{VALUE}};' ] ] );
        // Fix K — text-decoration control for links
        $this->add_control( 'links_text_decoration', [
            'label'               => esc_html__( 'Underline', 'zen-login-authentication' ),
            'type'                => \Elementor\Controls_Manager::SELECT,
            'default'             => 'default',
            'options'             => [
                'default'   => esc_html__( 'Default (hover only)',  'zen-login-authentication' ),
                'always'    => esc_html__( 'Always',                'zen-login-authentication' ),
                'none'      => esc_html__( 'Never',                 'zen-login-authentication' ),
            ],
            'selectors_dictionary' => [
                'always'  => 'text-decoration: underline;',
                'none'    => 'text-decoration: none;',
                'default' => '',
            ],
            'selectors' => [
                '{{WRAPPER}} .fauth-links a'        => '{{VALUE}}',
                '{{WRAPPER}} .fauth-links a:hover'  => '{{VALUE}}',
            ],
        ] );
        $this->end_controls_section();

        // Messages
        $this->start_controls_section( 'section_style_msg', [
            'label' => esc_html__( 'Messages & Errors', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        // Fix G — added Typography controls for error and message text
        $this->add_control( 'h_err', [ 'label' => esc_html__( 'Errors', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING ] );
        $this->add_control( 'err_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-error' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'err_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-error' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'err_border', [ 'label' => esc_html__( 'Border', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-error' => 'border-left-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'err_typography', 'selector' => '{{WRAPPER}} .fauth-error' ] );
        $this->add_control( 'h_msg', [ 'label' => esc_html__( 'Success', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'msg_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-message' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'msg_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-message' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'msg_border', [ 'label' => esc_html__( 'Border', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-message' => 'border-left-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'msg_typography', 'selector' => '{{WRAPPER}} .fauth-message' ] );
        $this->end_controls_section();
    }


    /* --- Shared password toggle content controls (Login / Register / Reset Password) --- */

    /**
     * Register Show/Hide label controls for the password-visibility toggle button.
     * Call from any widget that renders a password field.
     */
    protected function register_password_toggle_content_controls(): void {
        $this->add_control( 'zenlogau_h_toggle', [
            'label'     => esc_html__( 'Password Toggle Button', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::HEADING,
            'separator' => 'before',
        ] );
        $this->add_control( 'toggle_show_text', [
            'label'       => esc_html__( 'Show label', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Show', 'zen-login-authentication' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ],
            'description' => esc_html__( 'Text on the toggle button when the password is hidden.', 'zen-login-authentication' ),
        ] );
        $this->add_control( 'toggle_hide_text', [
            'label'       => esc_html__( 'Hide label', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Hide', 'zen-login-authentication' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ],
            'description' => esc_html__( 'Text on the toggle button when the password is visible.', 'zen-login-authentication' ),
        ] );
    }

    /* --- Shared "Sign in with Google" controls (Login / Register) --- */

    protected function register_google_button_controls(): void {
        $this->add_control( 'zenlogau_h_google', [
            'label'     => esc_html__( 'Google Sign-In', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::HEADING,
            'separator' => 'before',
        ] );
        $this->add_control( 'show_google_button', [
            'label'        => esc_html__( 'Show Google button', 'zen-login-authentication' ),
            'type'         => \Elementor\Controls_Manager::SWITCHER,
            'label_on'     => esc_html__( 'Yes', 'zen-login-authentication' ),
            'label_off'    => esc_html__( 'No', 'zen-login-authentication' ),
            'return_value' => 'yes',
            'default'      => 'yes',
            'description'  => esc_html__( 'Appears on the live page only when Google sign-in is configured under Settings → Zen Login & Authentication.', 'zen-login-authentication' ),
        ] );
        $this->add_control( 'google_button_text', [
            'label'       => esc_html__( 'Google button text', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Continue with Google', 'zen-login-authentication' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ],
            'condition'   => [ 'show_google_button' => 'yes' ],
        ] );
    }

    /**
     * Style section for the Google button + divider.
     */
    protected function register_google_button_style_controls(): void {
        $this->start_controls_section( 'section_style_google', [
            'label'     => esc_html__( 'Google Button', 'zen-login-authentication' ),
            'tab'       => \Elementor\Controls_Manager::TAB_STYLE,
            'condition' => [ 'show_google_button' => 'yes' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'google_btn_typography',
            'selector' => '{{WRAPPER}} .fauth-google-btn',
        ] );
        $this->add_responsive_control( 'google_btn_padding', [
            'label'      => esc_html__( 'Padding', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-google-btn' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'google_btn_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-google-btn' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->start_controls_tabs( 'google_btn_tabs' );
        $this->start_controls_tab( 'google_btn_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'google_btn_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'google_btn_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'google_btn_border', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_tab();
        $this->start_controls_tab( 'google_btn_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'google_btn_color_h', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn:hover,{{WRAPPER}} .fauth-google-btn:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'google_btn_bg_h', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn:hover,{{WRAPPER}} .fauth-google-btn:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'google_btn_border_h', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-google-btn:hover,{{WRAPPER}} .fauth-google-btn:focus' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_tab();
        $this->end_controls_tabs();
        $this->add_control( 'google_divider_color', [
            'label'     => esc_html__( 'Divider Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'separator' => 'before',
            'selectors' => [
                '{{WRAPPER}} .fauth-sso-divider'          => 'color: {{VALUE}};',
                '{{WRAPPER}} .fauth-sso-divider::before,{{WRAPPER}} .fauth-sso-divider::after' => 'background-color: {{VALUE}};',
            ],
        ] );
        $this->end_controls_section();
    }

    /**
     * Style controls for the "Sign in with a passkey" button (login form only).
     * It uses .fauth-passkey-signin (not .fauth-submit-button), so the main
     * Button controls don't reach it — these give it its own Normal/Hover styling.
     */
    protected function register_passkey_button_style_controls(): void {
        $this->start_controls_section( 'section_style_passkey', [
            'label' => esc_html__( 'Passkey Button', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'passkey_btn_typography',
            'selector' => '{{WRAPPER}} .fauth-passkey-signin',
        ] );
        $this->add_responsive_control( 'passkey_btn_padding', [
            'label'      => esc_html__( 'Padding', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-passkey-signin' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'passkey_btn_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-passkey-signin' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->start_controls_tabs( 'passkey_btn_tabs' );
        $this->start_controls_tab( 'passkey_btn_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'passkey_btn_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'passkey_btn_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'passkey_btn_border', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_tab();
        $this->start_controls_tab( 'passkey_btn_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'passkey_btn_color_h', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin:hover,{{WRAPPER}} .fauth-passkey-signin:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'passkey_btn_bg_h', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin:hover,{{WRAPPER}} .fauth-passkey-signin:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'passkey_btn_border_h', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-passkey-signin:hover,{{WRAPPER}} .fauth-passkey-signin:focus' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_tab();
        $this->end_controls_tabs();
        $this->end_controls_section();
    }

    /**
     * Apply the widget's Google-button settings as request-scoped filters.
     * Returns a cleanup callable to invoke immediately after the form renders —
     * same add→render→remove pattern as the link filters (see render_login_form).
     */
    protected function setup_google_button_overrides( array $s ): callable {
        $hide = ( 'yes' !== ( $s['show_google_button'] ?? 'yes' ) );
        if ( $hide ) {
            add_filter( 'zenlogau_show_google_button', '__return_false', 99 );
        }
        $text    = trim( (string) ( $s['google_button_text'] ?? '' ) );
        $text_cb = null;
        if ( '' !== $text ) {
            $text_cb = static function () use ( $text ) {
                return $text;
            };
            add_filter( 'zenlogau_google_button_text', $text_cb, 99 );
        }
        return static function () use ( $hide, $text_cb ): void {
            if ( $hide ) {
                remove_filter( 'zenlogau_show_google_button', '__return_false', 99 );
            }
            if ( null !== $text_cb ) {
                remove_filter( 'zenlogau_google_button_text', $text_cb, 99 );
            }
        };
    }

    /**
     * Apply the widget's passkey-button text as a request-scoped filter, mirroring
     * the Google override. Returns a cleanup callable to run after the form renders.
     */
    protected function setup_passkey_button_overrides( array $s ): callable {
        $text    = trim( (string) ( $s['passkey_button_text'] ?? '' ) );
        $text_cb = null;
        if ( '' !== $text ) {
            $text_cb = static function () use ( $text ) {
                return $text;
            };
            add_filter( 'zenlogau_passkey_button_text', $text_cb, 99 );
        }
        return static function () use ( $text_cb ): void {
            if ( null !== $text_cb ) {
                remove_filter( 'zenlogau_passkey_button_text', $text_cb, 99 );
            }
        };
    }

    /**
     * Editor-preview markup for the Google button (Backbone template fragment).
     * Mirrors zenlogau_google_button_html(); shown whenever the widget toggle is on.
     */
    protected function google_button_content_template(): void {
        // Editor-preview only. Built entirely from literals + esc_html__(); the
        // Google "G" mark is a static inline SVG literal (kept here rather than via
        // a returned variable so output stays literal and needs no escaping wrapper,
        // and so the case-sensitive viewBox survives — wp_kses() lowercases it).
        echo '<# if ( "yes" === settings.show_google_button ) { #>'
            . '<div class="fauth-sso"><div class="fauth-sso-divider"><span>' . esc_html__( 'or', 'zen-login-authentication' ) . '</span></div>'
            . '<a class="fauth-google-btn" href="#" onclick="return false;">'
            . '<svg class="fauth-google-icon" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" focusable="false"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92a8.78 8.78 0 0 0 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.33A9 9 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.97 10.71A5.41 5.41 0 0 1 3.68 9c0-.59.1-1.17.28-1.71V4.96H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.04l3.01-2.33z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.59A9 9 0 0 0 .96 4.96l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg>'
            . '<span><# if(settings.google_button_text){#>{{settings.google_button_text}}<#}else{#>' . esc_html__( 'Continue with Google', 'zen-login-authentication' ) . '<#}#></span></a></div>'
            . '<# } #>';
    }



    /**
     * Register style controls for the password strength meter.
     * Fix M — strength meter had no Elementor styling surface.
     * Called only from the Register widget (the only widget that renders the meter).
     */
    protected function register_strength_meter_style_controls(): void {
        $this->start_controls_section( 'section_style_strength', [
            'label' => esc_html__( 'Password Strength Meter', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'strength_typography',
            'selector' => '{{WRAPPER}} #pass-strength-result',
        ] );
        $this->add_responsive_control( 'strength_border_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} #pass-strength-result' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_control( 'h_str_short', [ 'label' => esc_html__( 'Too Short', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_short', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_short',    [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_short',[ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_bad', [ 'label' => esc_html__( 'Weak', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_bad', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_bad',    [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_bad',[ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_good', [ 'label' => esc_html__( 'Good', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_good', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_good',    [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_good',[ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_strong', [ 'label' => esc_html__( 'Strong', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_strong', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_strong',    [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_strong',[ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_section();
    }

    /**
     * Register style controls for the "Remember Me" checkbox (Login widget only).
     * Fix H — checkbox label had no Elementor styling surface.
     */
    protected function register_checkbox_style_controls(): void {
        $this->start_controls_section( 'section_style_checkbox', [
            'label' => esc_html__( 'Remember Me', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'checkbox_color', [
            'label'     => esc_html__( 'Label Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-checkbox-label' => 'color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'checkbox_typography',
            'selector' => '{{WRAPPER}} .fauth-checkbox-label',
        ] );
        $this->add_responsive_control( 'checkbox_gap', [
            'label'      => esc_html__( 'Gap (checkbox ↔ label)', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 20 ] ],
            'selectors'  => [ '{{WRAPPER}} .fauth-checkbox-label' => 'margin-left: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->end_controls_section();
    }

    /**
     * Register style controls for the password-visibility toggle button.
     * Must be called from register_form_style_controls() only for widgets
     * that render password fields (Login, Register, Reset Password).
     * Separate from shared style controls so Lost Password widget stays clean.
     */
    protected function register_password_toggle_style_controls(): void {
        $this->start_controls_section( 'section_style_toggle', [
            'label' => esc_html__( 'Password Toggle', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'toggle_typography',
            'selector' => '{{WRAPPER}} .fauth-password-toggle',
        ] );
        $this->add_responsive_control( 'toggle_padding', [
            'label'      => esc_html__( 'Padding', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-password-toggle' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        // Fix N — negative range removed; Fix J means flex gap replaces margin-top
        // Renamed to toggle_gap and targets the flex gap between input and button
        $this->add_responsive_control( 'toggle_gap', [
            'label'      => esc_html__( 'Gap (input ↔ button)', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em', 'rem' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 20 ], 'em' => [ 'min' => 0, 'max' => 2 ], 'rem' => [ 'min' => 0, 'max' => 2 ] ],
            'default'    => [ 'size' => 6, 'unit' => 'px' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-field-wrap--password' => 'gap: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [
            'name'     => 'toggle_border',
            'selector' => '{{WRAPPER}} .fauth-password-toggle',
        ] );
        $this->add_responsive_control( 'toggle_border_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-password-toggle' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );

        // Normal / Hover tabs
        $this->start_controls_tabs( 'toggle_tabs' );

        $this->start_controls_tab( 'toggle_tab_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'toggle_color', [
            'label'     => esc_html__( 'Text Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle' => 'color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_bg', [
            'label'     => esc_html__( 'Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle' => 'background-color: {{VALUE}};' ],
        ] );
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [
                'name'     => 'toggle_shadow',
                'selector' => '{{WRAPPER}} .fauth-password-toggle',
            ] );
        }
        $this->end_controls_tab();

        $this->start_controls_tab( 'toggle_tab_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'toggle_color_h', [
            'label'     => esc_html__( 'Text Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle:hover, {{WRAPPER}} .fauth-password-toggle:focus' => 'color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_bg_h', [
            'label'     => esc_html__( 'Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle:hover, {{WRAPPER}} .fauth-password-toggle:focus' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_border_color_h', [
            'label'     => esc_html__( 'Border Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle:hover, {{WRAPPER}} .fauth-password-toggle:focus' => 'border-color: {{VALUE}};' ],
        ] );
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [
                'name'     => 'toggle_shadow_h',
                'selector' => '{{WRAPPER}} .fauth-password-toggle:hover, {{WRAPPER}} .fauth-password-toggle:focus',
            ] );
        }
        $this->end_controls_tab();

        $this->end_controls_tabs();

        $this->add_control( 'toggle_transition', [
            'label'     => esc_html__( 'Transition (ms)', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::SLIDER,
            'separator' => 'before',
            'range'     => [ 'px' => [ 'min' => 0, 'max' => 1000, 'step' => 50 ] ],
            'default'   => [ 'size' => 200 ],
            'selectors' => [ '{{WRAPPER}} .fauth-password-toggle' => 'transition-duration: {{SIZE}}ms;' ],
        ] );

        $this->end_controls_section();
    }

    /* --- Shared render helpers --- */

    protected function build_render_args( array $s ): array {
        // Fix #3 — redirect_to is now a URL control (returns ['url'=>..., 'is_external'=>...])
        $redirect_raw = $s['redirect_to'] ?? '';
        $redirect_url = is_array( $redirect_raw ) ? ( $redirect_raw['url'] ?? '' ) : $redirect_raw;

        // FIX (v1.4.16): Honour ?redirect_to= from the current URL.
        // The editor control sets a *default* destination. But when a user is
        // bounced to the login page because they tried to visit a protected page
        // (e.g. /dashboard/ → /log-in/?redirect_to=/dashboard/),
        // the URL parameter represents their actual intended destination and must
        // take priority over whatever the editor default is.
        $url_redirect = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification
            ? zenlogau_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
            : '';

        if ( '' !== $url_redirect ) {
            $redirect_url = $url_redirect;
        }

        return [
            'show_links'  => 'yes' === ( $s['show_links'] ?? 'yes' ),
            'redirect_to' => esc_url( $redirect_url ),
        ];
    }

    protected function maybe_print_script_data(): void {
        zenlogau_maybe_add_inline_script();
    }

    protected function render_form_title( array $s ): void {
        $title = $s['form_title_text'] ?? '';
        if ( '' === $title ) { return; }
        $tag = $s['form_title_tag'] ?? 'h3';
        $ok  = [ 'h1','h2','h3','h4','h5','h6','div','span','p' ];
        if ( ! in_array( $tag, $ok, true ) ) { $tag = 'h3'; }

        // FIX: The previous code called add_render_attribute() with the return
        // value of get_render_attribute_string() as the $key parameter. That
        // method returns a rendered HTML string (e.g. 'class="..." data-...')
        // but add_render_attribute() expects either an attribute name string or
        // an array. The rendered string was silently used as an attribute name,
        // producing malformed HTML like: <h3 class="..." class="..." data-...="...>
        //
        // Correct approach: add_inline_editing_attributes() stores attributes
        // under a render-attribute key matching the setting key ('form_title_text').
        // We add our CSS class to that same key, then output it. This merges
        // the class and the inline-editing data attributes into one element.
        //
        // Source: developers.elementor.com/docs/widgets/rendering-inline-editing/
        $this->add_render_attribute( 'form_title_text', 'class', 'fauth-form-title' );
        $this->add_inline_editing_attributes( 'form_title_text', 'none' );
        echo '<' . esc_attr( $tag ) . ' ' . $this->get_render_attribute_string( 'form_title_text' ) . '>' . esc_html( $title ) . '</' . esc_attr( $tag ) . '>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- get_render_attribute_string() is Elementor's escaping API; all other parts escaped above.
    }

    /**
     * Open the .fauth-form-wrap container. All width/max-width/alignment
     * Elementor controls target this element. Must be called BEFORE
     * render_form_title() and the form output.
     */
    protected function open_form_wrap(): void {
        echo '<div class="fauth-form-wrap">';
    }

    protected function close_form_wrap(): void {
        echo '</div><!-- /.fauth-form-wrap -->';
    }

    /**
     * Apply custom text overrides from Elementor settings to a ZENLOGAU_Form.
     *
     * @param ZENLOGAU_Form $form  The form object.
     * @param array     $map   Setting key => [ field_name, field_property ].
     * @param array     $s     Elementor settings.
     */
    protected function apply_text_overrides( $form, array $map, array $s ): void {
        foreach ( $map as $setting_key => $target ) {
            $val = $s[ $setting_key ] ?? '';
            if ( '' !== $val && $form ) {
                $form->set_field_option( $target[0], $target[1], $val );
            }
        }
    }

    protected function render_editor_placeholder( string $msg ): void {
        $is_editor = \Elementor\Plugin::$instance->editor
                     && \Elementor\Plugin::$instance->editor->is_edit_mode();
        if ( $is_editor ) {
            // Fix B — replaced hardcoded inline styles with CSS class (editor.css)
            echo '<div class="fauth-editor-preview-wrap fauth-editor-notice">'
                . esc_html( $msg ) . '</div>';
        }
    }

    /**
     * Make the form self-post to the current page URL.
     *
     * Without this, the form's action URL is the canonical ZENLOGAU page URL
     * (e.g. /lost-password/). If that page doesn't exist or the rewrite
     * rules haven't been flushed, the AJAX POST goes to a 404 URL. The
     * handler still processes it (template_redirect fires on 404s too),
     * but jQuery fails to parse the non-JSON 404 response.
     *
     * Self-posting to the current page is safe because the handler checks
     * $_POST['zenlogau_action'], not the URL.
     */
    protected function make_form_self_post( string $form_name ): void {
        $form = zenlogau()->get_form( $form_name );
        if ( ! $form ) {
            return;
        }
        // Use the current page's permalink as the form action.
        // This ensures the POST goes to a real page, not a potentially-404 URL.
        $current_url = get_permalink();
        if ( $current_url ) {
            $form->set_action_url( $current_url );
        }
    }

}


/* =======================================================================
 * 1. LOGIN
 * ===================================================================== */

class ZENLOGAU_Elementor_Login_Widget extends ZENLOGAU_Elementor_Base_Widget {

    public function get_name(): string  { return 'fauth-login'; }
    public function get_title(): string { return esc_html__( 'Login Form', 'zen-login-authentication' ); }
    public function get_icon(): string  { return 'eicon-lock-user'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Login Form', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();

        // --- Field Labels ---
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 — dynamic tags enabled on all text controls
        $this->add_control( 'label_username', [ 'label' => esc_html__( 'Username label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username or Email Address', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_password', [ 'label' => esc_html__( 'Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_remember', [ 'label' => esc_html__( 'Remember Me label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Remember Me', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'zenlogau_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_username', [ 'label' => esc_html__( 'Username placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_password', [ 'label' => esc_html__( 'Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        // --- Action Links (text + URL for each) ---
        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #3 + #6 — URL controls and dynamic tags
        $this->add_control( 'link_register_text', [ 'label' => esc_html__( 'Register link text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Register', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_register_url', [ 'label' => esc_html__( 'Register link URL', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'zen-login-authentication' ), 'label_block' => true ] );
        $this->add_control( 'link_lostpw_text', [ 'label' => esc_html__( 'Lost password link text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Lost your password?', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_lostpw_url', [ 'label' => esc_html__( 'Lost password link URL', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'zen-login-authentication' ), 'label_block' => true ] );


        $this->register_google_button_controls();
        $this->add_control( 'zenlogau_h_passkey', [ 'label' => esc_html__( 'Passkey', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'passkey_button_text', [ 'label' => esc_html__( 'Passkey button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Sign in with a passkey', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->register_redirect_controls();
        $this->end_controls_section();

        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
        $this->register_checkbox_style_controls(); // Fix H
        $this->register_google_button_style_controls();
        $this->register_passkey_button_style_controls();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        $s         = $this->get_settings_for_display();
        $is_editor = \Elementor\Plugin::$instance->editor
                     && \Elementor\Plugin::$instance->editor->is_edit_mode();

        // FIX: Show the form when reauth=1 is present, even if user is logged in.
        //
        // WordPress sets reauth=1 when it requires the user to re-enter their password
        // (e.g. before accessing the admin dashboard after a long idle period).
        // Without this exception, a logged-in user hitting /log-in/?reauth=1 sees a
        // blank page — the widget bails, nothing renders, and they cannot re-authenticate.
        //
        // Source: developer.wordpress.org/reference/functions/auth_redirect/
        //         The login page must render for reauth requests regardless of login state.
        $is_reauth = ! empty( $_GET['reauth'] ); // phpcs:ignore WordPress.Security.NonceVerification

        // Logged-in with no reauth: show nothing. In editor: always show.
        if ( is_user_logged_in() && ! $is_editor && ! $is_reauth ) {
            return;
        }

        $this->render_login_form( $s );
    }

    /**
     * Render the login form with all text/URL overrides applied.
     */
    private function render_login_form( array $s ): void {
        $form = zenlogau()->get_form( 'login' );
        if ( ! $form ) { return; }

        $this->make_form_self_post( 'login' );

        // Override field labels, placeholders, button text, and toggle labels
        $this->apply_text_overrides( $form, [
            'label_username'    => [ 'log',    'label' ],
            'label_password'    => [ 'pwd',    'label' ],
            'label_remember'    => [ 'rememberme', 'label' ],
            'button_text'       => [ 'submit', 'value' ],
            'placeholder_username' => [ 'log', 'placeholder' ],
            'placeholder_password' => [ 'pwd', 'placeholder' ],
            'toggle_show_text'  => [ 'pwd',    'toggle_show' ],
            'toggle_hide_text'  => [ 'pwd',    'toggle_hide' ],
        ], $s );

        // Override link texts and URLs
        // Fix #3 — URL controls return arrays: ['url' => ..., 'is_external' => ...]
        $link_reg_text = $s['link_register_text'] ?? '';
        $link_reg_url_raw = $s['link_register_url'] ?? '';
        $link_reg_url  = is_array( $link_reg_url_raw ) ? ( $link_reg_url_raw['url'] ?? '' ) : $link_reg_url_raw;
        $link_lp_text  = $s['link_lostpw_text'] ?? '';
        $link_lp_url_raw = $s['link_lostpw_url'] ?? '';
        $link_lp_url   = is_array( $link_lp_url_raw ) ? ( $link_lp_url_raw['url'] ?? '' ) : $link_lp_url_raw;

        if ( '' !== $link_reg_text || '' !== $link_reg_url || '' !== $link_lp_text || '' !== $link_lp_url ) {
            // Fix #7 — detect each link explicitly; never rely on negation of the other.
            $link_callback = function ( $links ) use ( $link_reg_text, $link_reg_url, $link_lp_text, $link_lp_url ) {
                $register_url  = zenlogau_get_action_url( 'register' );
                $lostpw_url    = zenlogau_get_action_url( 'lostpassword' );
                $new_links = [];
                foreach ( $links as $link ) {
                    $is_register = ( $link['url'] === $register_url );
                    $is_lostpw   = ( $link['url'] === $lostpw_url );

                    if ( $is_register ) {
                        if ( '' !== $link_reg_text ) { $link['label'] = $link_reg_text; }
                        if ( '' !== $link_reg_url )  { $link['url']   = $link_reg_url; }
                    }
                    if ( $is_lostpw ) {
                        if ( '' !== $link_lp_text ) { $link['label'] = $link_lp_text; }
                        if ( '' !== $link_lp_url )  { $link['url']   = $link_lp_url; }
                    }
                    $new_links[] = $link;
                }
                return $new_links;
            };
            add_filter( 'zenlogau_form_links_login', $link_callback, 99 );
        } else {
            $link_callback = null;
        }

        $google_cleanup  = $this->setup_google_button_overrides( $s );
        $passkey_cleanup = $this->setup_passkey_button_overrides( $s );

        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo zenlogau_render_form( 'login', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();

        $google_cleanup();
        $passkey_cleanup();

        /*
         * ELEMENTOR EDITOR FIX (v1.4.2):
         *
         * Elementor calls render() on every control change in the editor panel —
         * meaning render() can fire dozens of times per editing session.
         *
         * The previous code used add_filter() with an anonymous closure inside
         * render(), but never removed it. Each call stacked another callback on
         * the hook. After several interactions the accumulated closures processed
         * the links array repeatedly, producing duplicated or mangled link output
         * and occasionally triggering PHP "undefined index" notices that crashed
         * the Elementor preview iframe.
         *
         * Fix: store the callback reference, then remove_filter() immediately
         * after zenlogau_render_form() returns. The filter is now request-scoped
         * (added → used → removed within one render() call) and never leaks
         * across multiple editor refreshes.
         */
        if ( null !== $link_callback ) {
            remove_filter( 'zenlogau_form_links_login', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="fauth-form-wrap">';
        echo '<# var tag = settings.form_title_tag || "h3"; if ( settings.form_title_text ) { #>';
        echo '<{{ tag }} class="fauth-form-title">{{ settings.form_title_text }}</{{ tag }}>';
        echo '<# } #>';
        echo '<div class="fauth fauth-form fauth-form-login"><div class="fauth-inner-form">';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_username){#>{{settings.label_username}}<#}else{#>' . esc_html__( 'Username or Email', 'zen-login-authentication' ) . '<#}#></label><input type="text" class="fauth-field" placeholder="<# if(settings.placeholder_username){#>{{settings.placeholder_username}}<#}#>" disabled></p>';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_password){#>{{settings.label_password}}<#}else{#>' . esc_html__( 'Password', 'zen-login-authentication' ) . '<#}#></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_password){#>{{settings.placeholder_password}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__( 'Show', 'zen-login-authentication' ) . '<#}#></button></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button"><# if(settings.button_text){#>{{settings.button_text}}<#}else{#>' . esc_html__( 'Log In', 'zen-login-authentication' ) . '<#}#></button></p>';
        echo '</div>';
        echo '<# if ( "yes" === settings.show_links ) { #>';
        echo '<p class="fauth-links"><a href="#"><# if(settings.link_register_text){#>{{settings.link_register_text}}<#}else{#>' . esc_html__( 'Register', 'zen-login-authentication' ) . '<#}#></a> &bull; <a href="#"><# if(settings.link_lostpw_text){#>{{settings.link_lostpw_text}}<#}else{#>' . esc_html__( 'Lost your password?', 'zen-login-authentication' ) . '<#}#></a></p>';
        echo '<# } #></div>';
        // Editor preview of the alternative sign-in buttons. The front end injects
        // these via hooks that don't run in the JS preview, so they're mirrored
        // here (order: divider -> passkey -> Google) so they render and can be styled.
        // Icons are static inline SVG literals (not variables) so the echoed
        // string stays fully literal — no escaping wrapper needed, and the
        // case-sensitive viewBox is preserved (wp_kses() would lowercase it).
        echo '<div class="fauth-sso-divider" aria-hidden="true"><span>' . esc_html__( 'or', 'zen-login-authentication' ) . '</span></div>';
        echo '<div class="fauth fauth-passkey-login"><button type="button" class="fauth-button fauth-button-secondary fauth-passkey-signin"><svg class="fauth-passkey-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M18.9 7a8 8 0 0 1 1.1 5v1a6 6 0 0 0 .8 3"/><path d="M8 11a4 4 0 0 1 8 0v1a10 10 0 0 0 2 6"/><path d="M12 11v2a14 14 0 0 0 2.5 8"/><path d="M8 15a18 18 0 0 0 1.8 6"/><path d="M4.9 19a22 22 0 0 1 -.9 -7v-1a8 8 0 0 1 12 -6.95"/></svg><span><# if(settings.passkey_button_text){#>{{settings.passkey_button_text}}<#}else{#>' . esc_html__( 'Sign in with a passkey', 'zen-login-authentication' ) . '<#}#></span></button></div>';
        echo '<# if ( "yes" === settings.show_google_button ) { #>';
        echo '<div class="fauth-sso"><a class="fauth-google-btn" href="#" onclick="return false;"><svg class="fauth-google-icon" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" focusable="false"><path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92a8.78 8.78 0 0 0 2.68-6.62z"/><path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.32-1.58-5.03-3.71H.96v2.33A9 9 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.97 10.71A5.41 5.41 0 0 1 3.68 9c0-.59.1-1.17.28-1.71V4.96H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.04l3.01-2.33z"/><path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.59A9 9 0 0 0 .96 4.96l3.01 2.33C4.68 5.16 6.66 3.58 9 3.58z"/></svg><span><# if(settings.google_button_text){#>{{settings.google_button_text}}<#}else{#>' . esc_html__( 'Continue with Google', 'zen-login-authentication' ) . '<#}#></span></a></div>';
        echo '<# } #>';
        echo '</div><!-- /.fauth-form-wrap -->';
    }
}


/* =======================================================================
 * 2. REGISTER
 * ===================================================================== */

class ZENLOGAU_Elementor_Register_Widget extends ZENLOGAU_Elementor_Base_Widget {

    public function get_name(): string  { return 'fauth-register'; }
    public function get_title(): string { return esc_html__( 'Registration Form', 'zen-login-authentication' ); }
    public function get_icon(): string  { return 'eicon-person'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Registration Form', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 — dynamic tags; Fix #3 — URL controls
        $this->add_control( 'label_username', [ 'label' => esc_html__( 'Username label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_email', [ 'label' => esc_html__( 'Email label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Email Address', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_password', [ 'label' => esc_html__( 'Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_confirm_pw', [ 'label' => esc_html__( 'Confirm Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Confirm Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Register', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'zenlogau_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_username', [ 'label' => esc_html__( 'Username placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. johndoe', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_email', [ 'label' => esc_html__( 'Email placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_password', [ 'label' => esc_html__( 'Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_confirm_pw', [ 'label' => esc_html__( 'Confirm Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'link_login_text', [ 'label' => esc_html__( 'Log In link text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_login_url', [ 'label' => esc_html__( 'Log In link URL', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'zen-login-authentication' ), 'label_block' => true ] );
        $this->register_google_button_controls();
        $this->register_redirect_controls();
        $this->end_controls_section();
        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
        $this->register_strength_meter_style_controls(); // Fix M
        $this->register_google_button_style_controls();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        $s = $this->get_settings_for_display();
        if ( ! get_option( 'users_can_register' ) ) { $this->render_editor_placeholder( __( 'Registration disabled in Settings > General.', 'zen-login-authentication' ) ); return; }
        if ( is_user_logged_in() ) { return; }

        $link_callback = null; // Fix #4 — initialise before conditional to avoid undefined variable
        $form = zenlogau()->get_form( 'register' );
        if ( $form ) {
            $this->make_form_self_post( 'register' );
            $this->apply_text_overrides( $form, [
                'label_username'       => [ 'user_login', 'label' ],
                'label_email'          => [ 'user_email', 'label' ],
                'label_password'       => [ 'user_pass1', 'label' ],
                'label_confirm_pw'     => [ 'user_pass2', 'label' ],
                'button_text'          => [ 'submit',     'value' ],
                'placeholder_username' => [ 'user_login', 'placeholder' ],
                'placeholder_email'    => [ 'user_email', 'placeholder' ],
                'placeholder_password' => [ 'user_pass1', 'placeholder' ],
                'placeholder_confirm_pw' => [ 'user_pass2', 'placeholder' ],
                'toggle_show_text'     => [ 'user_pass1', 'toggle_show' ],
                'toggle_hide_text'     => [ 'user_pass1', 'toggle_hide' ],
                // Also set on confirm-password field
            ], $s );
            // Apply toggle text to confirm-password field too
            $toggle_show = $s['toggle_show_text'] ?? '';
            $toggle_hide = $s['toggle_hide_text'] ?? '';
            if ( '' !== $toggle_show ) { $form->set_field_option( 'user_pass2', 'toggle_show', $toggle_show ); }
            if ( '' !== $toggle_hide ) { $form->set_field_option( 'user_pass2', 'toggle_hide', $toggle_hide ); }
            $link_text = $s['link_login_text'] ?? '';
            // Fix #3 — URL control returns array
            $link_url_raw = $s['link_login_url'] ?? '';
            $link_url     = is_array( $link_url_raw ) ? ( $link_url_raw['url'] ?? '' ) : $link_url_raw;
            if ( '' !== $link_text || '' !== $link_url ) {
                $link_callback = function ( $links ) use ( $link_text, $link_url ) {
                    foreach ( $links as &$l ) {
                        if ( '' !== $link_text ) { $l['label'] = $link_text; }
                        if ( '' !== $link_url )  { $l['url']   = $link_url; }
                    }
                    return $links;
                };
                add_filter( 'zenlogau_form_links_register', $link_callback, 99 );
            } else {
                $link_callback = null;
            }
        }
        $google_cleanup = $this->setup_google_button_overrides( $s );
        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo zenlogau_render_form( 'register', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();
        $google_cleanup();
        // Remove filter immediately after render — see Login widget for full explanation.
        if ( ! empty( $link_callback ) ) {
            remove_filter( 'zenlogau_form_links_register', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="fauth-form-wrap">';
        echo '<# var tag = settings.form_title_tag || "h3"; if ( settings.form_title_text ) { #><{{ tag }} class="fauth-form-title">{{ settings.form_title_text }}</{{ tag }}><# } #>';
        echo '<div class="fauth fauth-form fauth-form-register"><div class="fauth-inner-form">';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_username){#>{{settings.label_username}}<#}else{#>' . esc_html__('Username','zen-login-authentication') . '<#}#></label><input type="text" class="fauth-field" placeholder="<# if(settings.placeholder_username){#>{{settings.placeholder_username}}<#}#>" disabled></p>';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_email){#>{{settings.label_email}}<#}else{#>' . esc_html__('Email Address','zen-login-authentication') . '<#}#></label><input type="email" class="fauth-field" placeholder="<# if(settings.placeholder_email){#>{{settings.placeholder_email}}<#}#>" disabled></p>';
        // Fix #1 — password fields + toggle button previews
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_password){#>{{settings.label_password}}<#}else{#>' . esc_html__('Password','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_password){#>{{settings.placeholder_password}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button></p>';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_confirm_pw){#>{{settings.label_confirm_pw}}<#}else{#>' . esc_html__('Confirm Password','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_confirm_pw){#>{{settings.placeholder_confirm_pw}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button"><# if(settings.button_text){#>{{settings.button_text}}<#}else{#>' . esc_html__('Register','zen-login-authentication') . '<#}#></button></p>';
        echo '</div><# if("yes"===settings.show_links){#><p class="fauth-links"><a href="#"><# if(settings.link_login_text){#>{{settings.link_login_text}}<#}else{#>' . esc_html__('Log In','zen-login-authentication') . '<#}#></a></p><#}#></div>';
        $this->google_button_content_template();
        echo '</div><!-- /.fauth-form-wrap -->';
    }
}


/* =======================================================================
 * 3. LOST PASSWORD
 * ===================================================================== */

class ZENLOGAU_Elementor_Lost_Password_Widget extends ZENLOGAU_Elementor_Base_Widget {

    public function get_name(): string  { return 'fauth-lost-password'; }
    public function get_title(): string { return esc_html__( 'Lost Password Form', 'zen-login-authentication' ); }
    public function get_icon(): string  { return 'eicon-email'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Lost Password Form', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 + #3
        $this->add_control( 'label_user_login', [ 'label' => esc_html__( 'Username / Email label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username or Email Address', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Get New Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'zenlogau_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_user_login', [ 'label' => esc_html__( 'Username / Email placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'link_login_text', [ 'label' => esc_html__( 'Log In link text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_login_url', [ 'label' => esc_html__( 'Log In link URL', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'zen-login-authentication' ), 'label_block' => true ] );
        $this->register_redirect_controls();
        $this->end_controls_section();
        $this->register_form_style_controls();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        if ( is_user_logged_in() ) { return; }
        $s = $this->get_settings_for_display();
        $link_callback = null; // Fix #4 — initialise before conditional
        $form = zenlogau()->get_form( 'lostpassword' );
        if ( $form ) {
            $this->make_form_self_post( 'lostpassword' );
            $this->apply_text_overrides( $form, [
                'label_user_login'     => [ 'user_login', 'label' ],
                'button_text'          => [ 'submit',     'value' ],
                'placeholder_user_login' => [ 'user_login', 'placeholder' ],
            ], $s );
            $link_text    = $s['link_login_text'] ?? '';
            // Fix #3 — URL control returns array
            $link_url_raw = $s['link_login_url'] ?? '';
            $link_url     = is_array( $link_url_raw ) ? ( $link_url_raw['url'] ?? '' ) : $link_url_raw;
            if ( '' !== $link_text || '' !== $link_url ) {
                $link_callback = function ( $links ) use ( $link_text, $link_url ) {
                    foreach ( $links as &$l ) {
                        if ( '' !== $link_text ) { $l['label'] = $link_text; }
                        if ( '' !== $link_url )  { $l['url']   = $link_url; }
                    }
                    return $links;
                };
                add_filter( 'zenlogau_form_links_lostpassword', $link_callback, 99 );
            } else {
                $link_callback = null;
            }
        }
        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo zenlogau_render_form( 'lostpassword', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();
        // Remove filter immediately after render — see Login widget for full explanation.
        if ( ! empty( $link_callback ) ) {
            remove_filter( 'zenlogau_form_links_lostpassword', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="fauth-form-wrap">';
        echo '<# var tag=settings.form_title_tag||"h3";if(settings.form_title_text){#><{{tag}} class="fauth-form-title">{{settings.form_title_text}}</{{tag}}><#}#>';
        echo '<div class="fauth fauth-form fauth-form-lostpassword"><div class="fauth-inner-form">';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_user_login){#>{{settings.label_user_login}}<#}else{#>' . esc_html__('Username or Email','zen-login-authentication') . '<#}#></label><input type="text" class="fauth-field" placeholder="<# if(settings.placeholder_user_login){#>{{settings.placeholder_user_login}}<#}#>" disabled></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button"><# if(settings.button_text){#>{{settings.button_text}}<#}else{#>' . esc_html__('Get New Password','zen-login-authentication') . '<#}#></button></p>';
        echo '</div><# if("yes"===settings.show_links){#><p class="fauth-links"><a href="#"><# if(settings.link_login_text){#>{{settings.link_login_text}}<#}else{#>' . esc_html__('Log In','zen-login-authentication') . '<#}#></a></p><#}#></div>';
        echo '</div><!-- /.fauth-form-wrap -->';
    }
}


/* =======================================================================
 * 4. RESET PASSWORD
 * ===================================================================== */

class ZENLOGAU_Elementor_Reset_Password_Widget extends ZENLOGAU_Elementor_Base_Widget {

    // Fix #10 — This widget reads $_GET['key'] and $_GET['login'] so it must never be cached.
    protected function is_dynamic_content(): bool { return true; }

    public function get_name(): string  { return 'fauth-reset-password'; }
    public function get_title(): string { return esc_html__( 'Reset Password Form', 'zen-login-authentication' ); }
    public function get_icon(): string  { return 'eicon-lock'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Reset Password Form', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6
        $this->add_control( 'label_new_pw', [ 'label' => esc_html__( 'New Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'New Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_confirm_pw', [ 'label' => esc_html__( 'Confirm Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Confirm New Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Reset Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'zenlogau_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_new_pw', [ 'label' => esc_html__( 'New Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_confirm_pw', [ 'label' => esc_html__( 'Confirm Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        $this->add_control( 'h_invalid', [ 'label' => esc_html__( 'Invalid / Expired Link State', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 + #3
        $this->add_control( 'invalid_key_message', [ 'label' => esc_html__( 'Error message', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXTAREA, 'default' => '', 'placeholder' => esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'zen-login-authentication' ), 'rows' => 3, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_request_text', [ 'label' => esc_html__( 'Link text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Request a new password reset link', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_request_url', [
            'label'       => esc_html__( 'Link URL (override)', 'zen-login-authentication' ),
            'type'        => \Elementor\Controls_Manager::URL, // Fix #3
            'dynamic'     => [ 'active' => true ],              // Fix #6
            'default'     => [ 'url' => '' ],
            'placeholder' => esc_html__( 'Leave empty to auto-detect from plugin settings', 'zen-login-authentication' ),
            'label_block' => true,
            'description' => esc_html__( 'Override the "request new link" URL. Leave empty to use your Lost Password page slug from Zen Login & Authentication settings.', 'zen-login-authentication' ),
        ] );

        $this->end_controls_section();
        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        $s = $this->get_settings_for_display();
        // FIX (v1.4.15): Extract to local vars BEFORE the is_string guard.
        // The previous code used `is_string( $_GET['key'] ?? '' )` which returns true
        // for the '' default, then re-accessed `$_GET['key']` in the true branch —
        // triggering "Undefined array key" when the param is absent.
        $raw_key  = $_GET['key']   ?? ''; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- type-checked and sanitized on the next line.
        $raw_login = $_GET['login'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- type-checked and sanitized on the next line.
        $rp_key   = is_string( $raw_key )   ? sanitize_text_field( wp_unslash( $raw_key ) )   : '';
        $rp_login = is_string( $raw_login ) ? sanitize_text_field( wp_unslash( $raw_login ) ) : '';
        $is_editor = \Elementor\Plugin::$instance->editor && \Elementor\Plugin::$instance->editor->is_edit_mode();

        // Resolve the "request new link" URL: custom override > auto-detected from settings
        // Fix #3 — URL control returns array
        $request_url_raw = $s['link_request_url'] ?? '';
        $request_url     = trim( is_array( $request_url_raw ) ? ( $request_url_raw['url'] ?? '' ) : $request_url_raw );
        if ( '' === $request_url ) {
            $request_url = zenlogau_get_action_url( 'lostpassword' );
        }

        if ( empty( $rp_key ) || empty( $rp_login ) ) {
            // No valid reset key in URL. In the editor this is ALWAYS the case.
            // Show the error message + link so the user can preview and customise the text.
            $msg       = ( $s['invalid_key_message'] ?? '' ) ?: __( 'This password reset link is invalid or has expired. Please request a new one.', 'zen-login-authentication' );
            $link_text = ( $s['link_request_text']   ?? '' ) ?: __( 'Request a new password reset link', 'zen-login-authentication' );

            $this->open_form_wrap();
            $this->render_form_title( $s );
            echo '<div class="fauth fauth-form fauth-form-resetpass">'
                . '<ul class="fauth-errors" role="alert"><li class="fauth-error">' . esc_html( $msg ) . '</li></ul>'
                . '<p class="fauth-links"><a href="' . esc_url( $request_url ) . '">'
                . esc_html( $link_text ) . '</a></p></div>';

            // In editor only: also show the form fields below so the user can style them
            if ( $is_editor ) {
                echo '<div class="fauth-editor-preview-wrap">';
                echo '<p class="fauth-editor-preview-label">' . esc_html__( 'Form preview (visible only in editor):', 'zen-login-authentication' ) . '</p>'; // Fix #11
                echo '<div class="fauth fauth-form fauth-form-resetpass fauth-form--preview"><div class="fauth-inner-form">';
                $lbl_new     = ( $s['label_new_pw']     ?? '' ) ?: esc_html__( 'New Password', 'zen-login-authentication' );
                $lbl_confirm = ( $s['label_confirm_pw'] ?? '' ) ?: esc_html__( 'Confirm New Password', 'zen-login-authentication' );
                $btn_text    = ( $s['button_text']       ?? '' ) ?: esc_html__( 'Reset Password', 'zen-login-authentication' );
                $ph_new     = ( $s['placeholder_new_pw']    ?? '' );
                $ph_confirm = ( $s['placeholder_confirm_pw'] ?? '' );
                $show_lbl   = ( $s['toggle_show_text'] ?? '' ) ?: esc_html__( 'Show', 'zen-login-authentication' );
                echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label">' . esc_html( $lbl_new ) . ' <span class="fauth-required">*</span></label>'
                    . '<input type="password" class="fauth-field"' . ( $ph_new ? ' placeholder="' . esc_attr( $ph_new ) . '"' : '' ) . ' disabled>'
                    . '<button type="button" class="fauth-password-toggle">' . esc_html( $show_lbl ) . '</button></p>';
                echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label">' . esc_html( $lbl_confirm ) . ' <span class="fauth-required">*</span></label>'
                    . '<input type="password" class="fauth-field"' . ( $ph_confirm ? ' placeholder="' . esc_attr( $ph_confirm ) . '"' : '' ) . ' disabled>'
                    . '<button type="button" class="fauth-password-toggle">' . esc_html( $show_lbl ) . '</button></p>';
                echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button">' . esc_html( $btn_text ) . '</button></p>';
                echo '</div></div></div>';
            }
            $this->close_form_wrap();
            return;
        }

        $form = zenlogau()->get_form( 'resetpass' );
        if ( $form ) {
            $this->make_form_self_post( 'resetpass' );
            $this->apply_text_overrides( $form, [
                'label_new_pw'         => [ 'pass1',  'label' ],
                'label_confirm_pw'     => [ 'pass2',  'label' ],
                'button_text'          => [ 'submit', 'value' ],
                'placeholder_new_pw'   => [ 'pass1',  'placeholder' ],
                'placeholder_confirm_pw' => [ 'pass2', 'placeholder' ],
                'toggle_show_text'     => [ 'pass1',  'toggle_show' ],
                'toggle_hide_text'     => [ 'pass1',  'toggle_hide' ],
            ], $s );
            $toggle_show = $s['toggle_show_text'] ?? '';
            $toggle_hide = $s['toggle_hide_text'] ?? '';
            if ( '' !== $toggle_show ) { $form->set_field_option( 'pass2', 'toggle_show', $toggle_show ); }
            if ( '' !== $toggle_hide ) { $form->set_field_option( 'pass2', 'toggle_hide', $toggle_hide ); }
        }
        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo zenlogau_render_form( 'resetpass', [ 'show_links' => false, 'redirect_to' => '' ] ); // phpcs:ignore
        $this->close_form_wrap();
    }

    protected function content_template(): void {
        // Backbone JS live preview — shows the invalid-key state (always in editor)
        // plus a form preview below it. All texts respond to control changes in real time.
        echo '<div class="fauth-form-wrap">';
        echo '<# var tag=settings.form_title_tag||"h3";if(settings.form_title_text){#><{{tag}} class="fauth-form-title">{{settings.form_title_text}}</{{tag}}><#}#>';

        // Error message + link
        echo '<div class="fauth fauth-form fauth-form-resetpass">';
        echo '<ul class="fauth-errors" role="alert"><li class="fauth-error">';
        echo '<# if(settings.invalid_key_message){#>{{settings.invalid_key_message}}<#}else{#>' . esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'zen-login-authentication' ) . '<#}#>';
        echo '</li></ul>';
        echo '<p class="fauth-links"><a href="#">';
        echo '<# if(settings.link_request_text){#>{{settings.link_request_text}}<#}else{#>' . esc_html__( 'Request a new password reset link', 'zen-login-authentication' ) . '<#}#>';
        echo '</a></p></div>';

        // Form preview
        echo '<div class="fauth-editor-preview-wrap">'; // Fix #11
        echo '<p class="fauth-editor-preview-label">' . esc_html__( 'Form preview (visible only in editor):', 'zen-login-authentication' ) . '</p>';
        echo '<div class="fauth fauth-form fauth-form-resetpass fauth-form--preview"><div class="fauth-inner-form">';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_new_pw){#>{{settings.label_new_pw}}<#}else{#>' . esc_html__('New Password','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_new_pw){#>{{settings.placeholder_new_pw}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button></p>';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_confirm_pw){#>{{settings.label_confirm_pw}}<#}else{#>' . esc_html__('Confirm New Password','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_confirm_pw){#>{{settings.placeholder_confirm_pw}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button"><# if(settings.button_text){#>{{settings.button_text}}<#}else{#>' . esc_html__('Reset Password','zen-login-authentication') . '<#}#></button></p>';
        echo '</div></div></div>';
        echo '</div><!-- /.fauth-form-wrap -->';
    }
}


/* =======================================================================
 * 5. ACCOUNT (edit profile)
 * ===================================================================== */

class ZENLOGAU_Elementor_Account_Widget extends ZENLOGAU_Elementor_Base_Widget {

    public function get_name(): string  { return 'fauth-account'; }
    public function get_title(): string { return esc_html__( 'Account Form', 'zen-login-authentication' ); }
    public function get_icon(): string  { return 'eicon-user-circle-o'; }
    public function get_keywords(): array { return [ 'account', 'profile', 'edit', 'auth', 'password', 'fauth' ]; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Account Form', 'zen-login-authentication' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();

        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'label_username', [ 'label' => esc_html__( 'Username label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'show_username', [
            'label'        => esc_html__( 'Show username field', 'zen-login-authentication' ),
            'type'         => \Elementor\Controls_Manager::SWITCHER,
            'label_on'     => esc_html__( 'Yes', 'zen-login-authentication' ),
            'label_off'    => esc_html__( 'No', 'zen-login-authentication' ),
            'return_value' => 'yes',
            'default'      => 'yes',
            'description'  => esc_html__( 'Read-only, like the wp-admin profile screen — usernames cannot be changed.', 'zen-login-authentication' ),
        ] );
        $this->add_control( 'label_first_name', [ 'label' => esc_html__( 'First Name label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'First Name', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_last_name', [ 'label' => esc_html__( 'Last Name label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Last Name', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_display_name', [ 'label' => esc_html__( 'Display Name label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Display name publicly as', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_email', [ 'label' => esc_html__( 'Email label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Email Address', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_password', [ 'label' => esc_html__( 'New Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'New Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_confirm_pw', [ 'label' => esc_html__( 'Confirm Password label', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Confirm New Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'password_hint', [ 'label' => esc_html__( 'Password hint text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Leave blank to keep your current password.', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Save Profile button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Save Profile', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'update_password_text', [ 'label' => esc_html__( 'Update Password button text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Update Password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'zenlogau_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_first_name', [ 'label' => esc_html__( 'First Name placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. John', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_last_name', [ 'label' => esc_html__( 'Last Name placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. Doe', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_email', [ 'label' => esc_html__( 'Email placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_password', [ 'label' => esc_html__( 'New Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Leave blank to keep current', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_confirm_pw', [ 'label' => esc_html__( 'Confirm Password placeholder', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Re-enter new password', 'zen-login-authentication' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        $this->add_control( 'show_links', [
            'label'        => esc_html__( 'Show Log Out link', 'zen-login-authentication' ),
            'type'         => \Elementor\Controls_Manager::SWITCHER,
            'label_on'     => esc_html__( 'Yes', 'zen-login-authentication' ),
            'label_off'    => esc_html__( 'No', 'zen-login-authentication' ),
            'return_value' => 'yes',
            'default'      => 'yes',
            'separator'    => 'before',
        ] );
        $this->end_controls_section();

        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
        $this->register_strength_meter_style_controls();
        $this->register_2fa_style_controls();
        $this->register_passkeys_style_controls();
        $this->register_account_cards_style_controls();
        $this->register_action_links_style_controls();
    }

    /**
     * Style controls for the new Account card headings, descriptions, and card
     * surfaces (Profile Information, Change Password, Session Management). Without
     * these the headings inherit the theme's heading colour with no way to change
     * them (Golden Rule #6).
     */
    protected function register_account_cards_style_controls(): void {
        $this->start_controls_section( 'section_account_cards_style', [
            'label' => esc_html__( 'Account Cards', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_control( 'card_title_heading', [ 'label' => esc_html__( 'Card Headings', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING ] );
        $this->add_control( 'card_title_color', [
            'label'     => esc_html__( 'Heading Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-card-title, {{WRAPPER}} .fauth-sessions-title' => 'color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'card_title_typography',
            'selector' => '{{WRAPPER}} .fauth-card-title, {{WRAPPER}} .fauth-sessions-title',
        ] );

        $this->add_control( 'card_sub_heading', [ 'label' => esc_html__( 'Card Descriptions', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'card_sub_color', [
            'label'     => esc_html__( 'Description Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-card-sub, {{WRAPPER}} .fauth-sessions-sub' => 'color: {{VALUE}};' ],
        ] );

        $this->add_control( 'card_surface_heading', [ 'label' => esc_html__( 'Card Surface', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'card_bg', [
            'label'     => esc_html__( 'Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-card, {{WRAPPER}} .fauth-sessions, {{WRAPPER}} .fauth-2fa, {{WRAPPER}} .fauth-passkeys' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [
            'name'     => 'card_border',
            'selector' => '{{WRAPPER}} .fauth-card, {{WRAPPER}} .fauth-sessions, {{WRAPPER}} .fauth-2fa, {{WRAPPER}} .fauth-passkeys',
        ] );

        $this->end_controls_section();
    }

    /**
     * Style controls for the account page's ACTION LINKS — the text links that
     * are NOT buttons: "Log Out" and "Sign out of all other devices" (Session
     * Management), "Turn off two-factor authentication" / "Cancel" (2FA), and
     * "Remove" (Passkeys). They all share the .fauth-link-button class, so one
     * section styles every action link in one discoverable place (Golden Rule
     * #6). The 2FA section keeps its own, more specific .fauth-2fa .fauth-link-button
     * controls, which naturally win inside the 2FA card when both are set.
     */
    protected function register_action_links_style_controls(): void {
        $this->start_controls_section( 'section_action_links_style', [
            'label' => esc_html__( 'Action Links', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        // Alignment of the Session Management links row (Log Out / Sign out others).
        $this->add_responsive_control( 'action_link_align', [
            'label'     => esc_html__( 'Session Links Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            'selectors' => [ '{{WRAPPER}} .fauth-sessions-links' => 'text-align: {{VALUE}};' ],
        ] );

        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'action_link_typography',
            'selector' => '{{WRAPPER}} .fauth-link-button',
        ] );

        $this->start_controls_tabs( 'action_link_tabs' );
        $this->start_controls_tab( 'action_link_tab_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'action_link_color', [
            'label'     => esc_html__( 'Text Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-link-button' => 'color: {{VALUE}};' ],
        ] );
        $this->end_controls_tab();
        $this->start_controls_tab( 'action_link_tab_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'action_link_color_h', [
            'label'     => esc_html__( 'Text Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-link-button:hover, {{WRAPPER}} .fauth-link-button:focus' => 'color: {{VALUE}};' ],
        ] );
        $this->end_controls_tab();
        $this->end_controls_tabs();

        $this->end_controls_section();
    }

    /**
     * Style controls for the Passkeys section shown on the account page once the
     * feature is enabled. Rendered on the front end (not this editor preview).
     * The "Add a passkey" button reuses .fauth-submit-button, so the Button
     * controls above already style it; these cover the passkey-specific parts.
     */
    protected function register_passkeys_style_controls(): void {
        $this->start_controls_section( 'section_passkeys_style', [
            'label' => esc_html__( 'Passkeys', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_responsive_control( 'pk_align', [
            'label'     => esc_html__( 'Heading Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            'selectors' => [ '{{WRAPPER}} .fauth-passkeys-title' => 'text-align: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'pk_body_align', [
            'label'     => esc_html__( 'Body Text Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            'selectors' => [
                '{{WRAPPER}} .fauth-passkeys-intro, {{WRAPPER}} .fauth-passkeys-note, {{WRAPPER}} .fauth-passkey-items, {{WRAPPER}} .fauth-passkeys-empty, {{WRAPPER}} .fauth-passkey-status' => 'text-align: {{VALUE}};',
            ],
        ] );

        $this->add_control( 'pk_bg', [
            'label'     => esc_html__( 'Section Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-passkeys' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'pk_padding', [
            'label'      => esc_html__( 'Section Padding', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-passkeys' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'pk_border', 'selector' => '{{WRAPPER}} .fauth-passkeys' ] );
        $this->add_responsive_control( 'pk_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-passkeys' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );

        $this->add_control( 'pk_title_heading', [ 'label' => esc_html__( 'Heading', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'pk_title_color', [
            'label'     => esc_html__( 'Heading Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-passkeys-title' => 'color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'pk_title_typography', 'selector' => '{{WRAPPER}} .fauth-passkeys-title' ] );

        $this->add_control( 'pk_text_heading', [ 'label' => esc_html__( 'Body Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'pk_text_color', [
            'label'     => esc_html__( 'Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [
                '{{WRAPPER}} .fauth-passkeys-intro, {{WRAPPER}} .fauth-passkeys-note, {{WRAPPER}} .fauth-passkey-name, {{WRAPPER}} .fauth-passkey-meta, {{WRAPPER}} .fauth-passkeys-empty, {{WRAPPER}} .fauth-passkey-status' => 'color: {{VALUE}};',
            ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'pk_text_typography', 'selector' => '{{WRAPPER}} .fauth-passkeys-intro, {{WRAPPER}} .fauth-passkey-name' ] );

        $this->add_control( 'pk_remove_heading', [ 'label' => esc_html__( 'Remove Link', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'pk_remove_color', [
            'label'     => esc_html__( 'Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-passkey-remove' => 'color: {{VALUE}};' ],
        ] );
        $this->add_control( 'pk_remove_color_h', [
            'label'     => esc_html__( 'Hover Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-passkey-remove:hover, {{WRAPPER}} .fauth-passkey-remove:focus' => 'color: {{VALUE}};' ],
        ] );

        $this->end_controls_section();
    }

    /**
     * Style controls for the Two-Factor Authentication section shown on the
     * account page once the feature is enabled. The section renders on the front
     * end (not in this editor preview), so changes apply on the live page. The
     * 2FA buttons reuse the .fauth-submit-button class, so the Button controls
     * above already style them; these controls cover the 2FA-specific parts.
     */
    protected function register_2fa_style_controls(): void {
        $this->start_controls_section( 'section_2fa_style', [
            'label' => esc_html__( 'Two-Factor Authentication', 'zen-login-authentication' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_responsive_control( 'tfa_align', [
            'label'     => esc_html__( 'Heading Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            // Scoped to the heading only, so aligning it never shifts the body text.
            'selectors' => [ '{{WRAPPER}} .fauth-2fa-title' => 'text-align: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'tfa_qr_align', [
            'label'                => esc_html__( 'QR Code Alignment', 'zen-login-authentication' ),
            'type'                 => \Elementor\Controls_Manager::CHOOSE,
            'options'              => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-h-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-h-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-h-align-right' ],
            ],
            'selectors_dictionary' => [
                'left'   => 'margin-left: 0; margin-right: auto;',
                'center' => 'margin-left: auto; margin-right: auto;',
                'right'  => 'margin-left: auto; margin-right: 0;',
            ],
            'selectors'            => [ '{{WRAPPER}} .fauth-2fa-qr' => '{{VALUE}}' ],
        ] );
        $this->add_responsive_control( 'tfa_body_align', [
            'label'     => esc_html__( 'Body Text Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            // The status line, enrolment steps, setup key, recovery-code box, and
            // "codes remaining" line — but NOT the heading, QR, buttons, or links,
            // which each have their own alignment control.
            'selectors' => [
                '{{WRAPPER}} .fauth-2fa-status, {{WRAPPER}} .fauth-2fa-steps, {{WRAPPER}} .fauth-2fa-key, {{WRAPPER}} .fauth-2fa-codes, {{WRAPPER}} .fauth-2fa-recovery-count' => 'text-align: {{VALUE}};',
            ],
        ] );

        $this->add_control( 'tfa_bg', [
            'label'     => esc_html__( 'Section Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-2fa' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'tfa_padding', [
            'label'      => esc_html__( 'Section Padding', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-2fa' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'tfa_border', 'selector' => '{{WRAPPER}} .fauth-2fa' ] );
        $this->add_responsive_control( 'tfa_radius', [
            'label'      => esc_html__( 'Border Radius', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .fauth-2fa' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );

        $this->add_control( 'tfa_title_heading', [ 'label' => esc_html__( 'Heading', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'tfa_title_color', [
            'label'     => esc_html__( 'Heading Color', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .fauth-2fa-title' => 'color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'tfa_title_typography', 'selector' => '{{WRAPPER}} .fauth-2fa-title' ] );

        $this->add_responsive_control( 'tfa_qr_size', [
            'label'      => esc_html__( 'QR Code Size', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px' ],
            'range'      => [ 'px' => [ 'min' => 120, 'max' => 320 ] ],
            'separator'  => 'before',
            'selectors'  => [ '{{WRAPPER}} .fauth-2fa-qr' => 'max-width: {{SIZE}}{{UNIT}};' ],
        ] );

        $this->add_control( 'tfa_codes_bg', [
            'label'     => esc_html__( 'Recovery Codes Background', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'separator' => 'before',
            'selectors' => [ '{{WRAPPER}} .fauth-2fa-codes' => 'background-color: {{VALUE}};' ],
        ] );

        /* ----- Buttons (Set up / Verify / Regenerate / Copy / Download).
         * Mirrors the main Button controls; left blank, the 2FA buttons simply
         * inherit those. Scoped to .fauth-2fa so it can override them here. ----- */
        $this->add_control( 'tfa_btn_heading', [ 'label' => esc_html__( 'Buttons', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'tfa_btn_typography', 'selector' => '{{WRAPPER}} .fauth-2fa .fauth-submit-button' ] );
        $this->add_responsive_control( 'tfa_btn_width', [
            'label'                => esc_html__( 'Width', 'zen-login-authentication' ),
            'type'                 => \Elementor\Controls_Manager::CHOOSE,
            'options'              => [
                'auto' => [ 'title' => esc_html__( 'Auto', 'zen-login-authentication' ),       'icon' => 'eicon-fit-to-screen' ],
                'full' => [ 'title' => esc_html__( 'Full Width', 'zen-login-authentication' ), 'icon' => 'eicon-h-align-stretch' ],
            ],
            'default'              => 'full',
            'selectors_dictionary' => [ 'auto' => 'width: auto;', 'full' => 'width: 100%;' ],
            'selectors'            => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button' => '{{VALUE}}' ],
        ] );
        $this->add_responsive_control( 'tfa_btn_padding', [ 'label' => esc_html__( 'Padding', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'tfa_btn_radius', [ 'label' => esc_html__( 'Border Radius', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );

        $this->start_controls_tabs( 'tfa_btn_tabs' );
        $this->start_controls_tab( 'tfa_btn_tab_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'tfa_btn_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_btn_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'tfa_btn_border', 'selector' => '{{WRAPPER}} .fauth-2fa .fauth-submit-button' ] );
        if ( class_exists( '\Elementor\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'tfa_btn_shadow', 'selector' => '{{WRAPPER}} .fauth-2fa .fauth-submit-button' ] );
        }
        $this->end_controls_tab();
        $this->start_controls_tab( 'tfa_btn_tab_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'tfa_btn_color_h', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button:hover,{{WRAPPER}} .fauth-2fa .fauth-submit-button:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_btn_bg_h', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button:hover,{{WRAPPER}} .fauth-2fa .fauth-submit-button:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_btn_border_color_h', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-submit-button:hover,{{WRAPPER}} .fauth-2fa .fauth-submit-button:focus' => 'border-color: {{VALUE}};' ] ] );
        if ( class_exists( '\Elementor\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'tfa_btn_shadow_h', 'selector' => '{{WRAPPER}} .fauth-2fa .fauth-submit-button:hover,{{WRAPPER}} .fauth-2fa .fauth-submit-button:focus' ] );
        }
        $this->end_controls_tab();
        $this->end_controls_tabs();

        /* ----- Text links — "Turn off" and "Cancel". ----- */
        $this->add_control( 'tfa_link_heading', [ 'label' => esc_html__( 'Text Links (Turn off, Cancel)', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_responsive_control( 'tfa_link_align', [
            'label'     => esc_html__( 'Alignment', 'zen-login-authentication' ),
            'type'      => \Elementor\Controls_Manager::CHOOSE,
            'options'   => [
                'left'   => [ 'title' => esc_html__( 'Left', 'zen-login-authentication' ),   'icon' => 'eicon-text-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'zen-login-authentication' ), 'icon' => 'eicon-text-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right', 'zen-login-authentication' ),  'icon' => 'eicon-text-align-right' ],
            ],
            'selectors' => [ '{{WRAPPER}} .fauth-2fa-cancel' => 'text-align: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'tfa_link_typography', 'selector' => '{{WRAPPER}} .fauth-2fa .fauth-link-button' ] );
        $this->add_control( 'tfa_link_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-link-button' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_link_color_h', [ 'label' => esc_html__( 'Text (Hover)', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa .fauth-link-button:hover,{{WRAPPER}} .fauth-2fa .fauth-link-button:focus' => 'color: {{VALUE}};' ] ] );

        /* ----- Recovery-code buttons ("Copy codes" / "Download"). Independent of
         * the main buttons above: laid out side by side with their own controls. ----- */
        $this->add_control( 'tfa_codebtn_heading', [ 'label' => esc_html__( 'Recovery Code Buttons', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_responsive_control( 'tfa_codebtn_gap', [
            'label'      => esc_html__( 'Gap', 'zen-login-authentication' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 40 ] ],
            'selectors'  => [ '{{WRAPPER}} .fauth-2fa-code-actions' => 'gap: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'tfa_codebtn_typography', 'selector' => '{{WRAPPER}} .fauth-2fa-code-btn' ] );
        $this->add_responsive_control( 'tfa_codebtn_padding', [ 'label' => esc_html__( 'Padding', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'tfa_codebtn_radius', [ 'label' => esc_html__( 'Border Radius', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->start_controls_tabs( 'tfa_codebtn_tabs' );
        $this->start_controls_tab( 'tfa_codebtn_tab_normal', [ 'label' => esc_html__( 'Normal', 'zen-login-authentication' ) ] );
        $this->add_control( 'tfa_codebtn_color', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_codebtn_bg', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'tfa_codebtn_border', 'selector' => '{{WRAPPER}} .fauth-2fa-code-btn' ] );
        if ( class_exists( '\Elementor\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'tfa_codebtn_shadow', 'selector' => '{{WRAPPER}} .fauth-2fa-code-btn' ] );
        }
        $this->end_controls_tab();
        $this->start_controls_tab( 'tfa_codebtn_tab_hover', [ 'label' => esc_html__( 'Hover', 'zen-login-authentication' ) ] );
        $this->add_control( 'tfa_codebtn_color_h', [ 'label' => esc_html__( 'Text', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn:hover,{{WRAPPER}} .fauth-2fa-code-btn:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_codebtn_bg_h', [ 'label' => esc_html__( 'Background', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn:hover,{{WRAPPER}} .fauth-2fa-code-btn:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'tfa_codebtn_border_color_h', [ 'label' => esc_html__( 'Border Color', 'zen-login-authentication' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .fauth-2fa-code-btn:hover,{{WRAPPER}} .fauth-2fa-code-btn:focus' => 'border-color: {{VALUE}};' ] ] );
        if ( class_exists( '\Elementor\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'tfa_codebtn_shadow_h', 'selector' => '{{WRAPPER}} .fauth-2fa-code-btn:hover,{{WRAPPER}} .fauth-2fa-code-btn:focus' ] );
        }
        $this->end_controls_tab();
        $this->end_controls_tabs();

        $this->end_controls_section();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        $s = $this->get_settings_for_display();

        // Guests never see the account form. The account page itself bounces
        // guests to the login form (template_redirect), so this only matters
        // when the widget is embedded on some other, public page. In the
        // Elementor editor the current user is always logged in, so the form
        // previews normally.
        if ( ! is_user_logged_in() ) {
            return;
        }

        $form = zenlogau()->get_form( 'account' );
        if ( ! $form ) {
            return;
        }

        $this->make_form_self_post( 'account' );

        // Optional username row removal must happen before render. Safe to
        // remove outright: the field is display-only (disabled, never submitted).
        if ( 'yes' !== ( $s['show_username'] ?? 'yes' ) ) {
            $form->remove_field( 'user_login' );
        }

        $this->apply_text_overrides( $form, [
            'label_username'           => [ 'user_login',   'label' ],
            'label_first_name'         => [ 'first_name',   'label' ],
            'label_last_name'          => [ 'last_name',    'label' ],
            'label_display_name'       => [ 'display_name', 'label' ],
            'label_email'              => [ 'user_email',   'label' ],
            'label_password'           => [ 'pass1',        'label' ],
            'label_confirm_pw'         => [ 'pass2',        'label' ],
            'password_hint'            => [ 'pass1',        'description' ],
            'button_text'              => [ 'submit_profile',  'value' ],
            'update_password_text'     => [ 'submit_password', 'value' ],
            'placeholder_first_name'   => [ 'first_name',   'placeholder' ],
            'placeholder_last_name'    => [ 'last_name',    'placeholder' ],
            'placeholder_email'        => [ 'user_email',   'placeholder' ],
            'placeholder_password'     => [ 'pass1',        'placeholder' ],
            'placeholder_confirm_pw'   => [ 'pass2',        'placeholder' ],
            'toggle_show_text'         => [ 'pass1',        'toggle_show' ],
            'toggle_hide_text'         => [ 'pass1',        'toggle_hide' ],
        ], $s );
        // Apply toggle text to the confirm-password field too (same pattern as Register).
        $toggle_show = $s['toggle_show_text'] ?? '';
        $toggle_hide = $s['toggle_hide_text'] ?? '';
        if ( '' !== $toggle_show ) { $form->set_field_option( 'pass2', 'toggle_show', $toggle_show ); }
        if ( '' !== $toggle_hide ) { $form->set_field_option( 'pass2', 'toggle_hide', $toggle_hide ); }

        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo zenlogau_render_form( 'account', [ 'show_links' => 'yes' === ( $s['show_links'] ?? 'yes' ), 'redirect_to' => '' ] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- form HTML is escaped field-by-field inside ZENLOGAU_Form::render().
        $this->close_form_wrap();
    }

    protected function content_template(): void {
        echo '<div class="fauth-form-wrap">';
        echo '<# var tag=settings.form_title_tag||"h3";if(settings.form_title_text){#><{{tag}} class="fauth-form-title">{{settings.form_title_text}}</{{tag}}><#}#>';
        echo '<div class="fauth fauth-form fauth-form-account"><div class="fauth-inner-form">';

        // ----- Profile Information card -----
        echo '<div class="fauth-card fauth-card--profile"><div class="fauth-card-head">';
        echo '<h3 class="fauth-card-title">' . esc_html__('Profile Information','zen-login-authentication') . '</h3>';
        echo '<p class="fauth-card-sub">' . esc_html__('Update your account profile information and email address.','zen-login-authentication') . '</p></div>';
        echo '<div class="fauth-card-body">';
        echo '<div class="fauth-row">';
        echo '<# if ( "yes" === settings.show_username ) { #><p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_username){#>{{settings.label_username}}<#}else{#>' . esc_html__('Username','zen-login-authentication') . '<#}#></label><input type="text" class="fauth-field" value="username" disabled></p><# } #>';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_email){#>{{settings.label_email}}<#}else{#>' . esc_html__('Email Address','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><input type="email" class="fauth-field" placeholder="<# if(settings.placeholder_email){#>{{settings.placeholder_email}}<#}#>" disabled></p>';
        echo '</div>';
        echo '<div class="fauth-row">';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_first_name){#>{{settings.label_first_name}}<#}else{#>' . esc_html__('First Name','zen-login-authentication') . '<#}#></label><input type="text" class="fauth-field" placeholder="<# if(settings.placeholder_first_name){#>{{settings.placeholder_first_name}}<#}#>" disabled></p>';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_last_name){#>{{settings.label_last_name}}<#}else{#>' . esc_html__('Last Name','zen-login-authentication') . '<#}#></label><input type="text" class="fauth-field" placeholder="<# if(settings.placeholder_last_name){#>{{settings.placeholder_last_name}}<#}#>" disabled></p>';
        echo '</div>';
        echo '<p class="fauth-field-wrap"><label class="fauth-label"><# if(settings.label_display_name){#>{{settings.label_display_name}}<#}else{#>' . esc_html__('Display name publicly as','zen-login-authentication') . '<#}#> <span class="fauth-required">*</span></label><select class="fauth-field fauth-select" disabled><option>' . esc_html__('Your Name','zen-login-authentication') . '</option></select></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button fauth-button-inline"><# if(settings.button_text){#>{{settings.button_text}}<#}else{#>' . esc_html__('Save Profile','zen-login-authentication') . '<#}#></button></p>';
        echo '</div></div>';

        // ----- Change Password card -----
        echo '<div class="fauth-card fauth-card--password"><div class="fauth-card-head">';
        echo '<h3 class="fauth-card-title">' . esc_html__('Change Password','zen-login-authentication') . '</h3>';
        echo '<p class="fauth-card-sub">' . esc_html__('Update your password to keep your account secure.','zen-login-authentication') . '</p></div>';
        echo '<div class="fauth-card-body">';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_password){#>{{settings.label_password}}<#}else{#>' . esc_html__('New Password','zen-login-authentication') . '<#}#></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_password){#>{{settings.placeholder_password}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button><span class="fauth-description"><# if(settings.password_hint){#>{{settings.password_hint}}<#}else{#>' . esc_html__('Leave blank to keep your current password.','zen-login-authentication') . '<#}#></span></p>';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label"><# if(settings.label_confirm_pw){#>{{settings.label_confirm_pw}}<#}else{#>' . esc_html__('Confirm New Password','zen-login-authentication') . '<#}#></label><input type="password" class="fauth-field" placeholder="<# if(settings.placeholder_confirm_pw){#>{{settings.placeholder_confirm_pw}}<#}#>" disabled><button type="button" class="fauth-password-toggle"><# if(settings.toggle_show_text){#>{{settings.toggle_show_text}}<#}else{#>' . esc_html__('Show','zen-login-authentication') . '<#}#></button></p>';
        echo '<p class="fauth-field-wrap fauth-field-wrap--password"><label class="fauth-label">' . esc_html__('Current Password','zen-login-authentication') . '</label><input type="password" class="fauth-field" disabled><button type="button" class="fauth-password-toggle">' . esc_html__('Show','zen-login-authentication') . '</button><span class="fauth-description">' . esc_html__('Required to change your email address or password.','zen-login-authentication') . '</span></p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button fauth-button-inline"><# if(settings.update_password_text){#>{{settings.update_password_text}}<#}else{#>' . esc_html__('Update Password','zen-login-authentication') . '<#}#></button></p>';
        echo '</div></div>';

        echo '</div>'; // close .fauth-inner-form

        // Editor previews of the dynamic Account sections. On the front end these
        // render server-side via hooks (they need a logged-in user / live state),
        // so they're shown statically here as cards so they appear in the editor.
        echo '<div class="fauth fauth-passkeys"><h3 class="fauth-passkeys-title">' . esc_html__('Passkeys','zen-login-authentication') . '</h3>';
        echo '<p class="fauth-passkeys-intro">' . esc_html__('Sign in without a password using your fingerprint, face, screen lock, or a security key.','zen-login-authentication') . '</p>';
        echo '<div class="fauth-passkeys-list"><ul class="fauth-passkey-items"><li class="fauth-passkey-item"><span class="fauth-passkey-name">' . esc_html__('My device','zen-login-authentication') . '</span> <button type="button" class="fauth-link-button fauth-passkey-remove">' . esc_html__('Remove','zen-login-authentication') . '</button></li></ul></div>';
        echo '<p class="fauth-passkeys-actions"><button type="button" class="fauth-button fauth-submit-button fauth-passkey-add">' . esc_html__('Add a passkey','zen-login-authentication') . '</button></p></div>';

        echo '<div class="fauth fauth-2fa"><h3 class="fauth-2fa-title">' . esc_html__('Two-Factor Authentication','zen-login-authentication') . '</h3>';
        echo '<p class="fauth-2fa-sub">' . esc_html__('Add an extra layer of security to your account.','zen-login-authentication') . '</p>';
        echo '<p class="fauth-2fa-status fauth-2fa-off">' . esc_html__('Two-factor authentication is off. Add a second step at login using an authenticator app.','zen-login-authentication') . '</p>';
        echo '<p class="fauth-submit"><button type="button" class="fauth-button fauth-submit-button">' . esc_html__('Set up two-factor authentication','zen-login-authentication') . '</button></p></div>';

        echo '<div class="fauth fauth-sessions"><h3 class="fauth-sessions-title">' . esc_html__('Session Management','zen-login-authentication') . '</h3>';
        echo '<p class="fauth-sessions-sub">' . esc_html__('These are the devices currently signed in to your account.','zen-login-authentication') . '</p>';
        echo '<ul class="fauth-session-items"><li class="fauth-session-item"><span class="fauth-session-device">' . esc_html__('Windows PC','zen-login-authentication') . ' <span class="fauth-session-current">' . esc_html__('this device','zen-login-authentication') . '</span></span><span class="fauth-session-meta">' . esc_html__('Chrome','zen-login-authentication') . ' &middot; 192.0.2.1</span></li></ul>';
        echo '<p class="fauth-links fauth-sessions-links"><a class="fauth-link-button fauth-session-action">' . esc_html__('Log Out','zen-login-authentication') . '</a><span class="fauth-links-sep" aria-hidden="true"> &middot; </span><a class="fauth-link-button fauth-session-action">' . esc_html__('Sign out of all other devices','zen-login-authentication') . '</a></p></div>';

        echo '</div>'; // close .fauth-form-account
        echo '</div><!-- /.fauth-form-wrap -->';
    }
}


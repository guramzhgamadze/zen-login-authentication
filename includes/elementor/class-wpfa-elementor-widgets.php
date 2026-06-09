<?php
/**
 * WP Frontend Auth – Elementor Widgets
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
 *  A  Triple-brace {{{ }}} in placeholder HTML attributes → double-brace {{ }}
 *  B  render_editor_placeholder() inline styles → CSS class
 *  C  class_exists() double-escaped backslash corrected
 *  D  bindPasswordToggle() + bindPasswordStrength() wired to element_ready lifecycle
 *  E  outline:none replaced with :focus/:focus-visible pair (WCAG 2.2)
 *  F  field_focus_shadow split into spread SLIDER + color controls
 *  G  Messages & Errors: added Group_Control_Typography for error + message text
 *  H  Remember Me: added dedicated style section (color, typography, gap)
 *  I  label_spacing, field_spacing, toggle_gap: added em/rem units
 *  J  Password toggle: flex layout via .wpfa-field-wrap--password (CSS + JS)
 *  K  Action Links: added text-decoration SELECT control
 *  L  CSS: description + strength meter colors tokenised as custom properties
 *  M  Password strength meter: full style section (typography + 4-state colours)
 *  N  toggle_margin_top removed; replaced with toggle_gap targeting flex gap
 *  O  h_placeholders, h_toggle renamed to wpfa_h_* to avoid cross-widget ID collision
 *
 * @package WP_Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* =======================================================================
 * Registration functions
 * ===================================================================== */

function wpfa_register_elementor_category( $elements_manager ): void {
    $elements_manager->add_category( 'wp-frontend-auth', [
        'title' => esc_html__( 'Frontend Auth', 'wp-frontend-auth' ),
        'icon'  => 'eicon-lock-user',
    ] );
}

function wpfa_register_elementor_widgets( $manager ): void {
    $manager->register( new WPFA_Elementor_Login_Widget() );
    $manager->register( new WPFA_Elementor_Register_Widget() );
    $manager->register( new WPFA_Elementor_Lost_Password_Widget() );
    $manager->register( new WPFA_Elementor_Reset_Password_Widget() );
}

/* =======================================================================
 * Abstract base
 * ===================================================================== */

abstract class WPFA_Elementor_Base_Widget extends \Elementor\Widget_Base {

    public function get_categories(): array  { return [ 'wp-frontend-auth' ]; }
    public function get_keywords(): array    { return [ 'login', 'auth', 'register', 'password', 'wpfa' ]; }
    public function get_style_depends(): array  { return [ 'wp-frontend-auth' ]; }
    public function get_script_depends(): array { return [ 'wp-frontend-auth' ]; }
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
            'label'       => esc_html__( 'Form Title', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Leave empty to hide', 'wp-frontend-auth' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ], // Fix #6
        ] );
        $this->add_control( 'form_title_tag', [
            'label'   => esc_html__( 'Title HTML Tag', 'wp-frontend-auth' ),
            'type'    => \Elementor\Controls_Manager::SELECT,
            'default' => 'h3',
            'options' => [ 'h1'=>'H1','h2'=>'H2','h3'=>'H3','h4'=>'H4','h5'=>'H5','h6'=>'H6','div'=>'div','span'=>'span','p'=>'p' ], // Fix #9 — matches renderer allowlist
            'condition' => [ 'form_title_text!' => '' ],
        ] );
    }

    protected function register_redirect_controls(): void {
        $this->add_control( 'redirect_to', [
            'label'       => esc_html__( 'Redirect URL', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::URL, // Fix #3
            'dynamic'     => [ 'active' => true ],              // Fix #6
            'default'     => [ 'url' => '' ],
            'placeholder' => esc_html__( 'Default: admin dashboard', 'wp-frontend-auth' ),
            'label_block' => true,
            'separator'   => 'before',
        ] );
        $this->add_control( 'show_links', [
            'label'        => esc_html__( 'Show action links', 'wp-frontend-auth' ),
            'type'         => \Elementor\Controls_Manager::SWITCHER,
            'label_on'     => esc_html__( 'Yes', 'wp-frontend-auth' ),
            'label_off'    => esc_html__( 'No', 'wp-frontend-auth' ),
            'return_value' => 'yes',
            'default'      => 'yes',
        ] );
    }

    /* --- Shared style controls --- */

    protected function register_form_style_controls(): void {
        // Form Container
        $this->start_controls_section( 'section_style_form', [
            'label' => esc_html__( 'Form Container', 'wp-frontend-auth' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_responsive_control( 'form_width', [
            'label'      => esc_html__( 'Width', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', '%', 'vw' ],
            'range'      => [
                'px' => [ 'min' => 200, 'max' => 1200, 'step' => 10 ],
                '%'  => [ 'min' => 10,  'max' => 100 ],
                'vw' => [ 'min' => 10,  'max' => 100 ],
            ],
            'selectors'  => [
                '{{WRAPPER}} .wpfa-form-wrap' => 'width: {{SIZE}}{{UNIT}};',
            ],
        ] );

        $this->add_responsive_control( 'form_max_width', [
            'label'      => esc_html__( 'Max Width', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', '%', 'vw' ],
            'range'      => [
                'px' => [ 'min' => 200, 'max' => 1200, 'step' => 10 ],
                '%'  => [ 'min' => 10,  'max' => 100 ],
                'vw' => [ 'min' => 10,  'max' => 100 ],
            ],
            'selectors'  => [
                '{{WRAPPER}} .wpfa-form-wrap' => 'max-width: {{SIZE}}{{UNIT}};',
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
            'label'       => esc_html__( 'Alignment', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::CHOOSE,
            'options'     => [
                'left'   => [ 'title' => esc_html__( 'Left',   'wp-frontend-auth' ), 'icon' => 'eicon-h-align-left' ],
                'center' => [ 'title' => esc_html__( 'Center', 'wp-frontend-auth' ), 'icon' => 'eicon-h-align-center' ],
                'right'  => [ 'title' => esc_html__( 'Right',  'wp-frontend-auth' ), 'icon' => 'eicon-h-align-right' ],
            ],
            'description' => esc_html__( 'Requires a Form Width value smaller than the column width to be visible.', 'wp-frontend-auth' ),
            'selectors_dictionary' => [
                'left'   => 'margin-left: 0; margin-right: auto;',
                'center' => 'margin-left: auto; margin-right: auto;',
                'right'  => 'margin-left: auto; margin-right: 0;',
            ],
            'selectors' => [
                '{{WRAPPER}} .wpfa-form-wrap' => '{{VALUE}}',
            ],
            'separator' => 'after',
        ] );

        $this->add_control( 'form_bg_color', [
            'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-form-wrap' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'form_padding', [
            'label' => esc_html__( 'Padding', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em', '%' ],
            'selectors' => [ '{{WRAPPER}} .wpfa-form-wrap' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'form_spacing_top', [
            'label' => esc_html__( 'Spacing Top', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range' => [ 'px' => [ 'min' => 0, 'max' => 100 ], 'em' => [ 'min' => 0, 'max' => 6 ] ],
            'selectors' => [ '{{WRAPPER}} .wpfa-form-wrap' => 'margin-top: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->add_responsive_control( 'form_spacing_bottom', [
            'label' => esc_html__( 'Spacing Bottom', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range' => [ 'px' => [ 'min' => 0, 'max' => 100 ], 'em' => [ 'min' => 0, 'max' => 6 ] ],
            'selectors' => [ '{{WRAPPER}} .wpfa-form-wrap' => 'margin-bottom: {{SIZE}}{{UNIT}};' ],
            'separator' => 'after',
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'form_border', 'selector' => '{{WRAPPER}} .wpfa-form-wrap' ] );
        $this->add_responsive_control( 'form_border_radius', [
            'label' => esc_html__( 'Border Radius', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors' => [ '{{WRAPPER}} .wpfa-form-wrap' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        // Fix #2 — class_exists() guard for safety across Elementor versions.
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'form_shadow', 'selector' => '{{WRAPPER}} .wpfa-form-wrap' ] );
        }
        $this->end_controls_section();

        // Title
        $this->start_controls_section( 'section_style_title', [
            'label' => esc_html__( 'Form Title', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
            'condition' => [ 'form_title_text!' => '' ],
        ] );
        $this->add_control( 'title_color', [ 'label' => esc_html__( 'Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-form-title' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'title_typography', 'selector' => '{{WRAPPER}} .wpfa-form-title' ] );
        $this->add_responsive_control( 'title_align', [
            'label' => esc_html__( 'Alignment', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::CHOOSE,
            'options' => [ 'left' => [ 'title' => 'Left', 'icon' => 'eicon-text-align-left' ], 'center' => [ 'title' => 'Center', 'icon' => 'eicon-text-align-center' ], 'right' => [ 'title' => 'Right', 'icon' => 'eicon-text-align-right' ] ],
            'selectors' => [ '{{WRAPPER}} .wpfa-form-title' => 'text-align: {{VALUE}};' ],
        ] );
        $this->add_responsive_control( 'title_spacing', [ 'label' => esc_html__( 'Bottom Spacing', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 60 ] ], 'selectors' => [ '{{WRAPPER}} .wpfa-form-title' => 'margin-bottom: {{SIZE}}{{UNIT}};' ] ] );
        $this->end_controls_section();

        // Labels
        $this->start_controls_section( 'section_style_labels', [
            'label' => esc_html__( 'Labels', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'label_color', [ 'label' => esc_html__( 'Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-label' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'label_typography', 'selector' => '{{WRAPPER}} .wpfa-label' ] );
        $this->add_responsive_control( 'label_spacing', [ 'label' => esc_html__( 'Bottom Spacing', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em', 'rem' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 30 ], 'em' => [ 'min' => 0, 'max' => 4 ], 'rem' => [ 'min' => 0, 'max' => 4 ] ], 'selectors' => [ '{{WRAPPER}} .wpfa-label' => 'margin-bottom: {{SIZE}}{{UNIT}};' ] ] ); // Fix I
        $this->end_controls_section();

        // Fields
        $this->start_controls_section( 'section_style_fields', [
            'label' => esc_html__( 'Input Fields', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'field_text_color', [ 'label' => esc_html__( 'Text Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-field' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'field_placeholder_color', [ 'label' => esc_html__( 'Placeholder Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-field::placeholder' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'field_bg', [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-field' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'field_typography', 'selector' => '{{WRAPPER}} .wpfa-field' ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'field_border', 'selector' => '{{WRAPPER}} .wpfa-field' ] );
        $this->add_responsive_control( 'field_border_radius', [ 'label' => esc_html__( 'Border Radius', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .wpfa-field' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'field_padding', [ 'label' => esc_html__( 'Padding', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .wpfa-field' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_control( 'heading_focus', [ 'label' => esc_html__( 'Focus State', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'field_focus_color', [ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-field:focus' => 'border-color: {{VALUE}};' ] ] );
        // Fix F — separated spread and color so both are independently adjustable
        $this->add_control( 'field_focus_shadow_spread', [
            'label'      => esc_html__( 'Glow Spread (px)', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 8, 'step' => 1 ] ],
            'default'    => [ 'size' => 1 ],
            'selectors'  => [],  // combined below via field_focus_shadow_color
        ] );
        $this->add_control( 'field_focus_shadow_color', [
            'label'       => esc_html__( 'Glow Color', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::COLOR,
            'description' => esc_html__( 'Set to transparent to remove the focus glow.', 'wp-frontend-auth' ),
            'selectors'   => [
                // Uses spread from field_focus_shadow_spread. Elementor doesn't
                // cross-reference controls in selectors, so the spread is read
                // at render time via a CSS custom property injected below.
                '{{WRAPPER}} .wpfa-field:focus' => 'box-shadow: 0 0 0 {{field_focus_shadow_spread.SIZE}}px {{VALUE}};',
            ],
        ] );
        $this->add_responsive_control( 'field_spacing', [ 'label' => esc_html__( 'Field Spacing', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'size_units' => [ 'px', 'em', 'rem' ], 'range' => [ 'px' => [ 'min' => 0, 'max' => 40 ], 'em' => [ 'min' => 0, 'max' => 5 ], 'rem' => [ 'min' => 0, 'max' => 5 ] ], 'selectors' => [ '{{WRAPPER}} .wpfa-field-wrap' => 'margin-bottom: {{SIZE}}{{UNIT}};' ], 'separator' => 'before' ] ); // Fix I
        $this->end_controls_section();

        // Button
        $this->start_controls_section( 'section_style_button', [
            'label' => esc_html__( 'Button', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'btn_typography', 'selector' => '{{WRAPPER}} .wpfa-submit-button' ] );
        // Fix #8 — CHOOSE + selectors_dictionary is the correct pattern for non-numeric CSS toggles.
        $this->add_responsive_control( 'btn_width', [
            'label'               => esc_html__( 'Width', 'wp-frontend-auth' ),
            'type'                => \Elementor\Controls_Manager::CHOOSE,
            'options'             => [
                'auto' => [ 'title' => esc_html__( 'Auto',       'wp-frontend-auth' ), 'icon' => 'eicon-fit-to-screen' ],
                'full' => [ 'title' => esc_html__( 'Full Width', 'wp-frontend-auth' ), 'icon' => 'eicon-h-align-stretch' ],
            ],
            'default'             => 'auto',
            'selectors_dictionary' => [
                'auto' => 'width: auto;',
                'full' => 'width: 100%;',
            ],
            'selectors'           => [
                '{{WRAPPER}} .wpfa-submit-button' => '{{VALUE}}',
            ],
        ] );
        $this->add_responsive_control( 'btn_padding', [ 'label' => esc_html__( 'Padding', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', 'em' ], 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->add_responsive_control( 'btn_radius', [ 'label' => esc_html__( 'Border Radius', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::DIMENSIONS, 'size_units' => [ 'px', '%' ], 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ] ] );
        $this->start_controls_tabs( 'btn_tabs' );
        $this->start_controls_tab( 'btn_normal', [ 'label' => esc_html__( 'Normal', 'wp-frontend-auth' ) ] );
        $this->add_control( 'btn_color', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_bg', [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button' => 'background-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [ 'name' => 'btn_border', 'selector' => '{{WRAPPER}} .wpfa-submit-button' ] );
        // Fix #2
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'btn_shadow', 'selector' => '{{WRAPPER}} .wpfa-submit-button' ] );
        }
        $this->end_controls_tab();
        $this->start_controls_tab( 'btn_hover', [ 'label' => esc_html__( 'Hover', 'wp-frontend-auth' ) ] );
        $this->add_control( 'btn_color_h', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button:hover,{{WRAPPER}} .wpfa-submit-button:focus' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_bg_h', [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button:hover,{{WRAPPER}} .wpfa-submit-button:focus' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'btn_border_h', [ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button:hover,{{WRAPPER}} .wpfa-submit-button:focus' => 'border-color: {{VALUE}};' ] ] );
        // Fix #2
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [ 'name' => 'btn_shadow_h', 'selector' => '{{WRAPPER}} .wpfa-submit-button:hover,{{WRAPPER}} .wpfa-submit-button:focus' ] );
        }
        $this->add_control( 'btn_transition', [ 'label' => esc_html__( 'Transition (ms)', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::SLIDER, 'range' => [ 'px' => [ 'min' => 0, 'max' => 1000, 'step' => 50 ] ], 'default' => [ 'size' => 200 ], 'selectors' => [ '{{WRAPPER}} .wpfa-submit-button' => 'transition-duration: {{SIZE}}ms;' ] ] );
        $this->end_controls_tab();
        $this->end_controls_tabs();
        $this->end_controls_section();

        // Links
        $this->start_controls_section( 'section_style_links', [
            'label' => esc_html__( 'Action Links', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'links_color', [ 'label' => esc_html__( 'Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-links a' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'links_color_h', [ 'label' => esc_html__( 'Hover', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-links a:hover' => 'color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'links_typography', 'selector' => '{{WRAPPER}} .wpfa-links' ] );
        $this->add_responsive_control( 'links_align', [ 'label' => esc_html__( 'Alignment', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::CHOOSE, 'options' => [ 'left' => [ 'title' => 'Left', 'icon' => 'eicon-text-align-left' ], 'center' => [ 'title' => 'Center', 'icon' => 'eicon-text-align-center' ], 'right' => [ 'title' => 'Right', 'icon' => 'eicon-text-align-right' ] ], 'selectors' => [ '{{WRAPPER}} .wpfa-links' => 'text-align: {{VALUE}};' ] ] );
        // Fix K — text-decoration control for links
        $this->add_control( 'links_text_decoration', [
            'label'               => esc_html__( 'Underline', 'wp-frontend-auth' ),
            'type'                => \Elementor\Controls_Manager::SELECT,
            'default'             => 'default',
            'options'             => [
                'default'   => esc_html__( 'Default (hover only)',  'wp-frontend-auth' ),
                'always'    => esc_html__( 'Always',                'wp-frontend-auth' ),
                'none'      => esc_html__( 'Never',                 'wp-frontend-auth' ),
            ],
            'selectors_dictionary' => [
                'always'  => 'text-decoration: underline;',
                'none'    => 'text-decoration: none;',
                'default' => '',
            ],
            'selectors' => [
                '{{WRAPPER}} .wpfa-links a'        => '{{VALUE}}',
                '{{WRAPPER}} .wpfa-links a:hover'  => '{{VALUE}}',
            ],
        ] );
        $this->end_controls_section();

        // Messages
        $this->start_controls_section( 'section_style_msg', [
            'label' => esc_html__( 'Messages & Errors', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        // Fix G — added Typography controls for error and message text
        $this->add_control( 'h_err', [ 'label' => esc_html__( 'Errors', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING ] );
        $this->add_control( 'err_color', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-error' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'err_bg', [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-error' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'err_border', [ 'label' => esc_html__( 'Border', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-error' => 'border-left-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'err_typography', 'selector' => '{{WRAPPER}} .wpfa-error' ] );
        $this->add_control( 'h_msg', [ 'label' => esc_html__( 'Success', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'msg_color', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-message' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'msg_bg', [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-message' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'msg_border', [ 'label' => esc_html__( 'Border', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} .wpfa-message' => 'border-left-color: {{VALUE}};' ] ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [ 'name' => 'msg_typography', 'selector' => '{{WRAPPER}} .wpfa-message' ] );
        $this->end_controls_section();
    }


    /* --- Shared password toggle content controls (Login / Register / Reset Password) --- */

    /**
     * Register Show/Hide label controls for the password-visibility toggle button.
     * Call from any widget that renders a password field.
     */
    protected function register_password_toggle_content_controls(): void {
        $this->add_control( 'wpfa_h_toggle', [
            'label'     => esc_html__( 'Password Toggle Button', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::HEADING,
            'separator' => 'before',
        ] );
        $this->add_control( 'toggle_show_text', [
            'label'       => esc_html__( 'Show label', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Show', 'wp-frontend-auth' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ],
            'description' => esc_html__( 'Text on the toggle button when the password is hidden.', 'wp-frontend-auth' ),
        ] );
        $this->add_control( 'toggle_hide_text', [
            'label'       => esc_html__( 'Hide label', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::TEXT,
            'default'     => '',
            'placeholder' => esc_html__( 'Hide', 'wp-frontend-auth' ),
            'label_block' => true,
            'dynamic'     => [ 'active' => true ],
            'description' => esc_html__( 'Text on the toggle button when the password is visible.', 'wp-frontend-auth' ),
        ] );
    }



    /**
     * Register style controls for the password strength meter.
     * Fix M — strength meter had no Elementor styling surface.
     * Called only from the Register widget (the only widget that renders the meter).
     */
    protected function register_strength_meter_style_controls(): void {
        $this->start_controls_section( 'section_style_strength', [
            'label' => esc_html__( 'Password Strength Meter', 'wp-frontend-auth' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'strength_typography',
            'selector' => '{{WRAPPER}} #pass-strength-result',
        ] );
        $this->add_responsive_control( 'strength_border_radius', [
            'label'      => esc_html__( 'Border Radius', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} #pass-strength-result' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        $this->add_control( 'h_str_short', [ 'label' => esc_html__( 'Too Short', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_short', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_short',    [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_short',[ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.short' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_bad', [ 'label' => esc_html__( 'Weak', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_bad', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_bad',    [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_bad',[ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.bad' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_good', [ 'label' => esc_html__( 'Good', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_good', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_good',    [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_good',[ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.good' => 'border-color: {{VALUE}};' ] ] );
        $this->add_control( 'h_str_strong', [ 'label' => esc_html__( 'Strong', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'strength_color_strong', [ 'label' => esc_html__( 'Text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_bg_strong',    [ 'label' => esc_html__( 'Background', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'background-color: {{VALUE}};' ] ] );
        $this->add_control( 'strength_border_strong',[ 'label' => esc_html__( 'Border Color', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::COLOR, 'selectors' => [ '{{WRAPPER}} #pass-strength-result.strong' => 'border-color: {{VALUE}};' ] ] );
        $this->end_controls_section();
    }

    /**
     * Register style controls for the "Remember Me" checkbox (Login widget only).
     * Fix H — checkbox label had no Elementor styling surface.
     */
    protected function register_checkbox_style_controls(): void {
        $this->start_controls_section( 'section_style_checkbox', [
            'label' => esc_html__( 'Remember Me', 'wp-frontend-auth' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );
        $this->add_control( 'checkbox_color', [
            'label'     => esc_html__( 'Label Color', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-checkbox-label' => 'color: {{VALUE}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'checkbox_typography',
            'selector' => '{{WRAPPER}} .wpfa-checkbox-label',
        ] );
        $this->add_responsive_control( 'checkbox_gap', [
            'label'      => esc_html__( 'Gap (checkbox ↔ label)', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 20 ] ],
            'selectors'  => [ '{{WRAPPER}} .wpfa-checkbox-label' => 'margin-left: {{SIZE}}{{UNIT}};' ],
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
            'label' => esc_html__( 'Password Toggle', 'wp-frontend-auth' ),
            'tab'   => \Elementor\Controls_Manager::TAB_STYLE,
        ] );

        $this->add_group_control( \Elementor\Group_Control_Typography::get_type(), [
            'name'     => 'toggle_typography',
            'selector' => '{{WRAPPER}} .wpfa-password-toggle',
        ] );
        $this->add_responsive_control( 'toggle_padding', [
            'label'      => esc_html__( 'Padding', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', 'em' ],
            'selectors'  => [ '{{WRAPPER}} .wpfa-password-toggle' => 'padding: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );
        // Fix N — negative range removed; Fix J means flex gap replaces margin-top
        // Renamed to toggle_gap and targets the flex gap between input and button
        $this->add_responsive_control( 'toggle_gap', [
            'label'      => esc_html__( 'Gap (input ↔ button)', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::SLIDER,
            'size_units' => [ 'px', 'em', 'rem' ],
            'range'      => [ 'px' => [ 'min' => 0, 'max' => 20 ], 'em' => [ 'min' => 0, 'max' => 2 ], 'rem' => [ 'min' => 0, 'max' => 2 ] ],
            'default'    => [ 'size' => 6, 'unit' => 'px' ],
            'selectors'  => [ '{{WRAPPER}} .wpfa-field-wrap--password' => 'gap: {{SIZE}}{{UNIT}};' ],
        ] );
        $this->add_group_control( \Elementor\Group_Control_Border::get_type(), [
            'name'     => 'toggle_border',
            'selector' => '{{WRAPPER}} .wpfa-password-toggle',
        ] );
        $this->add_responsive_control( 'toggle_border_radius', [
            'label'      => esc_html__( 'Border Radius', 'wp-frontend-auth' ),
            'type'       => \Elementor\Controls_Manager::DIMENSIONS,
            'size_units' => [ 'px', '%' ],
            'selectors'  => [ '{{WRAPPER}} .wpfa-password-toggle' => 'border-radius: {{TOP}}{{UNIT}} {{RIGHT}}{{UNIT}} {{BOTTOM}}{{UNIT}} {{LEFT}}{{UNIT}};' ],
        ] );

        // Normal / Hover tabs
        $this->start_controls_tabs( 'toggle_tabs' );

        $this->start_controls_tab( 'toggle_tab_normal', [ 'label' => esc_html__( 'Normal', 'wp-frontend-auth' ) ] );
        $this->add_control( 'toggle_color', [
            'label'     => esc_html__( 'Text Color', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle' => 'color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_bg', [
            'label'     => esc_html__( 'Background', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle' => 'background-color: {{VALUE}};' ],
        ] );
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [
                'name'     => 'toggle_shadow',
                'selector' => '{{WRAPPER}} .wpfa-password-toggle',
            ] );
        }
        $this->end_controls_tab();

        $this->start_controls_tab( 'toggle_tab_hover', [ 'label' => esc_html__( 'Hover', 'wp-frontend-auth' ) ] );
        $this->add_control( 'toggle_color_h', [
            'label'     => esc_html__( 'Text Color', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle:hover, {{WRAPPER}} .wpfa-password-toggle:focus' => 'color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_bg_h', [
            'label'     => esc_html__( 'Background', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle:hover, {{WRAPPER}} .wpfa-password-toggle:focus' => 'background-color: {{VALUE}};' ],
        ] );
        $this->add_control( 'toggle_border_color_h', [
            'label'     => esc_html__( 'Border Color', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::COLOR,
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle:hover, {{WRAPPER}} .wpfa-password-toggle:focus' => 'border-color: {{VALUE}};' ],
        ] );
        if ( class_exists( '\\Elementor\\Group_Control_Box_Shadow' ) ) {
            $this->add_group_control( \Elementor\Group_Control_Box_Shadow::get_type(), [
                'name'     => 'toggle_shadow_h',
                'selector' => '{{WRAPPER}} .wpfa-password-toggle:hover, {{WRAPPER}} .wpfa-password-toggle:focus',
            ] );
        }
        $this->end_controls_tab();

        $this->end_controls_tabs();

        $this->add_control( 'toggle_transition', [
            'label'     => esc_html__( 'Transition (ms)', 'wp-frontend-auth' ),
            'type'      => \Elementor\Controls_Manager::SLIDER,
            'separator' => 'before',
            'range'     => [ 'px' => [ 'min' => 0, 'max' => 1000, 'step' => 50 ] ],
            'default'   => [ 'size' => 200 ],
            'selectors' => [ '{{WRAPPER}} .wpfa-password-toggle' => 'transition-duration: {{SIZE}}ms;' ],
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
            ? wpfa_validate_redirect( wp_unslash( $_GET['redirect_to'] ) ) // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
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
        wpfa_maybe_add_inline_script();
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
        $this->add_render_attribute( 'form_title_text', 'class', 'wpfa-form-title' );
        $this->add_inline_editing_attributes( 'form_title_text', 'none' );
        echo '<' . esc_attr( $tag ) . ' ' . $this->get_render_attribute_string( 'form_title_text' ) . '>' . esc_html( $title ) . '</' . esc_attr( $tag ) . '>';
    }

    /**
     * Open the .wpfa-form-wrap container. All width/max-width/alignment
     * Elementor controls target this element. Must be called BEFORE
     * render_form_title() and the form output.
     */
    protected function open_form_wrap(): void {
        echo '<div class="wpfa-form-wrap">';
    }

    protected function close_form_wrap(): void {
        echo '</div><!-- /.wpfa-form-wrap -->';
    }

    /**
     * Apply custom text overrides from Elementor settings to a WPFA_Form.
     *
     * @param WPFA_Form $form  The form object.
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
            echo '<div class="wpfa-editor-preview-wrap wpfa-editor-notice">'
                . esc_html( $msg ) . '</div>';
        }
    }

    /**
     * Make the form self-post to the current page URL.
     *
     * Without this, the form's action URL is the canonical WPFA page URL
     * (e.g. /lost-password/). If that page doesn't exist or the rewrite
     * rules haven't been flushed, the AJAX POST goes to a 404 URL. The
     * handler still processes it (template_redirect fires on 404s too),
     * but jQuery fails to parse the non-JSON 404 response.
     *
     * Self-posting to the current page is safe because the handler checks
     * $_POST['wpfa_action'], not the URL.
     */
    protected function make_form_self_post( string $form_name ): void {
        $form = wpfa()->get_form( $form_name );
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

class WPFA_Elementor_Login_Widget extends WPFA_Elementor_Base_Widget {

    public function get_name(): string  { return 'wpfa-login'; }
    public function get_title(): string { return esc_html__( 'Login Form', 'wp-frontend-auth' ); }
    public function get_icon(): string  { return 'eicon-lock-user'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Login Form', 'wp-frontend-auth' ),
            'tab'   => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();

        // --- Field Labels ---
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 — dynamic tags enabled on all text controls
        $this->add_control( 'label_username', [ 'label' => esc_html__( 'Username label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username or Email Address', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_password', [ 'label' => esc_html__( 'Password label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_remember', [ 'label' => esc_html__( 'Remember Me label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Remember Me', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'wpfa_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_username', [ 'label' => esc_html__( 'Username placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_password', [ 'label' => esc_html__( 'Password placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        // --- Action Links (text + URL for each) ---
        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #3 + #6 — URL controls and dynamic tags
        $this->add_control( 'link_register_text', [ 'label' => esc_html__( 'Register link text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Register', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_register_url', [ 'label' => esc_html__( 'Register link URL', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'wp-frontend-auth' ), 'label_block' => true ] );
        $this->add_control( 'link_lostpw_text', [ 'label' => esc_html__( 'Lost password link text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Lost your password?', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_lostpw_url', [ 'label' => esc_html__( 'Lost password link URL', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'wp-frontend-auth' ), 'label_block' => true ] );


        $this->register_redirect_controls();
        $this->end_controls_section();

        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
        $this->register_checkbox_style_controls(); // Fix H
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
        $form = wpfa()->get_form( 'login' );
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
                $register_url  = wpfa_get_action_url( 'register' );
                $lostpw_url    = wpfa_get_action_url( 'lostpassword' );
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
            add_filter( 'wpfa_form_links_login', $link_callback, 99 );
        } else {
            $link_callback = null;
        }

        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo wpfa_render_form( 'login', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();

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
         * after wpfa_render_form() returns. The filter is now request-scoped
         * (added → used → removed within one render() call) and never leaks
         * across multiple editor refreshes.
         */
        if ( null !== $link_callback ) {
            remove_filter( 'wpfa_form_links_login', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="wpfa-form-wrap">';
        echo '<# var tag = settings.form_title_tag || "h3"; if ( settings.form_title_text ) { #>';
        echo '<{{{ tag }}} class="wpfa-form-title">{{{ settings.form_title_text }}}</{{{ tag }}}>';
        echo '<# } #>';
        echo '<div class="wpfa wpfa-form wpfa-form-login"><div class="wpfa-inner-form">';
        echo '<p class="wpfa-field-wrap"><label class="wpfa-label"><# if(settings.label_username){#>{{{settings.label_username}}}<#}else{#>' . esc_html__( 'Username or Email', 'wp-frontend-auth' ) . '<#}#></label><input type="text" class="wpfa-field" placeholder="<# if(settings.placeholder_username){#>{{settings.placeholder_username}}<#}#>" disabled></p>';
        echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label"><# if(settings.label_password){#>{{{settings.label_password}}}<#}else{#>' . esc_html__( 'Password', 'wp-frontend-auth' ) . '<#}#></label><input type="password" class="wpfa-field" placeholder="<# if(settings.placeholder_password){#>{{settings.placeholder_password}}<#}#>" disabled><button type="button" class="wpfa-password-toggle"><# if(settings.toggle_show_text){#>{{{settings.toggle_show_text}}}<#}else{#>' . esc_html__( 'Show', 'wp-frontend-auth' ) . '<#}#></button></p>';
        echo '<p class="wpfa-submit"><button type="button" class="wpfa-button wpfa-submit-button"><# if(settings.button_text){#>{{{settings.button_text}}}<#}else{#>' . esc_html__( 'Log In', 'wp-frontend-auth' ) . '<#}#></button></p>';
        echo '</div>';
        echo '<# if ( "yes" === settings.show_links ) { #>';
        echo '<p class="wpfa-links"><a href="#"><# if(settings.link_register_text){#>{{{settings.link_register_text}}}<#}else{#>' . esc_html__( 'Register', 'wp-frontend-auth' ) . '<#}#></a> &bull; <a href="#"><# if(settings.link_lostpw_text){#>{{{settings.link_lostpw_text}}}<#}else{#>' . esc_html__( 'Lost your password?', 'wp-frontend-auth' ) . '<#}#></a></p>';
        echo '<# } #></div>';
        echo '</div><!-- /.wpfa-form-wrap -->';
    }
}


/* =======================================================================
 * 2. REGISTER
 * ===================================================================== */

class WPFA_Elementor_Register_Widget extends WPFA_Elementor_Base_Widget {

    public function get_name(): string  { return 'wpfa-register'; }
    public function get_title(): string { return esc_html__( 'Registration Form', 'wp-frontend-auth' ); }
    public function get_icon(): string  { return 'eicon-person'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Registration Form', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 — dynamic tags; Fix #3 — URL controls
        $this->add_control( 'label_username', [ 'label' => esc_html__( 'Username label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_email', [ 'label' => esc_html__( 'Email label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Email Address', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_password', [ 'label' => esc_html__( 'Password label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_confirm_pw', [ 'label' => esc_html__( 'Confirm Password label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Confirm Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Register', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'wpfa_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_username', [ 'label' => esc_html__( 'Username placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. johndoe', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_email', [ 'label' => esc_html__( 'Email placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_password', [ 'label' => esc_html__( 'Password placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_confirm_pw', [ 'label' => esc_html__( 'Confirm Password placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'link_login_text', [ 'label' => esc_html__( 'Log In link text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_login_url', [ 'label' => esc_html__( 'Log In link URL', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'wp-frontend-auth' ), 'label_block' => true ] );
        $this->register_redirect_controls();
        $this->end_controls_section();
        $this->register_form_style_controls();
        $this->register_password_toggle_style_controls();
        $this->register_strength_meter_style_controls(); // Fix M
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        $s = $this->get_settings_for_display();
        if ( ! get_option( 'users_can_register' ) ) { $this->render_editor_placeholder( __( 'Registration disabled in Settings > General.', 'wp-frontend-auth' ) ); return; }
        if ( is_user_logged_in() ) { return; }

        $link_callback = null; // Fix #4 — initialise before conditional to avoid undefined variable
        $form = wpfa()->get_form( 'register' );
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
                add_filter( 'wpfa_form_links_register', $link_callback, 99 );
            } else {
                $link_callback = null;
            }
        }
        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo wpfa_render_form( 'register', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();
        // Remove filter immediately after render — see Login widget for full explanation.
        if ( ! empty( $link_callback ) ) {
            remove_filter( 'wpfa_form_links_register', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="wpfa-form-wrap">';
        echo '<# var tag = settings.form_title_tag || "h3"; if ( settings.form_title_text ) { #><{{{ tag }}} class="wpfa-form-title">{{{ settings.form_title_text }}}</{{{ tag }}}><# } #>';
        echo '<div class="wpfa wpfa-form wpfa-form-register"><div class="wpfa-inner-form">';
        echo '<p class="wpfa-field-wrap"><label class="wpfa-label"><# if(settings.label_username){#>{{{settings.label_username}}}<#}else{#>' . esc_html__('Username','wp-frontend-auth') . '<#}#></label><input type="text" class="wpfa-field" placeholder="<# if(settings.placeholder_username){#>{{settings.placeholder_username}}<#}#>" disabled></p>';
        echo '<p class="wpfa-field-wrap"><label class="wpfa-label"><# if(settings.label_email){#>{{{settings.label_email}}}<#}else{#>' . esc_html__('Email Address','wp-frontend-auth') . '<#}#></label><input type="email" class="wpfa-field" placeholder="<# if(settings.placeholder_email){#>{{settings.placeholder_email}}<#}#>" disabled></p>';
        // Fix #1 — password fields + toggle button previews
        echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label"><# if(settings.label_password){#>{{{settings.label_password}}}<#}else{#>' . esc_html__('Password','wp-frontend-auth') . '<#}#> <span class="wpfa-required">*</span></label><input type="password" class="wpfa-field" placeholder="<# if(settings.placeholder_password){#>{{settings.placeholder_password}}<#}#>" disabled><button type="button" class="wpfa-password-toggle"><# if(settings.toggle_show_text){#>{{{settings.toggle_show_text}}}<#}else{#>' . esc_html__('Show','wp-frontend-auth') . '<#}#></button></p>';
        echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label"><# if(settings.label_confirm_pw){#>{{{settings.label_confirm_pw}}}<#}else{#>' . esc_html__('Confirm Password','wp-frontend-auth') . '<#}#> <span class="wpfa-required">*</span></label><input type="password" class="wpfa-field" placeholder="<# if(settings.placeholder_confirm_pw){#>{{settings.placeholder_confirm_pw}}<#}#>" disabled><button type="button" class="wpfa-password-toggle"><# if(settings.toggle_show_text){#>{{{settings.toggle_show_text}}}<#}else{#>' . esc_html__('Show','wp-frontend-auth') . '<#}#></button></p>';
        echo '<p class="wpfa-submit"><button type="button" class="wpfa-button wpfa-submit-button"><# if(settings.button_text){#>{{{settings.button_text}}}<#}else{#>' . esc_html__('Register','wp-frontend-auth') . '<#}#></button></p>';
        echo '</div><# if("yes"===settings.show_links){#><p class="wpfa-links"><a href="#"><# if(settings.link_login_text){#>{{{settings.link_login_text}}}<#}else{#>' . esc_html__('Log In','wp-frontend-auth') . '<#}#></a></p><#}#></div>';
        echo '</div><!-- /.wpfa-form-wrap -->';
    }
}


/* =======================================================================
 * 3. LOST PASSWORD
 * ===================================================================== */

class WPFA_Elementor_Lost_Password_Widget extends WPFA_Elementor_Base_Widget {

    public function get_name(): string  { return 'wpfa-lost-password'; }
    public function get_title(): string { return esc_html__( 'Lost Password Form', 'wp-frontend-auth' ); }
    public function get_icon(): string  { return 'eicon-email'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Lost Password Form', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 + #3
        $this->add_control( 'label_user_login', [ 'label' => esc_html__( 'Username / Email label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Username or Email Address', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Get New Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'wpfa_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_user_login', [ 'label' => esc_html__( 'Username / Email placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. your@email.com', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        $this->add_control( 'h_links', [ 'label' => esc_html__( 'Action Links', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'link_login_text', [ 'label' => esc_html__( 'Log In link text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Log In', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_login_url', [ 'label' => esc_html__( 'Log In link URL', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::URL, 'dynamic' => [ 'active' => true ], 'default' => [ 'url' => '' ], 'placeholder' => esc_html__( 'Leave empty for auto-detect', 'wp-frontend-auth' ), 'label_block' => true ] );
        $this->register_redirect_controls();
        $this->end_controls_section();
        $this->register_form_style_controls();
    }

    protected function render(): void {
        $this->maybe_print_script_data();
        if ( is_user_logged_in() ) { return; }
        $s = $this->get_settings_for_display();
        $link_callback = null; // Fix #4 — initialise before conditional
        $form = wpfa()->get_form( 'lostpassword' );
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
                add_filter( 'wpfa_form_links_lostpassword', $link_callback, 99 );
            } else {
                $link_callback = null;
            }
        }
        $this->open_form_wrap();
        $this->render_form_title( $s );
        echo wpfa_render_form( 'lostpassword', $this->build_render_args( $s ) ); // phpcs:ignore
        $this->close_form_wrap();
        // Remove filter immediately after render — see Login widget for full explanation.
        if ( ! empty( $link_callback ) ) {
            remove_filter( 'wpfa_form_links_lostpassword', $link_callback, 99 );
        }
    }

    protected function content_template(): void {
        echo '<div class="wpfa-form-wrap">';
        echo '<# var tag=settings.form_title_tag||"h3";if(settings.form_title_text){#><{{{tag}}} class="wpfa-form-title">{{{settings.form_title_text}}}</{{{tag}}}><#}#>';
        echo '<div class="wpfa wpfa-form wpfa-form-lostpassword"><div class="wpfa-inner-form">';
        echo '<p class="wpfa-field-wrap"><label class="wpfa-label"><# if(settings.label_user_login){#>{{{settings.label_user_login}}}<#}else{#>' . esc_html__('Username or Email','wp-frontend-auth') . '<#}#></label><input type="text" class="wpfa-field" placeholder="<# if(settings.placeholder_user_login){#>{{settings.placeholder_user_login}}<#}#>" disabled></p>';
        echo '<p class="wpfa-submit"><button type="button" class="wpfa-button wpfa-submit-button"><# if(settings.button_text){#>{{{settings.button_text}}}<#}else{#>' . esc_html__('Get New Password','wp-frontend-auth') . '<#}#></button></p>';
        echo '</div><# if("yes"===settings.show_links){#><p class="wpfa-links"><a href="#"><# if(settings.link_login_text){#>{{{settings.link_login_text}}}<#}else{#>' . esc_html__('Log In','wp-frontend-auth') . '<#}#></a></p><#}#></div>';
        echo '</div><!-- /.wpfa-form-wrap -->';
    }
}


/* =======================================================================
 * 4. RESET PASSWORD
 * ===================================================================== */

class WPFA_Elementor_Reset_Password_Widget extends WPFA_Elementor_Base_Widget {

    // Fix #10 — This widget reads $_GET['key'] and $_GET['login'] so it must never be cached.
    protected function is_dynamic_content(): bool { return true; }

    public function get_name(): string  { return 'wpfa-reset-password'; }
    public function get_title(): string { return esc_html__( 'Reset Password Form', 'wp-frontend-auth' ); }
    public function get_icon(): string  { return 'eicon-lock'; }

    protected function register_controls(): void {
        $this->start_controls_section( 'section_content', [
            'label' => esc_html__( 'Reset Password Form', 'wp-frontend-auth' ), 'tab' => \Elementor\Controls_Manager::TAB_CONTENT,
        ] );
        $this->register_title_controls();
        $this->add_control( 'h_labels', [ 'label' => esc_html__( 'Field Labels', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6
        $this->add_control( 'label_new_pw', [ 'label' => esc_html__( 'New Password label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'New Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'label_confirm_pw', [ 'label' => esc_html__( 'Confirm Password label', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Confirm New Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'button_text', [ 'label' => esc_html__( 'Button text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Reset Password', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Field Placeholders ---
        $this->add_control( 'wpfa_h_placeholders', [ 'label' => esc_html__( 'Field Placeholders', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        $this->add_control( 'placeholder_new_pw', [ 'label' => esc_html__( 'New Password placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'placeholder_confirm_pw', [ 'label' => esc_html__( 'Confirm Password placeholder', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'e.g. ••••••••', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );

        // --- Password Toggle ---
        $this->register_password_toggle_content_controls();

        $this->add_control( 'h_invalid', [ 'label' => esc_html__( 'Invalid / Expired Link State', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::HEADING, 'separator' => 'before' ] );
        // Fix #6 + #3
        $this->add_control( 'invalid_key_message', [ 'label' => esc_html__( 'Error message', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXTAREA, 'default' => '', 'placeholder' => esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'wp-frontend-auth' ), 'rows' => 3, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_request_text', [ 'label' => esc_html__( 'Link text', 'wp-frontend-auth' ), 'type' => \Elementor\Controls_Manager::TEXT, 'default' => '', 'placeholder' => esc_html__( 'Request a new password reset link', 'wp-frontend-auth' ), 'label_block' => true, 'dynamic' => [ 'active' => true ] ] );
        $this->add_control( 'link_request_url', [
            'label'       => esc_html__( 'Link URL (override)', 'wp-frontend-auth' ),
            'type'        => \Elementor\Controls_Manager::URL, // Fix #3
            'dynamic'     => [ 'active' => true ],              // Fix #6
            'default'     => [ 'url' => '' ],
            'placeholder' => esc_html__( 'Leave empty to auto-detect from plugin settings', 'wp-frontend-auth' ),
            'label_block' => true,
            'description' => esc_html__( 'Override the "request new link" URL. Leave empty to use your Lost Password page slug from Frontend Auth settings.', 'wp-frontend-auth' ),
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
        $raw_key  = $_GET['key']   ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        $raw_login = $_GET['login'] ?? ''; // phpcs:ignore WordPress.Security.NonceVerification
        $rp_key   = is_string( $raw_key )   ? sanitize_text_field( wp_unslash( $raw_key ) )   : '';
        $rp_login = is_string( $raw_login ) ? sanitize_text_field( wp_unslash( $raw_login ) ) : '';
        $is_editor = \Elementor\Plugin::$instance->editor && \Elementor\Plugin::$instance->editor->is_edit_mode();

        // Resolve the "request new link" URL: custom override > auto-detected from settings
        // Fix #3 — URL control returns array
        $request_url_raw = $s['link_request_url'] ?? '';
        $request_url     = trim( is_array( $request_url_raw ) ? ( $request_url_raw['url'] ?? '' ) : $request_url_raw );
        if ( '' === $request_url ) {
            $request_url = wpfa_get_action_url( 'lostpassword' );
        }

        if ( empty( $rp_key ) || empty( $rp_login ) ) {
            // No valid reset key in URL. In the editor this is ALWAYS the case.
            // Show the error message + link so the user can preview and customise the text.
            $msg       = ( $s['invalid_key_message'] ?? '' ) ?: __( 'This password reset link is invalid or has expired. Please request a new one.', 'wp-frontend-auth' );
            $link_text = ( $s['link_request_text']   ?? '' ) ?: __( 'Request a new password reset link', 'wp-frontend-auth' );

            $this->open_form_wrap();
            $this->render_form_title( $s );
            echo '<div class="wpfa wpfa-form wpfa-form-resetpass">'
                . '<ul class="wpfa-errors" role="alert"><li class="wpfa-error">' . esc_html( $msg ) . '</li></ul>'
                . '<p class="wpfa-links"><a href="' . esc_url( $request_url ) . '">'
                . esc_html( $link_text ) . '</a></p></div>';

            // In editor only: also show the form fields below so the user can style them
            if ( $is_editor ) {
                echo '<div class="wpfa-editor-preview-wrap">';
                echo '<p class="wpfa-editor-preview-label">' . esc_html__( 'Form preview (visible only in editor):', 'wp-frontend-auth' ) . '</p>'; // Fix #11
                echo '<div class="wpfa wpfa-form wpfa-form-resetpass wpfa-form--preview"><div class="wpfa-inner-form">';
                $lbl_new     = ( $s['label_new_pw']     ?? '' ) ?: esc_html__( 'New Password', 'wp-frontend-auth' );
                $lbl_confirm = ( $s['label_confirm_pw'] ?? '' ) ?: esc_html__( 'Confirm New Password', 'wp-frontend-auth' );
                $btn_text    = ( $s['button_text']       ?? '' ) ?: esc_html__( 'Reset Password', 'wp-frontend-auth' );
                $ph_new     = ( $s['placeholder_new_pw']    ?? '' );
                $ph_confirm = ( $s['placeholder_confirm_pw'] ?? '' );
                $show_lbl   = ( $s['toggle_show_text'] ?? '' ) ?: esc_html__( 'Show', 'wp-frontend-auth' );
                echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label">' . esc_html( $lbl_new ) . ' <span class="wpfa-required">*</span></label>'
                    . '<input type="password" class="wpfa-field"' . ( $ph_new ? ' placeholder="' . esc_attr( $ph_new ) . '"' : '' ) . ' disabled>'
                    . '<button type="button" class="wpfa-password-toggle">' . esc_html( $show_lbl ) . '</button></p>';
                echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label">' . esc_html( $lbl_confirm ) . ' <span class="wpfa-required">*</span></label>'
                    . '<input type="password" class="wpfa-field"' . ( $ph_confirm ? ' placeholder="' . esc_attr( $ph_confirm ) . '"' : '' ) . ' disabled>'
                    . '<button type="button" class="wpfa-password-toggle">' . esc_html( $show_lbl ) . '</button></p>';
                echo '<p class="wpfa-submit"><button type="button" class="wpfa-button wpfa-submit-button">' . esc_html( $btn_text ) . '</button></p>';
                echo '</div></div></div>';
            }
            $this->close_form_wrap();
            return;
        }

        $form = wpfa()->get_form( 'resetpass' );
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
        echo wpfa_render_form( 'resetpass', [ 'show_links' => false, 'redirect_to' => '' ] ); // phpcs:ignore
        $this->close_form_wrap();
    }

    protected function content_template(): void {
        // Backbone JS live preview — shows the invalid-key state (always in editor)
        // plus a form preview below it. All texts respond to control changes in real time.
        echo '<div class="wpfa-form-wrap">';
        echo '<# var tag=settings.form_title_tag||"h3";if(settings.form_title_text){#><{{{tag}}} class="wpfa-form-title">{{{settings.form_title_text}}}</{{{tag}}}><#}#>';

        // Error message + link
        echo '<div class="wpfa wpfa-form wpfa-form-resetpass">';
        echo '<ul class="wpfa-errors" role="alert"><li class="wpfa-error">';
        echo '<# if(settings.invalid_key_message){#>{{{settings.invalid_key_message}}}<#}else{#>' . esc_html__( 'This password reset link is invalid or has expired. Please request a new one.', 'wp-frontend-auth' ) . '<#}#>';
        echo '</li></ul>';
        echo '<p class="wpfa-links"><a href="#">';
        echo '<# if(settings.link_request_text){#>{{{settings.link_request_text}}}<#}else{#>' . esc_html__( 'Request a new password reset link', 'wp-frontend-auth' ) . '<#}#>';
        echo '</a></p></div>';

        // Form preview
        echo '<div class="wpfa-editor-preview-wrap">'; // Fix #11
        echo '<p class="wpfa-editor-preview-label">' . esc_html__( 'Form preview (visible only in editor):', 'wp-frontend-auth' ) . '</p>';
        echo '<div class="wpfa wpfa-form wpfa-form-resetpass wpfa-form--preview"><div class="wpfa-inner-form">';
        echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label"><# if(settings.label_new_pw){#>{{{settings.label_new_pw}}}<#}else{#>' . esc_html__('New Password','wp-frontend-auth') . '<#}#> <span class="wpfa-required">*</span></label><input type="password" class="wpfa-field" placeholder="<# if(settings.placeholder_new_pw){#>{{settings.placeholder_new_pw}}<#}#>" disabled><button type="button" class="wpfa-password-toggle"><# if(settings.toggle_show_text){#>{{{settings.toggle_show_text}}}<#}else{#>' . esc_html__('Show','wp-frontend-auth') . '<#}#></button></p>';
        echo '<p class="wpfa-field-wrap wpfa-field-wrap--password"><label class="wpfa-label"><# if(settings.label_confirm_pw){#>{{{settings.label_confirm_pw}}}<#}else{#>' . esc_html__('Confirm New Password','wp-frontend-auth') . '<#}#> <span class="wpfa-required">*</span></label><input type="password" class="wpfa-field" placeholder="<# if(settings.placeholder_confirm_pw){#>{{settings.placeholder_confirm_pw}}<#}#>" disabled><button type="button" class="wpfa-password-toggle"><# if(settings.toggle_show_text){#>{{{settings.toggle_show_text}}}<#}else{#>' . esc_html__('Show','wp-frontend-auth') . '<#}#></button></p>';
        echo '<p class="wpfa-submit"><button type="button" class="wpfa-button wpfa-submit-button"><# if(settings.button_text){#>{{{settings.button_text}}}<#}else{#>' . esc_html__('Reset Password','wp-frontend-auth') . '<#}#></button></p>';
        echo '</div></div></div>';
        echo '</div><!-- /.wpfa-form-wrap -->';
    }
}


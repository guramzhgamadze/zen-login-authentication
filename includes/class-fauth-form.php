<?php
/**
 * Zen Login & Authentication – Form Class
 *
 * Each "form" is responsible for building its own fields, rendering itself
 * and carrying its own WP_Error bag.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

class ZENLOGAU_Form {

    /** @var string  Unique name, e.g. 'login' */
    private string $name;

    /** @var string  Form action URL */
    private string $action_url;

    /** @var WP_Error */
    private WP_Error $errors;

    /** @var WP_Error  Non-error messages (success notices) */
    private WP_Error $messages;

    /**
     * Ordered field definitions.
     *
     * Each entry: [ type, label, name, value, attrs, priority ]
     *
     * @var array
     */
    private array $fields = [];

    /** @var bool  Whether to show action links (register / lost password) */
    private bool $show_links = true;

    public function __construct( string $name, string $action_url ) {
        $this->name       = $name;
        $this->action_url = $action_url;
        $this->errors     = new WP_Error();
        $this->messages   = new WP_Error();
    }

    /* -----------------------------------------------------------------------
     * Accessors
     * -------------------------------------------------------------------- */

    public function get_name(): string { return $this->name; }

    public function get_action_url(): string { return $this->action_url; }

    public function set_action_url( string $url ): void { $this->action_url = $url; }

    public function set_show_links( bool $v ): void { $this->show_links = $v; }

    /* -----------------------------------------------------------------------
     * Errors / Messages
     * -------------------------------------------------------------------- */

    public function add_error( string $code, string $message, $data = '' ): void {
        $this->errors->add( $code, $message, $data );
    }

    public function get_errors(): WP_Error { return $this->errors; }

    public function set_errors( WP_Error $errors ): void { $this->errors = $errors; }

    public function has_errors(): bool { return (bool) $this->errors->has_errors(); }

    public function add_message( string $code, string $message ): void {
        $this->messages->add( $code, $message );
    }

    /* -----------------------------------------------------------------------
     * Fields
     * -------------------------------------------------------------------- */

    /**
     * Add a field to the form.
     *
     * @param string $name     HTML name attribute.
     * @param array  $args {
     *   @type string  type       Input type (text|email|password|checkbox|submit|hidden).
     *   @type string  label      Visible label. Empty = no label.
     *   @type mixed   value      Default value.
     *   @type string  id         HTML id attribute (defaults to $name).
     *   @type array   attrs      Additional HTML attributes as key=>value.
     *   @type int     priority   Sort order (lower = first). Default 10.
     *   @type string  description  Small help text below the field.
     *   @type bool    required   Adds required attribute.
     * }
     */
    public function add_field( string $name, array $args = [] ): void {
        $defaults = [
            'type'        => 'text',
            'label'       => '',
            'value'       => '',
            'id'          => $name,
            'attrs'       => [],
            'priority'    => 10,
            'description' => '',
            'required'    => false,
            'options'     => [], // for type=select: value => label
        ];
        $this->fields[ $name ] = wp_parse_args( $args, $defaults );
    }

    public function get_field( string $name ): array|false {
        return $this->fields[ $name ] ?? false;
    }

    /** Remove a field entirely (e.g. a widget control toggles it off). */
    public function remove_field( string $name ): void {
        unset( $this->fields[ $name ] );
    }

    public function set_field_value( string $name, $value ): void {
        if ( isset( $this->fields[ $name ] ) ) {
            $this->fields[ $name ]['value'] = $value;
        }
    }

    /**
     * Override any field property (label, value, description, etc.).
     * Used by Elementor widgets to apply custom text from controls.
     */
    public function set_field_option( string $name, string $key, $value ): void {
        if ( isset( $this->fields[ $name ] ) ) {
            $this->fields[ $name ][ $key ] = $value;
        }
    }

    /** Return fields sorted by priority */
    private function sorted_fields(): array {
        $fields = $this->fields;
        uasort( $fields, static function ( $a, $b ) {
            return $a['priority'] <=> $b['priority'];
        } );
        return $fields;
    }

    /* -----------------------------------------------------------------------
     * Rendering
     * -------------------------------------------------------------------- */

    /**
     * Render the full form HTML.
     *
     * @param array $args Optional overrides (show_links, redirect_to).
     * @return string
     */
    public function render( array $args = [] ): string {
        $args = wp_parse_args( $args, [
            'show_links'  => $this->show_links,
            'redirect_to' => '',
        ] );

        ob_start();

        do_action( "zenlogau_before_form_{$this->name}", $this );

        echo '<div class="fauth fauth-form fauth-form-' . esc_attr( $this->name ) . '">';

        // ----- Messages
        if ( $this->messages->has_errors() ) {
            echo '<ul class="fauth-messages" role="status">';
            foreach ( $this->messages->get_error_messages() as $msg ) {
                echo '<li class="fauth-message">' . wp_kses_post( $msg ) . '</li>';
            }
            echo '</ul>';
        }

        // ----- Errors
        if ( $this->has_errors() ) {
            echo '<ul class="fauth-errors" role="alert">';
            foreach ( $this->errors->get_error_messages() as $msg ) {
                echo '<li class="fauth-error">' . wp_kses_post( $msg ) . '</li>';
            }
            echo '</ul>';
        }

        // ----- Form open
        // Store the raw URL here — esc_attr() is applied to every value in the
        // attribute loop below. Do NOT pre-escape with esc_url() here; doing so
        // and then running esc_attr() on it would double-encode & as &amp;amp;.
        $form_attrs = array_merge( [
            'method' => 'post',
            'action' => $this->action_url,
            'class'  => 'fauth-inner-form',
            'id'     => 'fauth-form-' . $this->name,
        ], (array) apply_filters( "zenlogau_form_attributes_{$this->name}", [] ) );

        if ( zenlogau_use_ajax() ) {
            $form_attrs['data-ajax'] = '1';
        }

        echo '<form';
        foreach ( $form_attrs as $attr => $val ) {
            if ( 'action' === $attr ) {
                // URLs must be escaped with esc_url(), not esc_attr().
                echo ' action="' . esc_url( $val ) . '"';
            } else {
                echo ' ' . esc_attr( $attr ) . '="' . esc_attr( $val ) . '"';
            }
        }
        echo ' novalidate>';

        // Hidden nonce
        wp_nonce_field( "zenlogau_{$this->name}", "zenlogau_{$this->name}_nonce", false );

        // Hidden action field
        echo '<input type="hidden" name="zenlogau_action" value="' . esc_attr( $this->name ) . '">';

        // Redirect_to
        if ( ! empty( $args['redirect_to'] ) ) {
            echo '<input type="hidden" name="redirect_to" value="' . esc_url( $args['redirect_to'] ) . '">';
        }

        // Honeypot
        echo zenlogau_honeypot_field_html(); // phpcs:ignore

        // ----- Fields
        foreach ( $this->sorted_fields() as $field_name => $field ) {
            $this->render_field( $field_name, $field );
        }

        echo '</form>';

        // ----- Action links
        if ( $args['show_links'] ) {
            $this->render_links();
        }

        echo '</div>';

        do_action( "zenlogau_after_form_{$this->name}", $this );

        // Allow a whole-form swap (e.g. the two-factor login challenge replaces
        // the login form). $name lets a single filter target one form.
        return (string) apply_filters( 'zenlogau_form_html', (string) ob_get_clean(), $this->name, $this );
    }

    private function render_field( string $name, array $field ): void {
        $type  = $field['type'];
        $id    = esc_attr( $field['id'] );
        $label = $field['label'];
        $value = $field['value'];

        if ( 'hidden' === $type ) {
            echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
            return;
        }

        if ( 'submit' === $type ) {
            echo '<p class="fauth-submit">'
                . '<button type="submit" class="fauth-button fauth-submit-button">'
                . esc_html( $value )
                . '</button></p>';
            return;
        }

        if ( 'action' === $type ) {
            // Fire the ZENLOGAU-namespaced hook for plugin extensions.
            do_action( "zenlogau_{$this->name}_form" );
            // BUG-9 fix: also fire the standard WordPress hooks that 3rd-party
            // plugins (2FA, CAPTCHA, social login) hook into. Without these,
            // any plugin that hooks 'login_form', 'register_form', etc. silently
            // fails to render its fields inside ZENLOGAU forms.
            $wp_hooks = [
                'login'        => 'login_form',
                'register'     => 'register_form',
                'lostpassword' => 'lostpassword_form',
                'resetpass'    => 'resetpass_form',
            ];
            if ( isset( $wp_hooks[ $this->name ] ) ) {
                do_action( $wp_hooks[ $this->name ] ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- fires WordPress core's own login_form/register_form/etc. hooks for third-party compatibility.
            }
            return;
        }

        echo '<p class="fauth-field-wrap fauth-field-' . esc_attr( $name ) . '">';

        $is_checkbox = ( 'checkbox' === $type );

        if ( $label && ! $is_checkbox ) {
            echo '<label class="fauth-label" for="' . esc_attr( $id ) . '">' . esc_html( $label );
            if ( $field['required'] ) {
                echo ' <span class="fauth-required" aria-hidden="true">*</span>';
            }
            echo '</label>';
        }

        if ( 'select' === $type ) {
            $attrs = array_merge( [
                'name'  => $name,
                'id'    => $id,
                'class' => 'fauth-field fauth-select',
            ], (array) $field['attrs'] );
            if ( $field['required'] ) {
                $attrs['required']      = 'required';
                $attrs['aria-required'] = 'true';
            }
            echo '<select';
            foreach ( $attrs as $attr => $val ) {
                echo ' ' . esc_attr( $attr ) . '="' . esc_attr( $val ) . '"';
            }
            echo '>';
            foreach ( (array) $field['options'] as $opt_value => $opt_label ) {
                echo '<option value="' . esc_attr( $opt_value ) . '"' . selected( (string) $value, (string) $opt_value, false ) . '>'
                    . esc_html( $opt_label ) . '</option>';
            }
            echo '</select>';
            if ( ! empty( $field['description'] ) ) {
                echo '<span class="fauth-description">' . esc_html( $field['description'] ) . '</span>';
            }
            echo '</p>';
            return;
        }

        $attrs = array_merge( [
            'type'  => $type,
            'name'  => $name,
            'id'    => $id,
            'value' => $value,
            'class' => $is_checkbox ? 'fauth-checkbox' : 'fauth-field',
        ], (array) $field['attrs'] );

        // BUG-8 fix: never pre-populate password fields with a value.
        if ( 'password' === $type ) {
            $attrs['value'] = '';
        }

        // Placeholder — set by Elementor widget control via set_field_option().
        if ( ! empty( $field['placeholder'] ) ) {
            $attrs['placeholder'] = $field['placeholder'];
        }

        // Password toggle i18n — injected as data attrs so JS can read per-field
        // values instead of relying on the global fauthConfig config object.
        // This allows each widget instance to have its own show/hide label text.
        if ( 'password' === $type ) {
            if ( ! empty( $field['toggle_show'] ) ) {
                $attrs['data-toggle-show'] = $field['toggle_show'];
            }
            if ( ! empty( $field['toggle_hide'] ) ) {
                $attrs['data-toggle-hide'] = $field['toggle_hide'];
            }
        }

        // For checkboxes, checked state is determined by comparing stored value.
        if ( $is_checkbox ) {
            $attrs['value'] = $value;
        }

        if ( $field['required'] ) {
            $attrs['required']      = 'required';
            $attrs['aria-required'] = 'true';
        }

        echo '<input';
        foreach ( $attrs as $attr => $val ) {
            echo ' ' . esc_attr( $attr ) . '="' . esc_attr( $val ) . '"';
        }
        // BUG-E fix: value is already included in $attrs above and output in the loop.
        // Removed the duplicate explicit echo of value= that was here before.
        echo '>';

        if ( $label && $is_checkbox ) {
            echo '<label class="fauth-label fauth-checkbox-label" for="' . esc_attr( $id ) . '">'
                . esc_html( $label ) . '</label>';
        }

        if ( ! empty( $field['description'] ) ) {
            echo '<span class="fauth-description">' . esc_html( $field['description'] ) . '</span>';
        }

        echo '</p>';
    }

    /**
     * Render the "action links" below the form (e.g. Register | Lost password).
     */
    private function render_links(): void {
        $links = apply_filters( "zenlogau_form_links_{$this->name}", [] );
        if ( empty( $links ) ) {
            return;
        }
        echo '<p class="fauth-links">';
        $parts = [];
        foreach ( $links as $link ) {
            $parts[] = '<a href="' . esc_url( $link['url'] ) . '">' . esc_html( $link['label'] ) . '</a>';
        }
        echo implode( ' &bull; ', $parts ); // phpcs:ignore
        echo '</p>';
    }
}

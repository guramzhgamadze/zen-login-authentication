<?php
/**
 * Frontend Auth – Core class
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

final class WPFA {

    /** @var WPFA */
    private static $instance;

    /** Registered action slugs => metadata */
    private array $actions = [];

    /** Registered form objects */
    private array $forms = [];

    public static function instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        do_action( 'wpfa_init', $this );
    }

    /* -----------------------------------------------------------------------
     * Actions registry
     * -------------------------------------------------------------------- */

    /**
     * Register an action.
     *
     * @param string $name  e.g. 'login'
     * @param array  $args {
     *   title, slug, callback, ajax_callback,
     *   show_on_forms, show_in_widget, show_in_nav_menus, show_nav_menu_item
     * }
     */
    public function register_action( string $name, array $args = [] ): void {
        $defaults = [
            'title'              => ucfirst( $name ),
            'slug'               => $name,
            'callback'           => null,
            'ajax_callback'      => null,
            'show_on_forms'      => true,
            'show_in_widget'     => true,
            'show_in_nav_menus'  => true,
            'show_nav_menu_item' => true,
        ];
        $this->actions[ $name ] = wp_parse_args( $args, $defaults );
        do_action( 'wpfa_registered_action', $name, $this->actions[ $name ] );
    }

    public function unregister_action( string $name ): void {
        unset( $this->actions[ $name ] );
    }

    public function get_action( string $name ): array|false {
        return $this->actions[ $name ] ?? false;
    }

    public function get_actions(): array {
        return $this->actions;
    }

    /* -----------------------------------------------------------------------
     * Forms registry
     * -------------------------------------------------------------------- */

    public function register_form( WPFA_Form $form ): WPFA_Form {
        $this->forms[ $form->get_name() ] = $form;
        do_action( 'wpfa_registered_form', $form->get_name(), $form );
        return $form;
    }

    public function unregister_form( string $name ): void {
        unset( $this->forms[ $name ] );
    }

    public function get_form( string $name ): WPFA_Form|false {
        return $this->forms[ $name ] ?? false;
    }

    public function get_forms(): array {
        return $this->forms;
    }
}

/** Global accessor */
function wpfa(): WPFA {
    return WPFA::instance();
}

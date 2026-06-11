<?php
/**
 * Frontend Auth – Form Definitions
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/**
 * Register all default forms.
 *
 * HIGH FIX: Removed is_admin() guard. Forms must be registered in every
 * context including admin-ajax.php (used by Elementor editor). Without
 * this fix, wpfa()->get_form('login') returns false inside the Elementor
 * editor context and every widget renders empty.
 */
function wpfa_register_default_forms(): void {
    wpfa_register_login_form();
    wpfa_register_registration_form();
    wpfa_register_lost_password_form();
    wpfa_register_password_reset_form();
}

/* -----------------------------------------------------------------------
 * Login
 * -------------------------------------------------------------------- */

function wpfa_register_login_form(): void {
    $form = new WPFA_Form( 'login', wpfa_get_action_url( 'login' ) );

    $form->add_field( 'log', [
        'type'     => 'text',
        'label'    => wpfa_get_username_label( 'login' ),
        'value'    => wpfa_get_request_value( 'log', 'post' ),
        'id'       => 'user_login',
        'attrs'    => [ 'autocapitalize' => 'off', 'autocomplete' => 'username' ],
        'required' => true,
        'priority' => 10,
    ] );

    $form->add_field( 'pwd', [
        'type'     => 'password',
        'label'    => __( 'Password', 'frontend-auth' ),
        'id'       => 'user_pass',
        'attrs'    => [ 'autocomplete' => 'current-password' ],
        'required' => true,
        'priority' => 15,
    ] );

    $form->add_field( 'login_form_hook', [
        'type'     => 'action',
        'priority' => 18,
    ] );

    $form->add_field( 'rememberme', [
        'type'     => 'checkbox',
        'label'    => __( 'Remember Me', 'frontend-auth' ),
        'value'    => 'forever',
        'id'       => 'rememberme',
        'priority' => 20,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Log In', 'frontend-auth' ),
        'priority' => 30,
    ] );

    wpfa()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Register
 * -------------------------------------------------------------------- */

function wpfa_register_registration_form(): void {
    if ( ! get_option( 'users_can_register' ) ) {
        return;
    }

    $form = new WPFA_Form( 'register', wpfa_get_action_url( 'register' ) );

    $form->add_field( 'user_login', [
        'type'        => 'text',
        'label'       => __( 'Username', 'frontend-auth' ),
        'value'       => wpfa_get_request_value( 'user_login', 'post' ),
        'id'          => 'user_login',
        'attrs'       => [ 'autocapitalize' => 'off', 'autocomplete' => 'username' ],
        'required'    => true,
        'priority'    => 10,
        'description' => __( 'Letters, numbers, and underscores only.', 'frontend-auth' ),
    ] );

    $form->add_field( 'user_email', [
        'type'     => 'email',
        'label'    => __( 'Email Address', 'frontend-auth' ),
        'value'    => wpfa_get_request_value( 'user_email', 'post' ),
        'id'       => 'user_email',
        'attrs'    => [ 'autocomplete' => 'email' ],
        'required' => true,
        'priority' => 20,
    ] );

    if ( wpfa_allow_user_passwords() ) {
        $form->add_field( 'user_pass1', [
            'type'     => 'password',
            'label'    => __( 'Password', 'frontend-auth' ),
            'id'       => 'user_pass1',
            'attrs'    => [ 'autocomplete' => 'new-password' ],
            'required' => true,
            'priority' => 30,
        ] );
        $form->add_field( 'user_pass2', [
            'type'     => 'password',
            'label'    => __( 'Confirm Password', 'frontend-auth' ),
            'id'       => 'user_pass2',
            'attrs'    => [ 'autocomplete' => 'new-password' ],
            'required' => true,
            'priority' => 35,
        ] );
    }

    $form->add_field( 'register_form_hook', [
        'type'     => 'action',
        'priority' => 38,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Register', 'frontend-auth' ),
        'priority' => 40,
    ] );

    wpfa()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Lost Password
 * -------------------------------------------------------------------- */

function wpfa_register_lost_password_form(): void {
    $form = new WPFA_Form( 'lostpassword', wpfa_get_action_url( 'lostpassword' ) );

    $form->add_field( 'user_login', [
        'type'     => 'text',
        'label'    => __( 'Username or Email Address', 'frontend-auth' ),
        'value'    => wpfa_get_request_value( 'user_login', 'post' ),
        'id'       => 'user_login',
        'attrs'    => [ 'autocapitalize' => 'off', 'autocomplete' => 'username email' ],
        'required' => true,
        'priority' => 10,
    ] );

    $form->add_field( 'lostpassword_form_hook', [
        'type'     => 'action',
        'priority' => 15,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Get New Password', 'frontend-auth' ),
        'priority' => 20,
    ] );

    wpfa()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Reset Password
 * -------------------------------------------------------------------- */

function wpfa_register_password_reset_form(): void {
    $form = new WPFA_Form( 'resetpass', wpfa_get_action_url( 'resetpass' ) );

    $form->add_field( 'rp_key', [
        'type'     => 'hidden',
        'value'    => wpfa_get_request_value( 'key', 'get' ),
        'priority' => 5,
    ] );

    $form->add_field( 'rp_login', [
        'type'     => 'hidden',
        'value'    => wpfa_get_request_value( 'login', 'get' ),
        'priority' => 5,
    ] );

    $form->add_field( 'pass1', [
        'type'     => 'password',
        'label'    => __( 'New Password', 'frontend-auth' ),
        'id'       => 'pass1',
        'attrs'    => [ 'autocomplete' => 'new-password' ],
        'required' => true,
        'priority' => 10,
    ] );

    $form->add_field( 'pass2', [
        'type'     => 'password',
        'label'    => __( 'Confirm New Password', 'frontend-auth' ),
        'id'       => 'pass2',
        'attrs'    => [ 'autocomplete' => 'new-password' ],
        'required' => true,
        'priority' => 20,
    ] );

    $form->add_field( 'resetpass_form_hook', [
        'type'     => 'action',
        'priority' => 25,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Reset Password', 'frontend-auth' ),
        'priority' => 30,
    ] );

    wpfa()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Links filters
 * -------------------------------------------------------------------- */

add_filter( 'wpfa_form_links_login', function ( $links ) {
    if ( get_option( 'users_can_register' ) ) {
        $links[] = [ 'label' => __( 'Register', 'frontend-auth' ), 'url' => wpfa_get_action_url( 'register' ) ];
    }
    $links[] = [ 'label' => __( 'Lost your password?', 'frontend-auth' ), 'url' => wpfa_get_action_url( 'lostpassword' ) ];
    return $links;
} );

add_filter( 'wpfa_form_links_register', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'frontend-auth' ), 'url' => wpfa_get_action_url( 'login' ) ];
    return $links;
} );

add_filter( 'wpfa_form_links_lostpassword', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'frontend-auth' ), 'url' => wpfa_get_action_url( 'login' ) ];
    return $links;
} );

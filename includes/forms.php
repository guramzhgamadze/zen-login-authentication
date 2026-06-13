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
 * this fix, fauth()->get_form('login') returns false inside the Elementor
 * editor context and every widget renders empty.
 */
function fauth_register_default_forms(): void {
    fauth_register_login_form();
    fauth_register_registration_form();
    fauth_register_lost_password_form();
    fauth_register_password_reset_form();
    fauth_register_account_form();
}

/* -----------------------------------------------------------------------
 * Login
 * -------------------------------------------------------------------- */

function fauth_register_login_form(): void {
    $form = new FAUTH_Form( 'login', fauth_get_action_url( 'login' ) );

    $form->add_field( 'log', [
        'type'     => 'text',
        'label'    => fauth_get_username_label( 'login' ),
        'value'    => fauth_get_request_value( 'log', 'post' ),
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

    fauth()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Register
 * -------------------------------------------------------------------- */

function fauth_register_registration_form(): void {
    if ( ! get_option( 'users_can_register' ) ) {
        return;
    }

    $form = new FAUTH_Form( 'register', fauth_get_action_url( 'register' ) );

    $form->add_field( 'user_login', [
        'type'        => 'text',
        'label'       => __( 'Username', 'frontend-auth' ),
        'value'       => fauth_get_request_value( 'user_login', 'post' ),
        'id'          => 'user_login',
        'attrs'       => [ 'autocapitalize' => 'off', 'autocomplete' => 'username' ],
        'required'    => true,
        'priority'    => 10,
        'description' => __( 'Letters, numbers, and underscores only.', 'frontend-auth' ),
    ] );

    $form->add_field( 'user_email', [
        'type'     => 'email',
        'label'    => __( 'Email Address', 'frontend-auth' ),
        'value'    => fauth_get_request_value( 'user_email', 'post' ),
        'id'       => 'user_email',
        'attrs'    => [ 'autocomplete' => 'email' ],
        'required' => true,
        'priority' => 20,
    ] );

    if ( fauth_allow_user_passwords() ) {
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

    fauth()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Lost Password
 * -------------------------------------------------------------------- */

function fauth_register_lost_password_form(): void {
    $form = new FAUTH_Form( 'lostpassword', fauth_get_action_url( 'lostpassword' ) );

    $form->add_field( 'user_login', [
        'type'     => 'text',
        'label'    => __( 'Username or Email Address', 'frontend-auth' ),
        'value'    => fauth_get_request_value( 'user_login', 'post' ),
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

    fauth()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Reset Password
 * -------------------------------------------------------------------- */

function fauth_register_password_reset_form(): void {
    $form = new FAUTH_Form( 'resetpass', fauth_get_action_url( 'resetpass' ) );

    $form->add_field( 'rp_key', [
        'type'     => 'hidden',
        'value'    => fauth_get_request_value( 'key', 'get' ),
        'priority' => 5,
    ] );

    $form->add_field( 'rp_login', [
        'type'     => 'hidden',
        'value'    => fauth_get_request_value( 'login', 'get' ),
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

    fauth()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Account (edit profile) — logged-in users only
 * -------------------------------------------------------------------- */

function fauth_register_account_form(): void {
    $form = new FAUTH_Form( 'account', fauth_get_action_url( 'account' ) );
    $user = wp_get_current_user();

    // Sticky values: after a failed POST re-show what the user typed; on a
    // fresh GET pre-fill from the current user's profile. Only trust POST
    // values when this request is actually an account submission — other
    // forms on the site may share field names like user_email.
    $is_account_post = fauth_is_post_request()
        && 'account' === sanitize_key( fauth_get_request_value( 'fauth_action', 'post' ) );

    $first_name = $is_account_post ? sanitize_text_field( fauth_get_request_value( 'first_name', 'post' ) ) : '';
    if ( '' === $first_name && $user->exists() ) {
        $first_name = $user->first_name;
    }

    $last_name = $is_account_post ? sanitize_text_field( fauth_get_request_value( 'last_name', 'post' ) ) : '';
    if ( '' === $last_name && $user->exists() ) {
        $last_name = $user->last_name;
    }

    $display_name = $is_account_post ? sanitize_text_field( fauth_get_request_value( 'display_name', 'post' ) ) : '';
    if ( '' === $display_name && $user->exists() ) {
        $display_name = $user->display_name;
    }

    $user_email = $is_account_post ? sanitize_email( fauth_get_request_value( 'user_email', 'post' ) ) : '';
    if ( '' === $user_email && $user->exists() ) {
        $user_email = $user->user_email;
    }

    // Read-only username, same as wp-admin's profile screen. Disabled inputs
    // are never submitted, so the handler cannot receive (or be tricked into
    // processing) a username change.
    $form->add_field( 'user_login', [
        'type'        => 'text',
        'label'       => __( 'Username', 'frontend-auth' ),
        'value'       => $user->exists() ? $user->user_login : '',
        'id'          => 'user_login',
        'attrs'       => [ 'disabled' => 'disabled', 'autocomplete' => 'username' ],
        'priority'    => 5,
        'description' => __( 'Usernames cannot be changed.', 'frontend-auth' ),
    ] );

    $form->add_field( 'first_name', [
        'type'     => 'text',
        'label'    => __( 'First Name', 'frontend-auth' ),
        'value'    => $first_name,
        'id'       => 'first_name',
        'attrs'    => [ 'autocomplete' => 'given-name' ],
        'priority' => 10,
    ] );

    $form->add_field( 'last_name', [
        'type'     => 'text',
        'label'    => __( 'Last Name', 'frontend-auth' ),
        'value'    => $last_name,
        'id'       => 'last_name',
        'attrs'    => [ 'autocomplete' => 'family-name' ],
        'priority' => 12,
    ] );

    $form->add_field( 'display_name', [
        'type'     => 'select',
        'label'    => __( 'Display name publicly as', 'frontend-auth' ),
        'value'    => $display_name,
        'id'       => 'display_name',
        'options'  => fauth_account_display_name_options( $user, $first_name, $last_name, $display_name ),
        // frontend-auth.js rebuilds the option list live as the user types
        // their first/last name (mirroring wp-admin's user-profile.js); the
        // username and nickname combos are exposed for it as data attributes.
        'attrs'    => [
            'data-username' => $user->exists() ? $user->user_login : '',
            'data-nickname' => $user->exists() ? $user->nickname : '',
        ],
        'required' => true,
        'priority' => 14,
    ] );

    $form->add_field( 'user_email', [
        'type'     => 'email',
        'label'    => __( 'Email Address', 'frontend-auth' ),
        'value'    => $user_email,
        'id'       => 'user_email',
        'attrs'    => [ 'autocomplete' => 'email' ],
        'required' => true,
        'priority' => 20,
    ] );

    // ids pass1/pass2 intentionally match the reset form: the password
    // strength meter and visibility toggle in frontend-auth.js bind to them.
    // The two forms never render on the same page, so the ids cannot collide.
    $form->add_field( 'pass1', [
        'type'        => 'password',
        'label'       => __( 'New Password', 'frontend-auth' ),
        'id'          => 'pass1',
        'attrs'       => [ 'autocomplete' => 'new-password' ],
        'priority'    => 30,
        'description' => __( 'Leave blank to keep your current password.', 'frontend-auth' ),
    ] );

    $form->add_field( 'pass2', [
        'type'     => 'password',
        'label'    => __( 'Confirm New Password', 'frontend-auth' ),
        'id'       => 'pass2',
        'attrs'    => [ 'autocomplete' => 'new-password' ],
        'priority' => 35,
    ] );

    $form->add_field( 'account_form_hook', [
        'type'     => 'action',
        'priority' => 38,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Save Changes', 'frontend-auth' ),
        'priority' => 40,
    ] );

    fauth()->register_form( $form );
}

/**
 * Build the "Display name publicly as" choices — the same set wp-admin's
 * profile.php offers: current display name, nickname, username, first, last,
 * "First Last", and "Last First". Keys equal values (the option's value IS
 * the display string), deduplicated, empties dropped.
 *
 * @param WP_User $user        The user being edited.
 * @param string  $first_name  First name (sticky POST value or saved meta).
 * @param string  $last_name   Last name (sticky POST value or saved meta).
 * @param string  $current     The currently selected display name.
 * @return array<string,string>
 */
function fauth_account_display_name_options( WP_User $user, string $first_name, string $last_name, string $current ): array {
    $options = [];
    $add     = static function ( string $candidate ) use ( &$options ): void {
        $candidate = trim( $candidate );
        if ( '' !== $candidate && ! isset( $options[ $candidate ] ) ) {
            $options[ $candidate ] = $candidate;
        }
    };

    $add( $current );
    if ( $user->exists() ) {
        $add( $user->nickname );
        $add( $user->user_login );
    }
    $add( $first_name );
    $add( $last_name );
    if ( '' !== trim( $first_name ) && '' !== trim( $last_name ) ) {
        $add( trim( $first_name ) . ' ' . trim( $last_name ) );
        $add( trim( $last_name ) . ' ' . trim( $first_name ) );
    }

    return (array) apply_filters( 'fauth_account_display_name_options', $options, $user );
}

/* -----------------------------------------------------------------------
 * Links filters
 * -------------------------------------------------------------------- */

add_filter( 'fauth_form_links_login', function ( $links ) {
    if ( get_option( 'users_can_register' ) ) {
        $links[] = [ 'label' => __( 'Register', 'frontend-auth' ), 'url' => fauth_get_action_url( 'register' ) ];
    }
    $links[] = [ 'label' => __( 'Lost your password?', 'frontend-auth' ), 'url' => fauth_get_action_url( 'lostpassword' ) ];
    return $links;
} );

add_filter( 'fauth_form_links_register', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'frontend-auth' ), 'url' => fauth_get_action_url( 'login' ) ];
    return $links;
} );

add_filter( 'fauth_form_links_lostpassword', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'frontend-auth' ), 'url' => fauth_get_action_url( 'login' ) ];
    return $links;
} );

add_filter( 'fauth_form_links_account', function ( $links ) {
    // wp_logout_url() is rewritten to the plugin's /logout/ URL (with nonce)
    // by fauth_filter_logout_url(), so this stays correct on custom slugs.
    $links[] = [ 'label' => __( 'Log Out', 'frontend-auth' ), 'url' => wp_logout_url() ];
    return $links;
} );

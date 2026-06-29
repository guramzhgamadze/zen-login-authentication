<?php
/**
 * Zen Login & Authentication – Form Definitions
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/**
 * Register all default forms.
 *
 * HIGH FIX: Removed is_admin() guard. Forms must be registered in every
 * context including admin-ajax.php (used by Elementor editor). Without
 * this fix, zenlogau()->get_form('login') returns false inside the Elementor
 * editor context and every widget renders empty.
 */
function zenlogau_register_default_forms(): void {
    zenlogau_register_login_form();
    zenlogau_register_registration_form();
    zenlogau_register_lost_password_form();
    zenlogau_register_password_reset_form();
    zenlogau_register_account_form();
}

/* -----------------------------------------------------------------------
 * Login
 * -------------------------------------------------------------------- */

function zenlogau_register_login_form(): void {
    $form = new ZENLOGAU_Form( 'login', zenlogau_get_action_url( 'login' ) );

    $form->add_field( 'log', [
        'type'     => 'text',
        'label'    => zenlogau_get_username_label( 'login' ),
        'value'    => zenlogau_get_request_value( 'log', 'post' ),
        'id'       => 'user_login',
        'attrs'    => [ 'autocapitalize' => 'off', 'autocomplete' => 'username' ],
        'required' => true,
        'priority' => 10,
    ] );

    $form->add_field( 'pwd', [
        'type'     => 'password',
        'label'    => __( 'Password', 'zen-login-authentication' ),
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
        'label'    => __( 'Remember Me', 'zen-login-authentication' ),
        'value'    => 'forever',
        'id'       => 'rememberme',
        'priority' => 20,
    ] );

    $form->add_field( 'submit', [
        'type'     => 'submit',
        'value'    => __( 'Log In', 'zen-login-authentication' ),
        'priority' => 30,
    ] );

    zenlogau()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Register
 * -------------------------------------------------------------------- */

function zenlogau_register_registration_form(): void {
    if ( ! get_option( 'users_can_register' ) ) {
        return;
    }

    $form = new ZENLOGAU_Form( 'register', zenlogau_get_action_url( 'register' ) );

    $form->add_field( 'user_login', [
        'type'        => 'text',
        'label'       => __( 'Username', 'zen-login-authentication' ),
        'value'       => zenlogau_get_request_value( 'user_login', 'post' ),
        'id'          => 'user_login',
        'attrs'       => [ 'autocapitalize' => 'off', 'autocomplete' => 'username' ],
        'required'    => true,
        'priority'    => 10,
        'description' => __( 'Letters, numbers, and underscores only.', 'zen-login-authentication' ),
    ] );

    $form->add_field( 'user_email', [
        'type'     => 'email',
        'label'    => __( 'Email Address', 'zen-login-authentication' ),
        'value'    => zenlogau_get_request_value( 'user_email', 'post' ),
        'id'       => 'user_email',
        'attrs'    => [ 'autocomplete' => 'email' ],
        'required' => true,
        'priority' => 20,
    ] );

    if ( zenlogau_allow_user_passwords() ) {
        $form->add_field( 'user_pass1', [
            'type'     => 'password',
            'label'    => __( 'Password', 'zen-login-authentication' ),
            'id'       => 'user_pass1',
            'attrs'    => [ 'autocomplete' => 'new-password' ],
            'required' => true,
            'priority' => 30,
        ] );
        $form->add_field( 'user_pass2', [
            'type'     => 'password',
            'label'    => __( 'Confirm Password', 'zen-login-authentication' ),
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
        'value'    => __( 'Register', 'zen-login-authentication' ),
        'priority' => 40,
    ] );

    zenlogau()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Lost Password
 * -------------------------------------------------------------------- */

function zenlogau_register_lost_password_form(): void {
    $form = new ZENLOGAU_Form( 'lostpassword', zenlogau_get_action_url( 'lostpassword' ) );

    $form->add_field( 'user_login', [
        'type'     => 'text',
        'label'    => __( 'Username or Email Address', 'zen-login-authentication' ),
        'value'    => zenlogau_get_request_value( 'user_login', 'post' ),
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
        'value'    => __( 'Get New Password', 'zen-login-authentication' ),
        'priority' => 20,
    ] );

    zenlogau()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Reset Password
 * -------------------------------------------------------------------- */

function zenlogau_register_password_reset_form(): void {
    $form = new ZENLOGAU_Form( 'resetpass', zenlogau_get_action_url( 'resetpass' ) );

    $form->add_field( 'rp_key', [
        'type'     => 'hidden',
        'value'    => zenlogau_get_request_value( 'key', 'get' ),
        'priority' => 5,
    ] );

    $form->add_field( 'rp_login', [
        'type'     => 'hidden',
        'value'    => zenlogau_get_request_value( 'login', 'get' ),
        'priority' => 5,
    ] );

    $form->add_field( 'pass1', [
        'type'     => 'password',
        'label'    => __( 'New Password', 'zen-login-authentication' ),
        'id'       => 'pass1',
        'attrs'    => [ 'autocomplete' => 'new-password' ],
        'required' => true,
        'priority' => 10,
    ] );

    $form->add_field( 'pass2', [
        'type'     => 'password',
        'label'    => __( 'Confirm New Password', 'zen-login-authentication' ),
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
        'value'    => __( 'Reset Password', 'zen-login-authentication' ),
        'priority' => 30,
    ] );

    zenlogau()->register_form( $form );
}

/* -----------------------------------------------------------------------
 * Account (edit profile) — logged-in users only
 * -------------------------------------------------------------------- */

function zenlogau_register_account_form(): void {
    $form = new ZENLOGAU_Form( 'account', zenlogau_get_action_url( 'account' ) );
    $user = wp_get_current_user();

    // Sticky values: after a failed POST re-show what the user typed; on a
    // fresh GET pre-fill from the current user's profile. Only trust POST
    // values when this request is actually an account submission — other
    // forms on the site may share field names like user_email.
    $is_account_post = zenlogau_is_post_request()
        && 'account' === sanitize_key( zenlogau_get_request_value( 'zenlogau_action', 'post' ) );

    $first_name = $is_account_post ? sanitize_text_field( zenlogau_get_request_value( 'first_name', 'post' ) ) : '';
    if ( '' === $first_name && $user->exists() ) {
        $first_name = $user->first_name;
    }

    $last_name = $is_account_post ? sanitize_text_field( zenlogau_get_request_value( 'last_name', 'post' ) ) : '';
    if ( '' === $last_name && $user->exists() ) {
        $last_name = $user->last_name;
    }

    $display_name = $is_account_post ? sanitize_text_field( zenlogau_get_request_value( 'display_name', 'post' ) ) : '';
    if ( '' === $display_name && $user->exists() ) {
        $display_name = $user->display_name;
    }

    $user_email = $is_account_post ? sanitize_email( zenlogau_get_request_value( 'user_email', 'post' ) ) : '';
    if ( '' === $user_email && $user->exists() ) {
        $user_email = $user->user_email;
    }

    // ===== Profile Information card =====
    $form->add_field( 'html_profile_open', [
        'type'     => 'html',
        'priority' => 1,
        'html'     => '<div class="fauth-card fauth-card--profile"><div class="fauth-card-head">'
            . '<h3 class="fauth-card-title">' . esc_html__( 'Profile Information', 'zen-login-authentication' ) . '</h3>'
            . '<p class="fauth-card-sub">' . esc_html__( 'Update your account profile information and email address.', 'zen-login-authentication' ) . '</p>'
            . '</div><div class="fauth-card-body"><div class="fauth-row">',
    ] );

    // Read-only username, same as wp-admin's profile screen. Disabled inputs
    // are never submitted, so the handler cannot receive (or be tricked into
    // processing) a username change.
    $form->add_field( 'user_login', [
        'type'        => 'text',
        'label'       => __( 'Username', 'zen-login-authentication' ),
        'value'       => $user->exists() ? $user->user_login : '',
        'id'          => 'user_login',
        'attrs'       => [ 'disabled' => 'disabled', 'autocomplete' => 'username' ],
        'priority'    => 5,
        'description' => __( 'Usernames cannot be changed.', 'zen-login-authentication' ),
    ] );

    $form->add_field( 'user_email', [
        'type'     => 'email',
        'label'    => __( 'Email Address', 'zen-login-authentication' ),
        'value'    => $user_email,
        'id'       => 'user_email',
        'attrs'    => [ 'autocomplete' => 'email' ],
        'required' => true,
        'priority' => 8,
    ] );

    $form->add_field( 'html_row_names', [
        'type'     => 'html',
        'priority' => 9,
        'html'     => '</div><div class="fauth-row">',
    ] );

    $form->add_field( 'first_name', [
        'type'     => 'text',
        'label'    => __( 'First Name', 'zen-login-authentication' ),
        'value'    => $first_name,
        'id'       => 'first_name',
        'attrs'    => [ 'autocomplete' => 'given-name' ],
        'priority' => 10,
    ] );

    $form->add_field( 'last_name', [
        'type'     => 'text',
        'label'    => __( 'Last Name', 'zen-login-authentication' ),
        'value'    => $last_name,
        'id'       => 'last_name',
        'attrs'    => [ 'autocomplete' => 'family-name' ],
        'priority' => 12,
    ] );

    $form->add_field( 'html_row_close', [
        'type'     => 'html',
        'priority' => 13,
        'html'     => '</div>',
    ] );

    $form->add_field( 'display_name', [
        'type'     => 'select',
        'label'    => __( 'Display name publicly as', 'zen-login-authentication' ),
        'value'    => $display_name,
        'id'       => 'display_name',
        'options'  => zenlogau_account_display_name_options( $user, $first_name, $last_name, $display_name ),
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

    $form->add_field( 'submit_profile', [
        'type'         => 'submit',
        'value'        => __( 'Save Profile', 'zen-login-authentication' ),
        'submit_name'  => 'zenlogau_account_action',
        'submit_value' => 'profile',
        'button_class' => 'fauth-button-inline',
        'priority'     => 16,
    ] );

    $form->add_field( 'html_profile_close', [
        'type'     => 'html',
        'priority' => 18,
        'html'     => '</div></div>',
    ] );

    // ===== Change Password card =====
    $form->add_field( 'html_password_open', [
        'type'     => 'html',
        'priority' => 28,
        'html'     => '<div class="fauth-card fauth-card--password"><div class="fauth-card-head">'
            . '<h3 class="fauth-card-title">' . esc_html__( 'Change Password', 'zen-login-authentication' ) . '</h3>'
            . '<p class="fauth-card-sub">' . esc_html__( 'Update your password to keep your account secure.', 'zen-login-authentication' ) . '</p>'
            . '</div><div class="fauth-card-body">',
    ] );

    // ids pass1/pass2 intentionally match the reset form: the password
    // strength meter and visibility toggle in frontend-auth.js bind to them.
    // The two forms never render on the same page, so the ids cannot collide.
    $form->add_field( 'pass1', [
        'type'        => 'password',
        'label'       => __( 'New Password', 'zen-login-authentication' ),
        'id'          => 'pass1',
        'attrs'       => [ 'autocomplete' => 'new-password' ],
        'placeholder' => __( 'Enter new password', 'zen-login-authentication' ),
        'priority'    => 30,
        'description' => __( 'Leave blank to keep your current password.', 'zen-login-authentication' ),
    ] );

    $form->add_field( 'pass2', [
        'type'        => 'password',
        'label'       => __( 'Confirm New Password', 'zen-login-authentication' ),
        'id'          => 'pass2',
        'attrs'       => [ 'autocomplete' => 'new-password' ],
        'placeholder' => __( 'Confirm new password', 'zen-login-authentication' ),
        'priority'    => 35,
    ] );

    // Re-authentication for sensitive changes. Only consulted server-side when
    // the email or password is actually changing (see zenlogau_handle_account);
    // left blank otherwise, so name-only edits don't require it.
    $form->add_field( 'current_password', [
        'type'        => 'password',
        'label'       => __( 'Current Password', 'zen-login-authentication' ),
        'id'          => 'current_password',
        'attrs'       => [ 'autocomplete' => 'current-password' ],
        'placeholder' => __( 'Enter current password', 'zen-login-authentication' ),
        'priority'    => 37,
        'description' => __( 'Required to change your email address or password.', 'zen-login-authentication' ),
    ] );

    $form->add_field( 'submit_password', [
        'type'         => 'submit',
        'value'        => __( 'Update Password', 'zen-login-authentication' ),
        'submit_name'  => 'zenlogau_account_action',
        'submit_value' => 'password',
        'button_class' => 'fauth-button-inline',
        'priority'     => 39,
    ] );

    $form->add_field( 'html_password_close', [
        'type'     => 'html',
        'priority' => 42,
        'html'     => '</div></div>',
    ] );

    // Third-party additions render after both cards, still inside the form.
    $form->add_field( 'account_form_hook', [
        'type'     => 'action',
        'priority' => 50,
    ] );

    zenlogau()->register_form( $form );
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
function zenlogau_account_display_name_options( WP_User $user, string $first_name, string $last_name, string $current ): array {
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

    return (array) apply_filters( 'zenlogau_account_display_name_options', $options, $user );
}

/* -----------------------------------------------------------------------
 * Links filters
 * -------------------------------------------------------------------- */

add_filter( 'zenlogau_form_links_login', function ( $links ) {
    if ( get_option( 'users_can_register' ) ) {
        $links[] = [ 'label' => __( 'Register', 'zen-login-authentication' ), 'url' => zenlogau_get_action_url( 'register' ) ];
    }
    $links[] = [ 'label' => __( 'Lost your password?', 'zen-login-authentication' ), 'url' => zenlogau_get_action_url( 'lostpassword' ) ];
    return $links;
} );

add_filter( 'zenlogau_form_links_register', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'zen-login-authentication' ), 'url' => zenlogau_get_action_url( 'login' ) ];
    return $links;
} );

add_filter( 'zenlogau_form_links_lostpassword', function ( $links ) {
    $links[] = [ 'label' => __( 'Log In', 'zen-login-authentication' ), 'url' => zenlogau_get_action_url( 'login' ) ];
    return $links;
} );

// The account "Log Out" and "Sign out of other devices" actions now live in
// the Session Management card (includes/account-sessions.php), so the account
// form no longer renders a links row.

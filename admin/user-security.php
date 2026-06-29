<?php
/**
 * Admin – reset a user's two-factor authentication and passkeys.
 *
 * Adds a control to the wp-admin user-edit screen so an administrator can clear
 * a locked-out user's second factor and remove their passkeys — e.g. a user who
 * lost their authenticator AND their recovery codes. Shown only to users who can
 * edit the account being viewed.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

add_action( 'edit_user_profile', 'zenlogau_admin_security_section' );

/**
 * @param mixed $user The user being edited (a WP_User from the edit_user_profile hook).
 */
function zenlogau_admin_security_section( $user ): void {
    if ( ! ( $user instanceof WP_User ) || ! current_user_can( 'edit_user', $user->ID ) ) {
        return;
    }

    $has_2fa  = function_exists( 'zenlogau_2fa_user_enabled' ) && zenlogau_2fa_user_enabled( (int) $user->ID );
    $passkeys = function_exists( 'zenlogau_get_passkeys' ) ? count( zenlogau_get_passkeys( (int) $user->ID ) ) : 0;

    echo '<h2>' . esc_html__( 'Zen Login & Authentication', 'zen-login-authentication' ) . '</h2>';
    echo '<table class="form-table" role="presentation"><tr>';
    echo '<th scope="row">' . esc_html__( 'Two-factor & passkeys', 'zen-login-authentication' ) . '</th>';
    echo '<td>';

    echo '<p>';
    echo $has_2fa
        ? esc_html__( 'Two-factor authentication: on', 'zen-login-authentication' )
        : esc_html__( 'Two-factor authentication: off', 'zen-login-authentication' );
    echo ' &middot; ';
    echo esc_html(
        sprintf(
            /* translators: %d: number of registered passkeys. */
            _n( '%d passkey', '%d passkeys', $passkeys, 'zen-login-authentication' ),
            $passkeys
        )
    );
    echo '</p>';

    if ( $has_2fa || $passkeys > 0 ) {
        wp_nonce_field( 'zenlogau_reset_security_' . $user->ID, 'zenlogau_reset_security_nonce', false );
        echo '<label for="zenlogau_reset_security"><input type="checkbox" name="zenlogau_reset_security" id="zenlogau_reset_security" value="1"> '
            . esc_html__( 'Turn off two-factor authentication and remove all passkeys for this user', 'zen-login-authentication' )
            . '</label>';
        echo '<p class="description">' . esc_html__( 'Use this to recover a user who has lost their authenticator and recovery codes. They can re-enrol afterwards.', 'zen-login-authentication' ) . '</p>';
    }

    echo '</td></tr></table>';
}

add_action( 'edit_user_profile_update', 'zenlogau_admin_security_save' );

/**
 * @param int $user_id The user being saved.
 */
function zenlogau_admin_security_save( $user_id ): void {
    $user_id = (int) $user_id;
    if ( ! current_user_can( 'edit_user', $user_id ) ) {
        return;
    }
    if ( ! isset( $_POST['zenlogau_reset_security_nonce'] ) ) {
        return;
    }
    $nonce = sanitize_key( wp_unslash( $_POST['zenlogau_reset_security_nonce'] ) );
    if ( ! wp_verify_nonce( $nonce, 'zenlogau_reset_security_' . $user_id ) ) {
        return;
    }
    if ( empty( $_POST['zenlogau_reset_security'] ) ) {
        return;
    }

    if ( function_exists( 'zenlogau_2fa_disable_user' ) ) {
        zenlogau_2fa_disable_user( $user_id );
    }
    if ( function_exists( 'zenlogau_passkey_delete_user_data' ) ) {
        zenlogau_passkey_delete_user_data( $user_id );
    }
    do_action( 'zenlogau_admin_reset_user_security', $user_id );
}

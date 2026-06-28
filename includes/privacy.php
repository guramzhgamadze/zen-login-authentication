<?php
/**
 * Zen Login & Authentication – Privacy (GDPR export & erasure)
 *
 * Registers the per-user data this plugin stores with WordPress's built-in
 * privacy tools (Tools → Export/Erase Personal Data) so a data subject's
 * export and erasure requests cover it. The data involved:
 *
 *   - zenlogau_known_devices  (new-device recognition: UA + IP + timestamps)
 *   - zenlogau_passkeys       (WebAuthn credentials — labels/dates exported,
 *                              never the public keys)
 *   - zenlogau_2fa_*          (two-factor enrolment state; secrets/recovery
 *                              codes are erased but never exported)
 *   - zenlogau_google_sub     (the linked Google account identifier)
 *
 * Account *deletion* is already handled by the deleted_user hooks in the 2FA
 * and passkey modules; this file covers the separate privacy-request flow.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

/* -----------------------------------------------------------------------
 * Exporter
 * -------------------------------------------------------------------- */
add_filter( 'wp_privacy_personal_data_exporters', 'zenlogau_register_privacy_exporter' );

function zenlogau_register_privacy_exporter( array $exporters ): array {
    $exporters['zen-login-authentication'] = [
        'exporter_friendly_name' => __( 'Zen Login & Authentication', 'zen-login-authentication' ),
        'callback'               => 'zenlogau_privacy_exporter',
    ];
    return $exporters;
}

/**
 * @param string $email_address
 * @param int    $page
 * @return array{data:array,done:bool}
 */
function zenlogau_privacy_exporter( $email_address, $page = 1 ): array {
    $user = get_user_by( 'email', $email_address );
    $data = [];

    if ( $user instanceof WP_User ) {
        $items = [];

        // Two-factor status (never the secret or recovery codes).
        if ( function_exists( 'zenlogau_2fa_user_enabled' ) ) {
            $items[] = [
                'name'  => __( 'Two-factor authentication', 'zen-login-authentication' ),
                'value' => zenlogau_2fa_user_enabled( (int) $user->ID )
                    ? __( 'Enabled', 'zen-login-authentication' )
                    : __( 'Not enabled', 'zen-login-authentication' ),
            ];
        }

        // Linked Google account identifier.
        $google_sub = (string) get_user_meta( $user->ID, 'zenlogau_google_sub', true );
        if ( '' !== $google_sub ) {
            $items[] = [
                'name'  => __( 'Linked Google account ID', 'zen-login-authentication' ),
                'value' => $google_sub,
            ];
        }

        // Passkeys — labels and dates only (not the credential public keys).
        if ( function_exists( 'zenlogau_get_passkeys' ) ) {
            foreach ( zenlogau_get_passkeys( (int) $user->ID ) as $pk ) {
                $label   = isset( $pk['label'] ) ? (string) $pk['label'] : __( 'Passkey', 'zen-login-authentication' );
                $created = ! empty( $pk['created'] ) ? wp_date( 'Y-m-d', (int) $pk['created'] ) : '';
                $items[] = [
                    'name'  => __( 'Passkey', 'zen-login-authentication' ),
                    'value' => '' !== $created ? $label . ' (' . $created . ')' : $label,
                ];
            }
        }

        // Recognised devices (new-device email feature).
        if ( function_exists( 'zenlogau_get_known_devices' ) ) {
            foreach ( zenlogau_get_known_devices( (int) $user->ID ) as $device ) {
                $parts = [];
                if ( ! empty( $device['ua'] ) ) {
                    $parts[] = (string) $device['ua'];
                }
                if ( ! empty( $device['ip'] ) ) {
                    $parts[] = (string) $device['ip'];
                }
                if ( ! empty( $device['last'] ) ) {
                    $parts[] = wp_date( 'Y-m-d H:i', (int) $device['last'] );
                }
                $items[] = [
                    'name'  => __( 'Recognised device', 'zen-login-authentication' ),
                    'value' => implode( ' — ', $parts ),
                ];
            }
        }

        if ( $items ) {
            $data[] = [
                'group_id'    => 'zenlogau',
                'group_label' => __( 'Login & Authentication', 'zen-login-authentication' ),
                'item_id'     => 'zenlogau-' . $user->ID,
                'data'        => $items,
            ];
        }
    }

    return [ 'data' => $data, 'done' => true ];
}

/* -----------------------------------------------------------------------
 * Eraser
 * -------------------------------------------------------------------- */
add_filter( 'wp_privacy_personal_data_erasers', 'zenlogau_register_privacy_eraser' );

function zenlogau_register_privacy_eraser( array $erasers ): array {
    $erasers['zen-login-authentication'] = [
        'eraser_friendly_name' => __( 'Zen Login & Authentication', 'zen-login-authentication' ),
        'callback'             => 'zenlogau_privacy_eraser',
    ];
    return $erasers;
}

/**
 * @param string $email_address
 * @param int    $page
 * @return array{items_removed:bool,items_retained:bool,messages:array,done:bool}
 */
function zenlogau_privacy_eraser( $email_address, $page = 1 ): array {
    $user    = get_user_by( 'email', $email_address );
    $removed = false;

    if ( $user instanceof WP_User ) {
        $meta_keys = [
            'zenlogau_known_devices',
            'zenlogau_passkeys',
            'zenlogau_2fa_secret',
            'zenlogau_2fa_pending_secret',
            'zenlogau_2fa_enabled',
            'zenlogau_2fa_recovery',
            'zenlogau_2fa_last_step',
            'zenlogau_google_sub',
        ];
        foreach ( $meta_keys as $key ) {
            if ( metadata_exists( 'user', $user->ID, $key ) ) {
                delete_user_meta( $user->ID, $key );
                $removed = true;
            }
        }
    }

    return [
        'items_removed'  => $removed,
        'items_retained' => false,
        'messages'       => [],
        'done'           => true,
    ];
}

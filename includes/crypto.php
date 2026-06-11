<?php
/**
 * Frontend Auth – Secret encryption
 *
 * Encrypts sensitive option values (the Google OAuth client secret) at rest so a
 * database dump alone cannot leak them. The key is derived from the site's
 * wp-config.php salts (AUTH_KEY / SECURE_AUTH_KEY / AUTH_SALT) — it is never
 * stored in the database, so ciphertext in wp_options is useless without the
 * config file.
 *
 * Uses AES-256-GCM (authenticated encryption) via OpenSSL. If OpenSSL is
 * unavailable the functions degrade gracefully to plaintext pass-through so the
 * feature keeps working — the value is simply not encrypted on that host.
 *
 * Stored format: "wpfaenc:" . base64( iv[12] . tag[16] . ciphertext )
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const WPFA_ENC_PREFIX = 'wpfaenc:';

/**
 * 32-byte encryption key derived from the site's wp-config.php salts.
 * Stable for a given install, unique per site, never persisted.
 */
function wpfa_crypto_key(): string {
    $material = ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' )
        . ( defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '' )
        . ( defined( 'AUTH_SALT' ) ? AUTH_SALT : '' );

    // Fallback for installs with default/empty salts — keeps the key deterministic.
    if ( '' === $material ) {
        $material = wp_salt( 'auth' );
    }

    return hash( 'sha256', 'wpfa-crypto|' . $material, true ); // 32 raw bytes
}

/**
 * True if the value is in this plugin's encrypted format.
 */
function wpfa_crypto_is_encrypted( string $value ): bool {
    return str_starts_with( $value, WPFA_ENC_PREFIX );
}

/**
 * Encrypt a string. Returns the "wpfaenc:" envelope, or the original plaintext
 * if encryption is impossible (empty input, or OpenSSL/AES-GCM unavailable).
 */
function wpfa_crypto_encrypt( string $plaintext ): string {
    if ( '' === $plaintext ) {
        return $plaintext;
    }
    if ( ! function_exists( 'openssl_encrypt' )
        || ! in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true ) ) {
        return $plaintext; // graceful degradation
    }

    $iv  = random_bytes( 12 );
    $tag = '';
    $cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', wpfa_crypto_key(), OPENSSL_RAW_DATA, $iv, $tag );
    if ( false === $cipher ) {
        return $plaintext;
    }

    return WPFA_ENC_PREFIX . base64_encode( $iv . $tag . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
}

/**
 * Decrypt a value produced by wpfa_crypto_encrypt(). A value that is not in the
 * encrypted envelope is returned unchanged (legacy plaintext / pass-through).
 * Returns '' if an encrypted value cannot be authenticated/decrypted.
 */
function wpfa_crypto_decrypt( string $value ): string {
    if ( ! wpfa_crypto_is_encrypted( $value ) ) {
        return $value;
    }
    if ( ! function_exists( 'openssl_decrypt' ) ) {
        return '';
    }

    $raw = base64_decode( substr( $value, strlen( WPFA_ENC_PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    if ( false === $raw || strlen( $raw ) < 28 ) {
        return '';
    }

    $iv     = substr( $raw, 0, 12 );
    $tag    = substr( $raw, 12, 16 );
    $cipher = substr( $raw, 28 );

    $plain = openssl_decrypt( $cipher, 'aes-256-gcm', wpfa_crypto_key(), OPENSSL_RAW_DATA, $iv, $tag );
    return false === $plain ? '' : $plain;
}

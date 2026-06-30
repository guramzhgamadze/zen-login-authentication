<?php
/**
 * Zen Login & Authentication – Secret encryption
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
 * KEY ROTATION (v2.2.0): each ciphertext is tagged with a short fingerprint of
 * the key that produced it, so we always decrypt with the right key. Because the
 * key is derived from the wp-config salts, rotating those salts would otherwise
 * make every stored secret permanently undecryptable. To make rotation
 * survivable, a site can supply the *previous* salt material via the
 * 'zenlogau_crypto_fallback_materials' filter; decryption falls back to it, and
 * zenlogau_crypto_maybe_reencrypt() lets callers rewrite the value under the new
 * key. AES-GCM authentication means trying multiple candidate keys is safe — a
 * wrong key fails the tag check and returns false, never wrong plaintext.
 *
 * Stored formats:
 *   v2 (current): "fauthenc2:" . keyId . ":" . base64( iv[12] . tag[16] . cipher )
 *   v1 (legacy):  "fauthenc:"  . base64( iv[12] . tag[16] . cipher )   (no keyId)
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_ENC_PREFIX    = 'fauthenc:';   // legacy v1 envelope (no key id).
const ZENLOGAU_ENC_PREFIX_V2 = 'fauthenc2:';  // current v2 envelope (key id tagged).

/**
 * Derive a 32-byte AES key from arbitrary salt material, using the plugin's
 * stable derivation. The same function produces both the current key and any
 * fallback keys so they are directly comparable.
 */
function zenlogau_crypto_derive_key( string $material ): string {
    if ( '' === $material ) {
        $material = wp_salt( 'auth' );
    }
    return hash( 'sha256', 'fauth-crypto|' . $material, true ); // 32 raw bytes
}

/**
 * The site's current salt material (AUTH_KEY + SECURE_AUTH_KEY + AUTH_SALT).
 */
function zenlogau_crypto_current_material(): string {
    return ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' )
        . ( defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '' )
        . ( defined( 'AUTH_SALT' ) ? AUTH_SALT : '' );
}

/**
 * 32-byte encryption key derived from the site's current wp-config.php salts.
 * Stable for a given install, unique per site, never persisted.
 */
function zenlogau_crypto_key(): string {
    return zenlogau_crypto_derive_key( zenlogau_crypto_current_material() );
}

/**
 * Short, non-reversible fingerprint identifying a key (12 hex chars). Stored in
 * the v2 envelope so decryption can select the matching key without trying all.
 */
function zenlogau_crypto_key_id( string $key ): string {
    return substr( bin2hex( hash( 'sha256', 'fauth-keyid|' . $key, true ) ), 0, 12 );
}

/**
 * Ordered list of candidate keys for decryption: the current key first, then any
 * fallback keys a site has registered for a salt rotation.
 *
 * @return array<string,string> Map of keyId => raw 32-byte key (current key first).
 */
function zenlogau_crypto_candidate_keys(): array {
    $keys    = [];
    $current = zenlogau_crypto_key();
    $keys[ zenlogau_crypto_key_id( $current ) ] = $current;

    /**
     * Filter the list of PREVIOUS salt materials to fall back on after a
     * wp-config salt rotation. Each entry is the old concatenated salt material
     * (old AUTH_KEY . SECURE_AUTH_KEY . AUTH_SALT). Supplying it lets the plugin
     * decrypt secrets that were encrypted before the rotation; they are then
     * re-encrypted under the current key on the next save.
     *
     *   add_filter( 'zenlogau_crypto_fallback_materials', function ( $m ) {
     *       $m[] = 'OLD_AUTH_KEY' . 'OLD_SECURE_AUTH_KEY' . 'OLD_AUTH_SALT';
     *       return $m;
     *   } );
     *
     * @param string[] $materials Previous salt material strings.
     */
    $materials = (array) apply_filters( 'zenlogau_crypto_fallback_materials', [] );
    foreach ( $materials as $material ) {
        $material = (string) $material;
        if ( '' === $material ) {
            continue;
        }
        $key = zenlogau_crypto_derive_key( $material );
        $id  = zenlogau_crypto_key_id( $key );
        if ( ! isset( $keys[ $id ] ) ) {
            $keys[ $id ] = $key;
        }
    }
    return $keys;
}

/**
 * True if the value is in either of this plugin's encrypted formats.
 */
function zenlogau_crypto_is_encrypted( string $value ): bool {
    return str_starts_with( $value, ZENLOGAU_ENC_PREFIX_V2 )
        || str_starts_with( $value, ZENLOGAU_ENC_PREFIX );
}

/**
 * Whether AES-256-GCM is available on this host.
 */
function zenlogau_crypto_available(): bool {
    return function_exists( 'openssl_encrypt' )
        && function_exists( 'openssl_decrypt' )
        && in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true );
}

/**
 * Encrypt a string. Returns the "fauthenc2:" envelope tagged with the current
 * key id, or the original plaintext if encryption is impossible (empty input, or
 * OpenSSL/AES-GCM unavailable).
 */
function zenlogau_crypto_encrypt( string $plaintext ): string {
    if ( '' === $plaintext ) {
        return $plaintext;
    }
    if ( ! zenlogau_crypto_available() ) {
        return $plaintext; // graceful degradation
    }

    $key = zenlogau_crypto_key();
    $iv  = random_bytes( 12 );
    $tag = '';
    $cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
    if ( false === $cipher ) {
        return $plaintext;
    }

    return ZENLOGAU_ENC_PREFIX_V2 . zenlogau_crypto_key_id( $key ) . ':'
        . base64_encode( $iv . $tag . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
}

/**
 * Decrypt a value produced by zenlogau_crypto_encrypt(). A value that is not in
 * an encrypted envelope is returned unchanged (legacy plaintext / pass-through).
 * Returns '' if an encrypted value cannot be authenticated/decrypted with any
 * candidate key.
 */
function zenlogau_crypto_decrypt( string $value ): string {
    if ( ! zenlogau_crypto_is_encrypted( $value ) ) {
        return $value;
    }
    if ( ! function_exists( 'openssl_decrypt' ) ) {
        return '';
    }

    $candidates = zenlogau_crypto_candidate_keys();

    // v2: "fauthenc2:<keyId>:<base64>" — decrypt with the tagged key only.
    if ( str_starts_with( $value, ZENLOGAU_ENC_PREFIX_V2 ) ) {
        $rest  = substr( $value, strlen( ZENLOGAU_ENC_PREFIX_V2 ) );
        $sep   = strpos( $rest, ':' );
        if ( false === $sep ) {
            return '';
        }
        $key_id  = substr( $rest, 0, $sep );
        $payload = substr( $rest, $sep + 1 );
        if ( ! isset( $candidates[ $key_id ] ) ) {
            return '';
        }
        return zenlogau_crypto_open( $payload, $candidates[ $key_id ] );
    }

    // v1 legacy: "fauthenc:<base64>" — no key id, so try every candidate key.
    $payload = substr( $value, strlen( ZENLOGAU_ENC_PREFIX ) );
    foreach ( $candidates as $key ) {
        $plain = zenlogau_crypto_open( $payload, $key );
        if ( '' !== $plain ) {
            return $plain;
        }
    }
    return '';
}

/**
 * Open a base64 "iv.tag.cipher" payload with a specific key. Returns '' on any
 * failure (bad base64, short payload, or failed authentication tag).
 */
function zenlogau_crypto_open( string $payload, string $key ): string {
    $raw = base64_decode( $payload, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
    if ( false === $raw || strlen( $raw ) < 28 ) {
        return '';
    }
    $iv     = substr( $raw, 0, 12 );
    $tag    = substr( $raw, 12, 16 );
    $cipher = substr( $raw, 28 );

    $plain = openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
    return false === $plain ? '' : $plain;
}

/**
 * If a stored value decrypts but was NOT produced by the current key (a legacy
 * v1 envelope, or a v2 envelope tagged with a fallback key), return a fresh
 * ciphertext under the current key so the caller can rewrite it. Returns null if
 * no rewrite is needed or the value cannot be decrypted — so callers can do:
 *
 *   $fresh = zenlogau_crypto_maybe_reencrypt( $stored );
 *   if ( null !== $fresh ) { update_option( $name, $fresh ); }
 */
function zenlogau_crypto_maybe_reencrypt( string $stored ): ?string {
    if ( '' === $stored || ! zenlogau_crypto_is_encrypted( $stored ) || ! zenlogau_crypto_available() ) {
        return null;
    }

    $current_id = zenlogau_crypto_key_id( zenlogau_crypto_key() );

    // Already current-format and current-key? Nothing to do.
    if ( str_starts_with( $stored, ZENLOGAU_ENC_PREFIX_V2 ) ) {
        $rest = substr( $stored, strlen( ZENLOGAU_ENC_PREFIX_V2 ) );
        $sep  = strpos( $rest, ':' );
        if ( false !== $sep && substr( $rest, 0, $sep ) === $current_id ) {
            return null;
        }
    }

    $plain = zenlogau_crypto_decrypt( $stored );
    if ( '' === $plain ) {
        return null; // couldn't decrypt (e.g. no fallback supplied) — leave as-is.
    }
    return zenlogau_crypto_encrypt( $plain );
}

<?php

use PHPUnit\Framework\TestCase;

/**
 * AES-256-GCM round-trip + authentication for the secret store (includes/crypto.php).
 */
final class CryptoTest extends TestCase {

    protected function setUp(): void {
        if ( ! function_exists( 'openssl_encrypt' )
            || ! in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true ) ) {
            $this->markTestSkipped( 'OpenSSL AES-256-GCM not available.' );
        }
    }

    public function test_encrypt_then_decrypt_round_trips(): void {
        $enc = zenlogau_crypto_encrypt( 's3cr3t-value' );
        $this->assertTrue( zenlogau_crypto_is_encrypted( $enc ) );
        $this->assertSame( 's3cr3t-value', zenlogau_crypto_decrypt( $enc ) );
    }

    public function test_empty_input_is_passed_through(): void {
        $this->assertSame( '', zenlogau_crypto_encrypt( '' ) );
    }

    public function test_legacy_plaintext_is_returned_unchanged(): void {
        $this->assertSame( 'legacy-plain', zenlogau_crypto_decrypt( 'legacy-plain' ) );
    }

    public function test_tampered_ciphertext_fails_authentication(): void {
        $enc = zenlogau_crypto_encrypt( 'value' );
        $this->assertSame( '', zenlogau_crypto_decrypt( substr( $enc, 0, -3 ) . 'AAA' ) );
    }

    public function test_each_encryption_uses_a_fresh_iv(): void {
        $this->assertNotSame( zenlogau_crypto_encrypt( 'x' ), zenlogau_crypto_encrypt( 'x' ) );
    }

    public function test_encrypt_produces_v2_envelope(): void {
        $enc = zenlogau_crypto_encrypt( 'value' );
        $this->assertStringStartsWith( ZENLOGAU_ENC_PREFIX_V2, $enc );
    }

    public function test_legacy_v1_envelope_still_decrypts(): void {
        // Build a legacy "fauthenc:" envelope (no key id) under the current key.
        $key    = zenlogau_crypto_key();
        $iv     = random_bytes( 12 );
        $tag    = '';
        $cipher = openssl_encrypt( 'legacy-secret', 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
        $v1     = ZENLOGAU_ENC_PREFIX . base64_encode( $iv . $tag . $cipher );

        $this->assertTrue( zenlogau_crypto_is_encrypted( $v1 ) );
        $this->assertSame( 'legacy-secret', zenlogau_crypto_decrypt( $v1 ) );
    }

    public function test_maybe_reencrypt_upgrades_legacy_to_current(): void {
        $key    = zenlogau_crypto_key();
        $iv     = random_bytes( 12 );
        $tag    = '';
        $cipher = openssl_encrypt( 'rotate-me', 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
        $v1     = ZENLOGAU_ENC_PREFIX . base64_encode( $iv . $tag . $cipher );

        $fresh = zenlogau_crypto_maybe_reencrypt( $v1 );
        $this->assertNotNull( $fresh );
        $this->assertStringStartsWith( ZENLOGAU_ENC_PREFIX_V2, (string) $fresh );
        $this->assertSame( 'rotate-me', zenlogau_crypto_decrypt( (string) $fresh ) );
    }

    public function test_maybe_reencrypt_is_noop_for_current_key(): void {
        $enc = zenlogau_crypto_encrypt( 'already-current' );
        $this->assertNull( zenlogau_crypto_maybe_reencrypt( $enc ) );
    }
}

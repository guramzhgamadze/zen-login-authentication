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
}

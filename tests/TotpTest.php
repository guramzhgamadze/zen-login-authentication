<?php

use PHPUnit\Framework\TestCase;

/**
 * RFC 6238 / RFC 4648 conformance for the TOTP core (includes/totp.php).
 */
final class TotpTest extends TestCase {

    /** The RFC 6238 Appendix B reference secret ("12345678901234567890"). */
    private string $secret;

    protected function setUp(): void {
        $this->secret = zenlogau_base32_encode( '12345678901234567890' );
    }

    public function test_base32_encode_matches_known_value(): void {
        $this->assertSame( 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $this->secret );
    }

    public function test_base32_round_trips(): void {
        $this->assertSame( '12345678901234567890', zenlogau_base32_decode( $this->secret ) );
    }

    public function test_base32_decode_ignores_spaces_and_case(): void {
        $this->assertSame( '12345678901234567890', zenlogau_base32_decode( 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq' ) );
    }

    /**
     * RFC 6238 Appendix B reference codes (SHA-1, 8 digits).
     *
     * @dataProvider rfc6238_vectors
     */
    public function test_rfc6238_reference_vectors( int $timestamp, string $expected ): void {
        $this->assertSame( $expected, zenlogau_totp_code( $this->secret, $timestamp, 8 ) );
    }

    public function rfc6238_vectors(): array {
        return [
            [ 59, '94287082' ],
            [ 1111111109, '07081804' ],
            [ 1111111111, '14050471' ],
            [ 1234567890, '89005924' ],
            [ 2000000000, '69279037' ],
            [ 20000000000, '65353130' ],
        ];
    }

    public function test_verify_accepts_the_current_code(): void {
        $code = zenlogau_totp_code( $this->secret, time() );
        $this->assertTrue( zenlogau_totp_verify( $this->secret, $code ) );
    }

    public function test_verify_rejects_a_wrong_code(): void {
        // Use a fixed timestamp far from now so the real code can never collide.
        $this->assertFalse( zenlogau_totp_verify( $this->secret, '000000', 0, 59 ) );
    }

    public function test_verify_rejects_non_numeric_input(): void {
        $this->assertFalse( zenlogau_totp_verify( $this->secret, 'abcdef' ) );
    }

    public function test_verify_accepts_one_step_of_skew(): void {
        $now  = time();
        $prev = zenlogau_totp_code( $this->secret, $now - ZENLOGAU_TOTP_PERIOD );
        $this->assertTrue( zenlogau_totp_verify( $this->secret, $prev, 1, $now ) );
    }

    public function test_verify_rejects_two_steps_of_skew(): void {
        $now = time();
        $old = zenlogau_totp_code( $this->secret, $now - ( 2 * ZENLOGAU_TOTP_PERIOD ) );
        $this->assertFalse( zenlogau_totp_verify( $this->secret, $old, 1, $now ) );
    }
}

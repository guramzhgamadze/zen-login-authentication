<?php
/**
 * Zen Login & Authentication – TOTP core (RFC 6238 / RFC 4648)
 *
 * Pure, dependency-free helpers for time-based one-time passwords: Base32
 * encode/decode, the HMAC-SHA1 TOTP algorithm, constant-time verification with a
 * small clock-skew window, secret generation, and the otpauth:// provisioning
 * URI used to build the enrollment QR. No WordPress calls and no hooks here, so
 * this file is unit-testable in isolation; storage, enrollment, the login
 * challenge, and the UI live in includes/two-factor.php.
 *
 * @package Frontend_Auth
 */

defined( 'ABSPATH' ) || exit;

const ZENLOGAU_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ZENLOGAU_TOTP_DIGITS     = 6;
const ZENLOGAU_TOTP_PERIOD     = 30;

/**
 * RFC 4648 Base32 encode (no padding). Used to present the shared secret.
 */
function zenlogau_base32_encode( string $data ): string {
    if ( '' === $data ) {
        return '';
    }
    $buffer = 0;
    $bits   = 0;
    $out    = '';
    $len    = strlen( $data );
    for ( $i = 0; $i < $len; $i++ ) {
        $buffer = ( $buffer << 8 ) | ( ord( $data[ $i ] ) & 0xFF );
        $bits  += 8;
        while ( $bits >= 5 ) {
            $bits -= 5;
            $out  .= ZENLOGAU_BASE32_ALPHABET[ ( $buffer >> $bits ) & 0x1F ];
        }
    }
    if ( $bits > 0 ) {
        $out .= ZENLOGAU_BASE32_ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 0x1F ];
    }
    return $out;
}

/**
 * RFC 4648 Base32 decode. Case-insensitive; spaces, padding, and any non-
 * alphabet character are ignored (authenticator apps display the key in groups).
 */
function zenlogau_base32_decode( string $b32 ): string {
    $b32    = strtoupper( $b32 );
    $buffer = 0;
    $bits   = 0;
    $out    = '';
    $len    = strlen( $b32 );
    for ( $i = 0; $i < $len; $i++ ) {
        $val = strpos( ZENLOGAU_BASE32_ALPHABET, $b32[ $i ] );
        if ( false === $val ) {
            continue; // skip '=', spaces, etc.
        }
        $buffer = ( $buffer << 5 ) | $val;
        $bits  += 5;
        if ( $bits >= 8 ) {
            $bits -= 8;
            $out  .= chr( ( $buffer >> $bits ) & 0xFF );
        }
    }
    return $out;
}

/**
 * Compute the TOTP code for a given Base32 secret and UNIX timestamp.
 *
 * @return string Zero-padded $digits-length code.
 */
function zenlogau_totp_code( string $secret_base32, int $timestamp, int $digits = ZENLOGAU_TOTP_DIGITS, int $period = ZENLOGAU_TOTP_PERIOD ): string {
    $key     = zenlogau_base32_decode( $secret_base32 );
    $counter = (int) floor( $timestamp / $period );

    // 8-byte big-endian counter (high 32 bits are 0 for all realistic dates).
    $bin  = pack( 'N*', 0, $counter );
    $hash = hash_hmac( 'sha1', $bin, $key, true );

    // Dynamic truncation (RFC 4226 §5.3).
    $offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
    $value  = ( unpack( 'N', substr( $hash, $offset, 4 ) )[1] ) & 0x7FFFFFFF;

    return str_pad( (string) ( $value % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
}

/**
 * Constant-time verification of a submitted code against the secret, allowing
 * ±$window time steps of clock skew (default ±1 = ±30s).
 */
function zenlogau_totp_verify( string $secret_base32, string $code, int $window = 1, ?int $timestamp = null, int $digits = ZENLOGAU_TOTP_DIGITS, int $period = ZENLOGAU_TOTP_PERIOD ): bool {
    $code = preg_replace( '/\D/', '', $code );
    if ( null === $code || strlen( $code ) !== $digits ) {
        return false;
    }
    $timestamp = $timestamp ?? time();
    for ( $i = -$window; $i <= $window; $i++ ) {
        $candidate = zenlogau_totp_code( $secret_base32, $timestamp + ( $i * $period ), $digits, $period );
        if ( hash_equals( $candidate, $code ) ) {
            return true;
        }
    }
    return false;
}

/**
 * Generate a new random Base32 secret (default 20 bytes = 160 bits, the RFC 6238
 * recommendation for SHA-1).
 */
function zenlogau_totp_generate_secret( int $bytes = 20 ): string {
    return zenlogau_base32_encode( random_bytes( $bytes ) );
}

/**
 * Build the otpauth:// provisioning URI an authenticator app reads from the QR.
 */
function zenlogau_totp_provisioning_uri( string $secret_base32, string $account_label, string $issuer ): string {
    $label  = rawurlencode( $issuer ) . ':' . rawurlencode( $account_label );
    $params = http_build_query(
        [
            'secret'    => $secret_base32,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => ZENLOGAU_TOTP_DIGITS,
            'period'    => ZENLOGAU_TOTP_PERIOD,
        ],
        '',
        '&',
        PHP_QUERY_RFC3986
    );
    return 'otpauth://totp/' . $label . '?' . $params;
}

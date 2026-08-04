<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use InvalidArgumentException;

/**
 * RFC 4226 (HOTP) and RFC 6238 (TOTP), plus the RFC 4648 base32 and the
 * otpauth:// provisioning URI that authenticator apps expect.
 *
 * Deliberately dependency-free and stateless: this class is the one piece of
 * the module that has to interoperate byte-for-byte with Google Authenticator,
 * Aegis, 1Password and friends, so it is pinned to the published RFC test
 * vectors in test/TotpTest.php rather than to anything Omeka-specific.
 *
 * It knows nothing about users, replay or storage — see TotpManager for that.
 */
class Totp
{
    /** RFC 4648 §6 base32 alphabet. Note the absent 0, 1 and 8. */
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Seconds per step. 30 is the de-facto standard every app assumes. */
    const PERIOD = 30;

    const DIGITS = 6;

    const ALGORITHM = 'sha1';

    /**
     * 160 bits, the shared-secret length recommended by RFC 4226 §4 R6.
     */
    const SECRET_BYTES = 20;

    /**
     * Generate a new shared secret, base32-encoded and ready to hand to an
     * authenticator app.
     */
    public function generateSecret(int $bytes = self::SECRET_BYTES): string
    {
        if ($bytes < 16) {
            throw new InvalidArgumentException('A TOTP secret must be at least 128 bits.');
        }
        return $this->base32Encode(random_bytes($bytes));
    }

    /**
     * Encode raw bytes as unpadded base32.
     */
    public function base32Encode(string $raw): string
    {
        if ('' === $raw) {
            return '';
        }

        $encoded = '';
        $buffer = 0;
        $bits = 0;

        for ($i = 0, $length = strlen($raw); $i < $length; $i++) {
            $buffer = ($buffer << 8) | ord($raw[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $encoded .= self::ALPHABET[($buffer >> $bits) & 0x1F];
                $buffer &= (1 << $bits) - 1;
            }
        }

        // Left-align whatever is left over into a final character.
        if ($bits > 0) {
            $encoded .= self::ALPHABET[($buffer << (5 - $bits)) & 0x1F];
        }

        return $encoded;
    }

    /**
     * Decode base32 back to raw bytes.
     *
     * Tolerant of what users actually paste: lowercase, padding and internal
     * whitespace are all accepted, since authenticator apps and password
     * managers each format the secret differently.
     *
     * @throws InvalidArgumentException on any character outside the alphabet.
     */
    public function base32Decode(string $base32): string
    {
        $clean = strtoupper((string) preg_replace('/[\s=]+/', '', $base32));
        if ('' === $clean) {
            return '';
        }

        $decoded = '';
        $buffer = 0;
        $bits = 0;

        for ($i = 0, $length = strlen($clean); $i < $length; $i++) {
            $position = strpos(self::ALPHABET, $clean[$i]);
            if (false === $position) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid base32 character "%s" in secret.',
                    $clean[$i]
                ));
            }
            $buffer = ($buffer << 5) | $position;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $decoded .= chr(($buffer >> $bits) & 0xFF);
                $buffer &= (1 << $bits) - 1;
            }
        }

        // Any trailing bits are the encoder's zero padding and are discarded.
        return $decoded;
    }

    /**
     * RFC 4226 HOTP: an HMAC over the counter, dynamically truncated.
     *
     * @param string $rawSecret The shared secret as raw bytes, not base32.
     */
    public function hotp(string $rawSecret, int $counter, int $digits = self::DIGITS): string
    {
        // 'J' is an unsigned 64-bit big-endian integer: the 8-byte counter.
        $hash = hash_hmac(self::ALGORITHM, pack('J', $counter), $rawSecret, true);

        // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte
        // selects where in the digest to read the 31-bit value from.
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad(
            (string) ($binary % (10 ** $digits)),
            $digits,
            '0',
            STR_PAD_LEFT
        );
    }

    /**
     * The code an authenticator app shows at a given moment.
     *
     * @param string $base32Secret The shared secret as base32.
     */
    public function totpAt(
        string $base32Secret,
        int $time,
        int $digits = self::DIGITS,
        int $period = self::PERIOD
    ): string {
        return $this->hotp($this->base32Decode($base32Secret), intdiv($time, $period), $digits);
    }

    /**
     * Check a user-supplied code against the secret.
     *
     * Returns the *counter* that matched rather than a boolean, because the
     * caller must persist it to reject replays: without that, a code observed
     * over someone's shoulder stays usable for the rest of its 30-second step.
     * See TotpManager::verify().
     *
     * @param int $window How many steps either side of now to accept, to
     *                    absorb clock skew between server and phone.
     * @return int|null The matching counter, or null if nothing matched.
     */
    public function verify(
        string $base32Secret,
        string $code,
        int $window = 1,
        ?int $time = null,
        int $digits = self::DIGITS,
        int $period = self::PERIOD
    ): ?int {
        // Apps and password managers group the digits for legibility
        // ("050 471"); accept what the user actually pasted.
        $candidate = (string) preg_replace('/\s+/', '', $code);
        if (!preg_match('/^[0-9]{' . $digits . '}$/', $candidate)) {
            return null;
        }

        $time ??= time();
        $current = intdiv($time, $period);
        $rawSecret = $this->base32Decode($base32Secret);

        $match = null;
        for ($offset = -$window; $offset <= $window; $offset++) {
            $counter = $current + $offset;
            // hash_equals, not ===, so the comparison cannot be timed. The loop
            // deliberately runs to completion for the same reason.
            if (hash_equals($this->hotp($rawSecret, $counter, $digits), $candidate)) {
                $match = $counter;
            }
        }

        return $match;
    }

    /**
     * The otpauth:// URI encoded into the enrollment QR code.
     *
     * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     */
    public function provisioningUri(
        string $base32Secret,
        string $accountName,
        string $issuer,
        int $digits = self::DIGITS,
        int $period = self::PERIOD
    ): string {
        // Both halves of the label are percent-encoded so that a ":" or "/" in
        // the site title cannot make an app mis-split issuer from account.
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);

        $query = http_build_query([
            'secret' => $base32Secret,
            'issuer' => $issuer,
            'algorithm' => strtoupper(self::ALGORITHM),
            'digits' => $digits,
            'period' => $period,
        ], '', '&', PHP_QUERY_RFC3986);

        return sprintf('otpauth://totp/%s?%s', $label, $query);
    }
}

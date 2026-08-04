<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\Totp;

/**
 * The crypto core is the one part of this module that must be provably correct:
 * a subtly wrong HOTP implementation still "works" against itself while
 * rejecting every real authenticator app. So it is pinned to the published
 * RFC test vectors rather than to its own output.
 */
class TotpTest extends TestCase
{
    /** The shared secret used by both RFCs: ASCII "12345678901234567890". */
    const RFC_SECRET_RAW = '12345678901234567890';
    const RFC_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    private Totp $totp;

    protected function setUp(): void
    {
        $this->totp = new Totp();
    }

    // ---------------------------------------------------------------- base32

    public function testBase32EncodesTheRfcSecret(): void
    {
        $this->assertSame(self::RFC_SECRET_B32, $this->totp->base32Encode(self::RFC_SECRET_RAW));
    }

    public function testBase32DecodesTheRfcSecret(): void
    {
        $this->assertSame(self::RFC_SECRET_RAW, $this->totp->base32Decode(self::RFC_SECRET_B32));
    }

    /**
     * RFC 4648 section 10 vectors — these exercise every remainder of the
     * 5-bytes-to-8-characters grouping, which is where hand-rolled base32
     * implementations usually break.
     *
     * @dataProvider base32Vectors
     */
    public function testBase32RoundTripsRfc4648Vectors(string $raw, string $encoded): void
    {
        $this->assertSame($encoded, $this->totp->base32Encode($raw), 'encode');
        $this->assertSame($raw, $this->totp->base32Decode($encoded), 'decode');
    }

    public static function base32Vectors(): array
    {
        return [
            'empty'  => ['', ''],
            'f'      => ['f', 'MY'],
            'fo'     => ['fo', 'MZXQ'],
            'foo'    => ['foo', 'MZXW6'],
            'foob'   => ['foob', 'MZXW6YQ'],
            'fooba'  => ['fooba', 'MZXW6YTB'],
            'foobar' => ['foobar', 'MZXW6YTBOI'],
        ];
    }

    public function testBase32DecodeToleratesPaddingWhitespaceAndLowercase(): void
    {
        $this->assertSame('foobar', $this->totp->base32Decode('mzxw 6ytb oi======'));
    }

    public function testBase32DecodeRejectsCharactersOutsideTheAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // 0, 1 and 8 are deliberately absent from the RFC 4648 base32 alphabet.
        $this->totp->base32Decode('MZXW6YTB01');
    }

    public function testRandomSecretsRoundTrip(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $raw = random_bytes(random_int(1, 40));
            $this->assertSame($raw, $this->totp->base32Decode($this->totp->base32Encode($raw)));
        }
    }

    public function testGenerateSecretProduces160BitsOfBase32(): void
    {
        $secret = $this->totp->generateSecret();
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $secret);
        $this->assertSame(20, strlen($this->totp->base32Decode($secret)), '160 bits per RFC 4226 §4 R6');
        $this->assertNotSame($secret, $this->totp->generateSecret(), 'secrets must not repeat');
    }

    // ------------------------------------------------------------------ HOTP

    /**
     * RFC 4226 Appendix D — "Test Values".
     *
     * @dataProvider hotpVectors
     */
    public function testHotpMatchesRfc4226AppendixD(int $counter, string $expected): void
    {
        $this->assertSame($expected, $this->totp->hotp(self::RFC_SECRET_RAW, $counter));
    }

    public static function hotpVectors(): array
    {
        return [
            [0, '755224'],
            [1, '287082'],
            [2, '359152'],
            [3, '969429'],
            [4, '338314'],
            [5, '254676'],
            [6, '287922'],
            [7, '162583'],
            [8, '399871'],
            [9, '520489'],
        ];
    }

    public function testHotpAlwaysReturnsZeroPaddedDigits(): void
    {
        // Counter 40 yields a value that needs left-padding to six digits.
        $code = $this->totp->hotp(self::RFC_SECRET_RAW, 40);
        $this->assertSame(6, strlen($code));
        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $code);
    }

    // ------------------------------------------------------------------ TOTP

    /**
     * RFC 6238 Appendix B, the SHA-1 rows. The RFC prints eight digits; a
     * six-digit authenticator shows the last six of the same value.
     *
     * @dataProvider totpVectors
     */
    public function testTotpMatchesRfc6238AppendixB(int $time, string $eightDigits): void
    {
        $this->assertSame(
            $eightDigits,
            $this->totp->totpAt(self::RFC_SECRET_B32, $time, 8),
            '8-digit'
        );
        $this->assertSame(
            substr($eightDigits, -6),
            $this->totp->totpAt(self::RFC_SECRET_B32, $time, 6),
            '6-digit'
        );
    }

    public static function totpVectors(): array
    {
        return [
            [59, '94287082'],
            [1111111109, '07081804'],
            [1111111111, '14050471'],
            [1234567890, '89005924'],
            [2000000000, '69279037'],
            [20000000000, '65353130'],
        ];
    }

    // ---------------------------------------------------------------- verify

    public function testVerifyAcceptsTheCurrentCodeAndReturnsItsCounter(): void
    {
        $time = 1111111111;
        $counter = $this->totp->verify(self::RFC_SECRET_B32, '050471', 1, $time);
        $this->assertSame(intdiv($time, 30), $counter);
    }

    public function testVerifyAcceptsThePreviousAndNextStepWithinTheWindow(): void
    {
        $time = 1111111111;
        $step = intdiv($time, 30);

        $previous = $this->totp->totpAt(self::RFC_SECRET_B32, $time - 30);
        $next = $this->totp->totpAt(self::RFC_SECRET_B32, $time + 30);

        $this->assertSame($step - 1, $this->totp->verify(self::RFC_SECRET_B32, $previous, 1, $time));
        $this->assertSame($step + 1, $this->totp->verify(self::RFC_SECRET_B32, $next, 1, $time));
    }

    public function testVerifyRejectsCodesOutsideTheWindow(): void
    {
        $time = 1111111111;
        $twoStepsAgo = $this->totp->totpAt(self::RFC_SECRET_B32, $time - 60);
        $this->assertNull($this->totp->verify(self::RFC_SECRET_B32, $twoStepsAgo, 1, $time));
    }

    public function testVerifyWithZeroWindowAcceptsOnlyTheExactStep(): void
    {
        $time = 1111111111;
        $previous = $this->totp->totpAt(self::RFC_SECRET_B32, $time - 30);
        $this->assertNull($this->totp->verify(self::RFC_SECRET_B32, $previous, 0, $time));
        $this->assertIsInt($this->totp->verify(self::RFC_SECRET_B32, '050471', 0, $time));
    }

    public function testVerifyRejectsWrongAndMalformedCodes(): void
    {
        $time = 1111111111;
        foreach (['000000', '', '05047', '0504711', 'abcdef', '05047a', '05-0471'] as $code) {
            $this->assertNull(
                $this->totp->verify(self::RFC_SECRET_B32, $code, 1, $time),
                sprintf('code %s must be rejected', var_export($code, true))
            );
        }
    }

    public function testVerifyIgnoresSpacesUsersPasteFromAuthenticatorApps(): void
    {
        // Several apps render the code as "050 471"; users paste it verbatim.
        $this->assertIsInt($this->totp->verify(self::RFC_SECRET_B32, '050 471', 1, 1111111111));
    }

    // ------------------------------------------------------- provisioning URI

    public function testProvisioningUriIsScannableAndCarriesEveryParameter(): void
    {
        $uri = $this->totp->provisioningUri(self::RFC_SECRET_B32, 'bob@example.org', 'Gouda Tijdmachine');

        $this->assertStringStartsWith('otpauth://totp/', $uri);

        $parts = parse_url($uri);
        parse_str($parts['query'], $query);

        $this->assertSame(self::RFC_SECRET_B32, $query['secret']);
        $this->assertSame('Gouda Tijdmachine', $query['issuer']);
        $this->assertSame('SHA1', $query['algorithm']);
        $this->assertSame('6', $query['digits']);
        $this->assertSame('30', $query['period']);

        // The label must be "Issuer:account", each part percent-encoded.
        $this->assertSame(
            'Gouda%20Tijdmachine:bob%40example.org',
            ltrim($parts['path'] ?? '', '/')
        );
    }

    public function testProvisioningUriEscapesSeparatorsInTheIssuer(): void
    {
        $uri = $this->totp->provisioningUri(self::RFC_SECRET_B32, 'a@b.org', 'Ac / Me: Inc');
        // A raw ":" or "/" in the label would make apps mis-split issuer from account.
        $label = ltrim(parse_url($uri, PHP_URL_PATH) ?? '', '/');
        $this->assertSame(1, substr_count($label, ':'), 'exactly one unescaped separator');
        $this->assertStringNotContainsString(' ', $label);
    }
}

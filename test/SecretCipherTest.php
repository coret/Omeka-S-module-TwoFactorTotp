<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\SecretCipher;

/**
 * The TOTP secret is the one value in the module that is stored recoverably —
 * the server has to compute HMACs with it — and the one that cannot be rotated
 * without the user re-enrolling. Read access to the database alone therefore
 * bought a permanent second-factor bypass for every enrolled account.
 *
 * Encrypting it moves that from "read the database" to "read the database and
 * the filesystem", which is the whole point: the key lives in Omeka's
 * config/local.config.php, not in a table.
 *
 * Two properties matter as much as the encryption itself: with no key
 * configured nothing changes, and a value written before a key was configured
 * still reads back. Otherwise turning this on is a lockout.
 */
class SecretCipherTest extends TestCase
{
    private const KEY = 'a-long-enough-passphrase-from-local-config';

    private const PLAINTEXT = 'JBSWY3DPEHPK3PXP';

    public function testWithNoKeyItIsOffAndChangesNothing(): void
    {
        $cipher = new SecretCipher(null);

        $this->assertFalse($cipher->isEnabled());
        $this->assertSame(self::PLAINTEXT, $cipher->encrypt(self::PLAINTEXT));
        $this->assertSame(self::PLAINTEXT, $cipher->decrypt(self::PLAINTEXT));
    }

    public function testAnEmptyKeyCountsAsNoKey(): void
    {
        $this->assertFalse((new SecretCipher('   '))->isEnabled());
    }

    public function testItRoundTrips(): void
    {
        $cipher = new SecretCipher(self::KEY);

        $this->assertSame(self::PLAINTEXT, $cipher->decrypt($cipher->encrypt(self::PLAINTEXT)));
    }

    public function testTheStoredValueDoesNotContainTheSecret(): void
    {
        $stored = (new SecretCipher(self::KEY))->encrypt(self::PLAINTEXT);

        $this->assertStringNotContainsString(self::PLAINTEXT, $stored);
        $this->assertTrue(SecretCipher::isEncrypted($stored));
    }

    /**
     * A fresh nonce every time, so two accounts with the same secret — or one
     * account re-enrolling — do not produce the same ciphertext.
     */
    public function testTheSamePlaintextEncryptsDifferentlyEachTime(): void
    {
        $cipher = new SecretCipher(self::KEY);

        $this->assertNotSame($cipher->encrypt(self::PLAINTEXT), $cipher->encrypt(self::PLAINTEXT));
    }

    /**
     * The migration path. Rows written before a key was configured are plain
     * base32 and have to keep working, or turning encryption on locks everyone
     * out of their own accounts.
     */
    public function testALegacyPlaintextValueStillReadsBack(): void
    {
        $this->assertSame(self::PLAINTEXT, (new SecretCipher(self::KEY))->decrypt(self::PLAINTEXT));
        $this->assertFalse(SecretCipher::isEncrypted(self::PLAINTEXT));
    }

    public function testTheWrongKeyIsRefusedRatherThanReturningRubbish(): void
    {
        $stored = (new SecretCipher(self::KEY))->encrypt(self::PLAINTEXT);

        $this->expectException(\RuntimeException::class);
        (new SecretCipher('a-different-key'))->decrypt($stored);
    }

    /**
     * Authenticated encryption, so a tampered row is an error rather than a
     * secret somebody else chose.
     */
    public function testTamperingIsDetected(): void
    {
        $cipher = new SecretCipher(self::KEY);
        $stored = $cipher->encrypt(self::PLAINTEXT);

        // Flip a bit in the payload, leaving the prefix intact.
        $prefix = substr($stored, 0, 7);
        $payload = base64_decode(substr($stored, 7), true);
        $payload[strlen($payload) - 1] = chr(ord($payload[strlen($payload) - 1]) ^ 0x01);

        $this->expectException(\RuntimeException::class);
        $cipher->decrypt($prefix . base64_encode($payload));
    }

    public function testDecryptingWithNoKeyWhenTheValueIsEncryptedIsAnError(): void
    {
        $stored = (new SecretCipher(self::KEY))->encrypt(self::PLAINTEXT);

        $this->expectException(\RuntimeException::class);
        (new SecretCipher(null))->decrypt($stored);
    }

    /**
     * The column is VARCHAR(255); a value that does not fit is silently
     * truncated by MySQL in non-strict mode, which would be unrecoverable.
     */
    public function testTheStoredValueFitsTheColumn(): void
    {
        $stored = (new SecretCipher(self::KEY))->encrypt(str_repeat('A', 64));

        $this->assertLessThanOrEqual(255, strlen($stored));
    }

    // ------------------------------------------------------------- rotation

    private const OLD_KEY = 'the-key-that-is-being-retired';

    private const NEW_KEY = 'the-key-that-replaces-it';

    public function testEncryptionUsesTheFirstKey(): void
    {
        $stored = (new SecretCipher([self::NEW_KEY, self::OLD_KEY]))->encrypt(self::PLAINTEXT);

        $this->assertSame(self::PLAINTEXT, (new SecretCipher(self::NEW_KEY))->decrypt($stored));
    }

    /**
     * The point of keeping retired keys: rows written under the old one still
     * read while their owners have not logged in yet.
     */
    public function testARetiredKeyStillDecrypts(): void
    {
        $stored = (new SecretCipher(self::OLD_KEY))->encrypt(self::PLAINTEXT);

        $rotated = new SecretCipher([self::NEW_KEY, self::OLD_KEY]);

        $this->assertSame(self::PLAINTEXT, $rotated->decrypt($stored));
    }

    public function testAValueUnderThePrimaryKeyNeedsNoRewrite(): void
    {
        $cipher = new SecretCipher([self::NEW_KEY, self::OLD_KEY]);

        $this->assertFalse($cipher->needsRewrite($cipher->encrypt(self::PLAINTEXT)));
    }

    public function testAValueUnderARetiredKeyNeedsRewriting(): void
    {
        $stored = (new SecretCipher(self::OLD_KEY))->encrypt(self::PLAINTEXT);

        $this->assertTrue((new SecretCipher([self::NEW_KEY, self::OLD_KEY]))->needsRewrite($stored));
    }

    public function testLegacyPlaintextNeedsRewritingOnceAKeyExists(): void
    {
        $this->assertTrue((new SecretCipher(self::KEY))->needsRewrite(self::PLAINTEXT));
    }

    public function testNothingNeedsRewritingWhenEncryptionIsOff(): void
    {
        $this->assertFalse((new SecretCipher(null))->needsRewrite(self::PLAINTEXT));
    }

    /**
     * The whole point, end to end: after a rotation has worked through, the
     * retired key can be dropped from the config and the row still reads.
     * Without this, setting a key is a decision you can never revise.
     */
    public function testARotationCanActuallyBeCompleted(): void
    {
        // Written under the old key.
        $stored = (new SecretCipher(self::OLD_KEY))->encrypt(self::PLAINTEXT);

        // New key added in front, old one kept. The user logs in: the value
        // reads, and is flagged for rewriting.
        $rotating = new SecretCipher([self::NEW_KEY, self::OLD_KEY]);
        $plain = $rotating->decrypt($stored);
        $this->assertTrue($rotating->needsRewrite($stored));
        $rewritten = $rotating->encrypt($plain);

        // The old key can now be retired for good.
        $this->assertSame(self::PLAINTEXT, (new SecretCipher(self::NEW_KEY))->decrypt($rewritten));
    }

    public function testAnEmptyKeyListCountsAsNoKey(): void
    {
        $this->assertFalse((new SecretCipher([]))->isEnabled());
        $this->assertFalse((new SecretCipher(['', '  ']))->isEnabled());
    }
}

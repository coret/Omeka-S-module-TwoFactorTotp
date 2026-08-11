<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use RuntimeException;

/**
 * Encryption at rest for the TOTP shared secret.
 *
 * Everything else the module keeps is already protected: recovery codes are
 * password_hash'ed, device validators are SHA-256'd, only public keys are
 * stored for passkeys. The TOTP secret was the exception, and it is the worst
 * one to leave — the server must be able to compute HMACs with it, so it
 * cannot be hashed, and it cannot be rotated without the user re-enrolling.
 * Read access to the database alone was therefore a permanent second-factor
 * bypass for every enrolled account.
 *
 * The key lives in Omeka's config/local.config.php, never in the database:
 *
 *     'twofactortotp' => [
 *         'encryption_key' => 'a long random string',
 *         // While rotating, the key(s) this is replacing:
 *         'previous_encryption_keys' => ['the old one'],
 *     ],
 *
 * Keeping it in a settings row would be theatre — the same SELECT that leaks
 * the secrets would leak the key with them. Putting it in a file the web user
 * reads but the database does not means the two have to be compromised
 * separately.
 *
 * There is deliberately no default key. A key shipped in the source would be
 * known to everyone who can read the repository, so it would turn "stored in
 * clear, and an audit will say so" into "looks protected, is not" — which is
 * worse, because it silences the check that would otherwise notice.
 *
 * Opt-in, and every transition is survivable:
 *
 *   - With no key configured this class is a no-op, so nothing changes for an
 *     install that has not set one.
 *   - decrypt() passes an unencrypted value straight through, so rows written
 *     before a key was configured keep working and get re-encrypted the next
 *     time their owner logs in. Without that, turning encryption on would lock
 *     out everybody who had already enrolled.
 *   - Retired keys listed in previous_encryption_keys still decrypt, and
 *     needsRewrite() reports the rows still under them, so a key can be
 *     changed. Rows convert as their owners log in; once they all have, the old
 *     key can be dropped. Without that, setting a key would be a decision that
 *     could never be revised.
 *   - What is *not* survivable is losing every key that a row was written
 *     under. That is the trade, and it is why decrypt() raises rather than
 *     quietly returning something that would make every code look wrong.
 *
 * AES-256-GCM: authenticated, so a tampered row is an error rather than a
 * secret of somebody else's choosing, and ext-openssl is already a declared
 * requirement of the module.
 */
class SecretCipher
{
    /**
     * Marks a stored value as encrypted, and carries the format version so a
     * later change of cipher can still read what this one wrote.
     */
    const PREFIX = 'enc:v1:';

    const CIPHER = 'aes-256-gcm';

    const IV_BYTES = 12;

    const TAG_BYTES = 16;

    /** Domain separation, so this key is only ever this key. */
    const HKDF_INFO = 'twofactortotp:totp-secret:v1';

    /**
     * Derived 32-byte keys. The first is the one anything new is encrypted
     * with; the rest are retired keys kept only so that rows written under them
     * still read. Empty when no key is configured.
     *
     * @var string[]
     */
    protected array $keys = [];

    /**
     * @param string|string[]|null $keyMaterial Whatever the operator put in
     *        config/local.config.php. Any length; it is stretched, not used
     *        raw. A list means a rotation is in progress: current key first.
     */
    public function __construct($keyMaterial)
    {
        foreach (is_array($keyMaterial) ? $keyMaterial : [$keyMaterial] as $material) {
            $material = is_string($material) ? trim($material) : '';
            if ('' !== $material) {
                $this->keys[] = hash_hkdf('sha256', $material, 32, self::HKDF_INFO);
            }
        }
    }

    /**
     * Build from Omeka's merged application config.
     *
     * A named constructor rather than only a service factory, because the one
     * other caller — Module::upgrade() — cannot use the container: raising the
     * version puts the module into `needs_upgrade`, and Omeka merges the config
     * of active modules only, so none of this module's services are registered
     * at the moment the migration runs. Asking for one there threw, aborted the
     * upgrade half-way, and left the module stuck out of service.
     *
     * @param array $applicationConfig What 'Config' resolves to. Always present,
     *        because it is core's, not ours.
     */
    public static function fromConfig(array $applicationConfig): self
    {
        $moduleConfig = $applicationConfig['twofactortotp'] ?? [];

        $keys = [];
        if (isset($moduleConfig['encryption_key']) && is_string($moduleConfig['encryption_key'])) {
            $keys[] = $moduleConfig['encryption_key'];
        }
        foreach ((array) ($moduleConfig['previous_encryption_keys'] ?? []) as $previous) {
            if (is_string($previous)) {
                $keys[] = $previous;
            }
        }

        return new self($keys);
    }

    public function isEnabled(): bool
    {
        return [] !== $this->keys;
    }

    /**
     * Should this stored value be written back?
     *
     * True for a row that predates encryption, and for one still under a
     * retired key. Callers rewrite it the next time they hold the plaintext
     * anyway — after a successful verification — which is what lets a key
     * rotation finish without a maintenance window: rows convert as their
     * owners log in, and the old key can be dropped once they all have.
     */
    public function needsRewrite(string $stored): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }
        if (!self::isEncrypted($stored)) {
            return true;
        }

        return 0 !== $this->findKeyIndex($stored);
    }

    public static function isEncrypted(string $stored): bool
    {
        return 0 === strncmp($stored, self::PREFIX, strlen(self::PREFIX));
    }

    /**
     * With no key configured this returns the plaintext unchanged, so the
     * caller never has to ask whether encryption is on.
     */
    public function encrypt(string $plaintext): string
    {
        if (!$this->isEnabled()) {
            return $plaintext;
        }

        $iv = random_bytes(self::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->keys[0],
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_BYTES
        );

        if (false === $ciphertext) {
            throw new RuntimeException('TwoFactorTotp: could not encrypt the TOTP secret.');
        }

        return self::PREFIX . base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * @throws RuntimeException when a value is encrypted but cannot be read —
     *         a missing, changed or wrong key, or a tampered row.
     *
     * Deliberately loud. The alternative, returning something unusable, shows
     * up as every code being rejected for every user, which is the same outage
     * with none of the explanation.
     */
    public function decrypt(string $stored): string
    {
        if (!self::isEncrypted($stored)) {
            // Written before a key was configured. Still valid.
            return $stored;
        }

        if (!$this->isEnabled()) {
            throw new RuntimeException(
                'TwoFactorTotp: a TOTP secret is encrypted but no encryption key is configured. '
                . "Restore twofactortotp.encryption_key in Omeka's config/local.config.php."
            );
        }

        foreach ($this->keys as $key) {
            $plaintext = $this->tryKey($stored, $key);
            if (null !== $plaintext) {
                return $plaintext;
            }
        }

        throw new RuntimeException(
            'TwoFactorTotp: a stored TOTP secret could not be decrypted by any configured key. '
            . 'The key has changed without the old one being kept in '
            . 'twofactortotp.previous_encryption_keys, or the row has been altered.'
        );
    }

    /**
     * Which configured key reads this value: 0 for the current one, higher for
     * a retired one.
     *
     * @throws RuntimeException when none of them do.
     */
    protected function findKeyIndex(string $stored): int
    {
        foreach ($this->keys as $index => $key) {
            if (null !== $this->tryKey($stored, $key)) {
                return $index;
            }
        }

        throw new RuntimeException(
            'TwoFactorTotp: a stored TOTP secret could not be decrypted by any configured key.'
        );
    }

    /**
     * @return string|null The plaintext, or null if this key is not the one.
     */
    protected function tryKey(string $stored, string $key): ?string
    {
        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if (false === $raw || strlen($raw) <= self::IV_BYTES + self::TAG_BYTES) {
            throw new RuntimeException('TwoFactorTotp: a stored TOTP secret is malformed.');
        }

        $iv = substr($raw, 0, self::IV_BYTES);
        $tag = substr($raw, self::IV_BYTES, self::TAG_BYTES);
        $ciphertext = substr($raw, self::IV_BYTES + self::TAG_BYTES);

        // GCM authenticates, so a wrong key fails here rather than returning
        // plausible rubbish. That is what makes trying keys in turn safe.
        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);

        return false === $plaintext ? null : $plaintext;
    }
}

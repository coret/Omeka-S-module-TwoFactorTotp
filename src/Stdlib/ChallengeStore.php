<?php declare(strict_types=1);

namespace TwoFactorTotp\Stdlib;

use Laminas\Stdlib\ArrayObject;

/**
 * The one-shot random challenge a WebAuthn ceremony is built around.
 *
 * It lives here rather than in PendingLogin for two reasons: registration
 * happens when there is no pending login at all, and PendingLogin's payload has
 * no room for per-factor scratch space.
 *
 * Stored as base64 of the raw bytes, never as the library's ByteBuffer object.
 * A ByteBuffer put in the session comes back as __PHP_Incomplete_Class on the
 * next request, because the session is deserialised before the module's
 * autoloader has run.
 *
 * Single use and time limited: a challenge that could be replayed, or that
 * lived forever, would defeat the point of having one.
 */
class ChallengeStore
{
    const CONTAINER_NAME = 'TwoFactorTotpChallenge';

    /** Registration and authentication must not be able to reuse each other's. */
    const PURPOSE_REGISTER = 'register';
    const PURPOSE_AUTHENTICATE = 'authenticate';

    /**
     * Typed as the ArrayObject that Laminas\Session\Container extends, rather
     * than the Container itself: property access is all this needs, and the
     * narrower hint would force a live session on anything exercising it.
     */
    protected ArrayObject $container;

    protected int $ttl;

    public function __construct(ArrayObject $container, int $ttl = 300)
    {
        $this->container = $container;
        $this->ttl = max(30, $ttl);
    }

    public function put(string $purpose, string $rawChallenge): void
    {
        $this->container->challenge = [
            'purpose' => $purpose,
            'value' => base64_encode($rawChallenge),
            'created' => time(),
        ];
    }

    /**
     * Read the challenge and destroy it in the same breath, so a replayed
     * response finds nothing to verify against.
     *
     * @return string|null The raw challenge bytes.
     */
    public function take(string $purpose): ?string
    {
        $stored = $this->container->challenge ?? null;
        $this->clear();

        if (!is_array($stored)) {
            return null;
        }
        if (($stored['purpose'] ?? null) !== $purpose) {
            return null;
        }
        if ((time() - (int) ($stored['created'] ?? 0)) > $this->ttl) {
            return null;
        }

        $raw = base64_decode((string) ($stored['value'] ?? ''), true);

        return false === $raw || '' === $raw ? null : $raw;
    }

    public function clear(): void
    {
        unset($this->container->challenge);
    }
}

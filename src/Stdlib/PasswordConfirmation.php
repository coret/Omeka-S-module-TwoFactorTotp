<?php declare(strict_types=1);

namespace TwoFactorTotp\Stdlib;

use Laminas\Stdlib\ArrayObject;

/**
 * "This person typed their password a moment ago."
 *
 * Turning TOTP off and reissuing recovery codes have always asked for the
 * password again, on the reasoning that an unlocked, unattended browser should
 * not be enough to change what protects an account. Registering a passkey is
 * the same kind of change — arguably a worse one, because the passkey an
 * attacker adds survives the victim changing their password — so it asks too.
 *
 * A stamp rather than a prompt per action, because enrolling two keys in a row
 * is normal and three password prompts to do it is how people stop bothering.
 *
 * Deliberately narrow: bound to one user id, so a confirmation cannot survive
 * a logout and vouch for the next account in the same session, and short
 * lived, so a browser left open does not stay privileged.
 */
class PasswordConfirmation
{
    const CONTAINER_NAME = 'TwoFactorTotpPasswordConfirm';

    /** Seconds a confirmation stands. */
    const DEFAULT_TTL = 300;

    /**
     * Typed as the ArrayObject that Laminas\Session\Container extends, for the
     * same reason as ChallengeStore: property access is all this needs, and the
     * narrower hint would force a live session on anything exercising it.
     */
    protected ArrayObject $container;

    protected int $ttl;

    public function __construct(ArrayObject $container, int $ttl = self::DEFAULT_TTL)
    {
        $this->container = $container;
        $this->ttl = max(30, $ttl);
    }

    public function confirm(int $userId): void
    {
        $this->container->confirmed = [
            'user_id' => $userId,
            'at' => time(),
        ];
    }

    public function isConfirmed(int $userId): bool
    {
        // No user, no confirmation. Falling through to a comparison of two
        // zeroes would hand the privilege out for free.
        if ($userId <= 0) {
            return false;
        }

        $stamp = $this->container->confirmed ?? null;
        if (!is_array($stamp)) {
            return false;
        }
        if ((int) ($stamp['user_id'] ?? 0) !== $userId) {
            return false;
        }

        return (time() - (int) ($stamp['at'] ?? 0)) <= $this->ttl;
    }

    /**
     * Seconds the current confirmation has left, for a caller that wants to
     * say so. Zero when there is nothing standing.
     */
    public function getSecondsRemaining(int $userId): int
    {
        if (!$this->isConfirmed($userId)) {
            return 0;
        }
        $stamp = $this->container->confirmed;

        return max(0, $this->ttl - (time() - (int) $stamp['at']));
    }

    public function clear(): void
    {
        unset($this->container->confirmed);
    }
}

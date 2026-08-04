<?php declare(strict_types=1);

namespace TwoFactorTotp\Stdlib;

use Laminas\Session\Container;

/**
 * The half-finished login that sits between "password accepted" and "code
 * accepted".
 *
 * This is sensitive state: anyone holding it has already proved the password.
 * So it is deliberately narrow — a user id, never an identity — and short
 * lived, and it counts its own failures so the code form cannot be used as a
 * six-digit oracle.
 *
 * The password itself is never stored.
 */
class PendingLogin
{
    const CONTAINER_NAME = 'TwoFactorTotp';

    protected Container $container;

    /** Seconds a pending login stays usable. */
    protected int $ttl;

    /** Wrong codes tolerated before the pending login is destroyed. */
    protected int $maxAttempts;

    public function __construct(Container $container, int $ttl, int $maxAttempts)
    {
        $this->container = $container;
        $this->ttl = max(30, $ttl);
        $this->maxAttempts = max(1, $maxAttempts);
    }

    /**
     * Park a password-verified user, awaiting their code.
     *
     * @param string|null $redirectUrl Where the user was headed before being
     *                                 bounced to the login form.
     */
    public function start(int $userId, ?string $redirectUrl = null): void
    {
        $this->container->pending = [
            'user_id' => $userId,
            // Not used as a credential: it makes each pending login distinct
            // so a stale one can never be mistaken for a fresh one.
            'nonce' => bin2hex(random_bytes(32)),
            'created' => time(),
            'attempts' => 0,
            'redirect_url' => $redirectUrl,
        ];
    }

    public function isActive(): bool
    {
        return null !== $this->read();
    }

    public function getUserId(): ?int
    {
        $pending = $this->read();
        return $pending ? (int) $pending['user_id'] : null;
    }

    public function getRedirectUrl(): ?string
    {
        $pending = $this->read();
        return $pending['redirect_url'] ?? null;
    }

    public function getAttempts(): int
    {
        $pending = $this->read();
        return $pending ? (int) $pending['attempts'] : 0;
    }

    public function getRemainingAttempts(): int
    {
        return max(0, $this->maxAttempts - $this->getAttempts());
    }

    /**
     * Seconds left before this pending login expires.
     */
    public function getSecondsRemaining(): int
    {
        $pending = $this->read();
        if (!$pending) {
            return 0;
        }
        return max(0, $this->ttl - (time() - (int) $pending['created']));
    }

    /**
     * Record a wrong code.
     *
     * @return bool True if the pending login survived; false if it has been
     *              destroyed and the user must start over.
     */
    public function recordFailure(): bool
    {
        $pending = $this->read();
        if (!$pending) {
            return false;
        }

        $pending['attempts'] = (int) $pending['attempts'] + 1;
        $this->container->pending = $pending;

        if ($pending['attempts'] >= $this->maxAttempts) {
            $this->clear();
            return false;
        }

        return true;
    }

    public function clear(): void
    {
        unset($this->container->pending);
    }

    /**
     * Read the pending login, expiring it if it is too old.
     */
    protected function read(): ?array
    {
        $pending = $this->container->pending ?? null;

        if (!is_array($pending) || empty($pending['user_id']) || !isset($pending['created'])) {
            return null;
        }

        if ((time() - (int) $pending['created']) > $this->ttl) {
            $this->clear();
            return null;
        }

        return $pending;
    }
}

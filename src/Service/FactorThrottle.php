<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;

/**
 * How many times an account may fail its second factor before the second step
 * stops answering for a while.
 *
 * PendingLogin already counts wrong codes, but it counts them *per pending
 * login*, and a pending login is created fresh by every password submission.
 * That bounds a sitting, not an account: somebody who holds the password can
 * spend the budget, re-post the login form and get another one. With a window
 * of 1 there are three valid codes out of a million at any moment, so at a
 * modest rate the expected time to a hit is a couple of hours. The per-sitting
 * limit is still worth having — it is what stops a single form being hammered
 * — but the limit that matters has to live on the account.
 *
 * State lives in user settings rather than a table of its own: it is three
 * small values per user, Omeka already has somewhere to put those, and a new
 * table would mean a migration for something that is not really the module's
 * data model.
 *
 * Recovery codes deliberately do not go through this. They are ten characters
 * out of a 32-character alphabet, so there is nothing here to guess, and
 * exempting them means the throttle can never leave somebody with no way back
 * into their own account — which is the failure mode that turns a lockout into
 * a support ticket, or worse, into a reason to switch the module off.
 */
class FactorThrottle
{
    const KEY_FAILURES = 'twofactortotp_factor_failures';

    const KEY_LOCKED_UNTIL = 'twofactortotp_factor_locked_until';

    const KEY_LOCK_LEVEL = 'twofactortotp_factor_lock_level';

    /**
     * However far the backoff climbs, a lock never outlasts a day. Beyond that
     * it stops being a throttle and becomes a permanent denial of service that
     * the account holder cannot clear themselves.
     */
    const MAX_LOCK_SECONDS = 86400;

    protected UserSettings $userSettings;

    protected Settings $settings;

    public function __construct(UserSettings $userSettings, Settings $settings)
    {
        $this->userSettings = $userSettings;
        $this->settings = $settings;
    }

    /**
     * Failures tolerated before a lock. 0 turns the throttle off entirely.
     */
    public function getThreshold(): int
    {
        return max(0, (int) $this->settings->get('twofactortotp_lockout_threshold', 10));
    }

    /**
     * The first lock's length. Each subsequent one doubles it.
     */
    public function getBaseLockSeconds(): int
    {
        return max(30, (int) $this->settings->get('twofactortotp_lockout_seconds', 900));
    }

    public function isEnabled(): bool
    {
        return $this->getThreshold() > 0;
    }

    public function isLocked(int $userId): bool
    {
        return $this->getSecondsRemaining($userId) > 0;
    }

    public function getSecondsRemaining(int $userId): int
    {
        if ($userId <= 0 || !$this->isEnabled()) {
            return 0;
        }

        $until = (int) $this->read($userId, self::KEY_LOCKED_UNTIL, 0);

        return max(0, $until - time());
    }

    /**
     * Count a wrong code or a rejected assertion, and lock the account once
     * the threshold is reached.
     */
    public function recordFailure(int $userId): void
    {
        if ($userId <= 0 || !$this->isEnabled()) {
            return;
        }

        $failures = (int) $this->read($userId, self::KEY_FAILURES, 0) + 1;

        if ($failures < $this->getThreshold()) {
            $this->write($userId, self::KEY_FAILURES, $failures);
            return;
        }

        // Threshold reached. Each lock is twice the last, so waiting one out to
        // buy another round of guesses gets steadily more expensive, and the
        // counter starts again so the next round is a full threshold's worth
        // rather than a single failure away from another lock.
        $level = (int) $this->read($userId, self::KEY_LOCK_LEVEL, 0) + 1;
        $seconds = min(
            self::MAX_LOCK_SECONDS,
            $this->getBaseLockSeconds() * (2 ** min($level - 1, 20))
        );

        $this->write($userId, self::KEY_FAILURES, 0);
        $this->write($userId, self::KEY_LOCK_LEVEL, $level);
        $this->write($userId, self::KEY_LOCKED_UNTIL, time() + $seconds);
    }

    /**
     * A factor was presented correctly, so the account is in its owner's hands
     * and none of this applies any more.
     */
    public function clear(int $userId): void
    {
        if ($userId <= 0) {
            return;
        }

        foreach ([self::KEY_FAILURES, self::KEY_LOCK_LEVEL, self::KEY_LOCKED_UNTIL] as $key) {
            $this->userSettings->delete($key, $userId);
        }
    }

    /**
     * @return mixed
     */
    protected function read(int $userId, string $key, $default)
    {
        // The third argument is the target user. UserSettings saves and
        // restores its own target id around it, so this never disturbs the
        // settings of whoever is (or is not) logged in — which matters here,
        // because at step two nobody is.
        return $this->userSettings->get($key, $default, $userId);
    }

    protected function write(int $userId, string $key, $value): void
    {
        $this->userSettings->set($key, $value, $userId);
    }
}

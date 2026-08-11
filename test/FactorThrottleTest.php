<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\FactorThrottle;

/**
 * The gap this closes: the wrong-codes limit lived on the pending login, and
 * a pending login is created fresh by every password submission. Five guesses,
 * re-post the login form, five more — with three of a million codes valid at
 * any moment, that is a couple of hours' work for somebody who already has the
 * password.
 *
 * So the count has to live on the account, not on the sitting.
 */
class FactorThrottleTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    /** @var array<int, array<string, mixed>> Stand-in for the user_setting table. */
    private array $stored = [];

    private function throttle(int $threshold = 10, int $lockSeconds = 900): FactorThrottle
    {
        $this->stored = $this->stored ?: [];

        $userSettings = $this->createMock(UserSettings::class);
        $userSettings->method('get')->willReturnCallback(
            fn (string $id, $default = null, $targetId = null) => $this->stored[(int) $targetId][$id] ?? $default
        );
        $userSettings->method('set')->willReturnCallback(
            function (string $id, $value, $targetId = null): void {
                $this->stored[(int) $targetId][$id] = $value;
            }
        );
        $userSettings->method('delete')->willReturnCallback(
            function (string $id, $targetId = null): void {
                unset($this->stored[(int) $targetId][$id]);
            }
        );

        $settings = $this->createMock(Settings::class);
        $settings->method('get')->willReturnCallback(
            function (string $id, $default = null) use ($threshold, $lockSeconds) {
                if ('twofactortotp_lockout_threshold' === $id) {
                    return $threshold;
                }
                if ('twofactortotp_lockout_seconds' === $id) {
                    return $lockSeconds;
                }
                return $default;
            }
        );

        return new FactorThrottle($userSettings, $settings);
    }

    public function testAnAccountThatHasNotFailedIsNotLocked(): void
    {
        $this->assertFalse($this->throttle()->isLocked(7));
    }

    public function testFailuresBelowTheThresholdDoNotLock(): void
    {
        $throttle = $this->throttle(10);

        for ($i = 0; $i < 9; $i++) {
            $throttle->recordFailure(7);
        }

        $this->assertFalse($throttle->isLocked(7));
    }

    public function testReachingTheThresholdLocks(): void
    {
        $throttle = $this->throttle(10);

        for ($i = 0; $i < 10; $i++) {
            $throttle->recordFailure(7);
        }

        $this->assertTrue($throttle->isLocked(7));
        $this->assertGreaterThan(0, $throttle->getSecondsRemaining(7));
    }

    /**
     * The whole point of moving the count off the pending login: starting a
     * new login must not hand out a fresh budget.
     */
    public function testANewSittingDoesNotResetTheCount(): void
    {
        $throttle = $this->throttle(10);

        for ($i = 0; $i < 5; $i++) {
            $throttle->recordFailure(7);
        }
        // A second FactorThrottle over the same storage stands for the next
        // request, with its own pending login.
        $next = $this->throttle(10);
        for ($i = 0; $i < 5; $i++) {
            $next->recordFailure(7);
        }

        $this->assertTrue($next->isLocked(7), 'Failures must accumulate across logins, not per login.');
    }

    public function testSuccessClearsEverything(): void
    {
        $throttle = $this->throttle(10);
        for ($i = 0; $i < 10; $i++) {
            $throttle->recordFailure(7);
        }

        $throttle->clear(7);

        $this->assertFalse($throttle->isLocked(7));
        $this->assertSame(0, $throttle->getSecondsRemaining(7));
    }

    public function testTheLockExpires(): void
    {
        $throttle = $this->throttle(10, 900);
        for ($i = 0; $i < 10; $i++) {
            $throttle->recordFailure(7);
        }

        $this->stored[7][FactorThrottle::KEY_LOCKED_UNTIL] = time() - 1;

        $this->assertFalse($throttle->isLocked(7));
    }

    /**
     * A fixed lock is a fixed cost: wait it out, get another N guesses, repeat.
     * Each lockout has to be more expensive than the last.
     */
    public function testRepeatedLockoutsBackOff(): void
    {
        $throttle = $this->throttle(2, 100);

        $throttle->recordFailure(7);
        $throttle->recordFailure(7);
        $firstLock = $throttle->getSecondsRemaining(7);

        // Serve the first lock, then fail again.
        $this->stored[7][FactorThrottle::KEY_LOCKED_UNTIL] = time() - 1;
        $throttle->recordFailure(7);
        $throttle->recordFailure(7);
        $secondLock = $throttle->getSecondsRemaining(7);

        $this->assertGreaterThan($firstLock, $secondLock);
    }

    public function testOneAccountsFailuresDoNotLockAnother(): void
    {
        $throttle = $this->throttle(2);
        $throttle->recordFailure(7);
        $throttle->recordFailure(7);

        $this->assertTrue($throttle->isLocked(7));
        $this->assertFalse($throttle->isLocked(8));
    }

    public function testAThresholdOfZeroTurnsItOff(): void
    {
        $throttle = $this->throttle(0);

        for ($i = 0; $i < 50; $i++) {
            $throttle->recordFailure(7);
        }

        $this->assertFalse($throttle->isLocked(7));
    }

    /**
     * No user id, nothing to throttle — and in particular nothing to lock,
     * since a shared "user 0" bucket would let one anonymous failure lock the
     * form for everybody.
     */
    public function testAnUnknownUserIsNeverLocked(): void
    {
        $throttle = $this->throttle(1);
        $throttle->recordFailure(0);

        $this->assertFalse($throttle->isLocked(0));
    }
}

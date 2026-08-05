<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Stdlib\ChallengeStore;

/**
 * A WebAuthn challenge is the entire replay defence. If it can be used twice,
 * or outlives its ceremony, or can be spent by a ceremony it was not issued
 * for, it is not doing its job.
 */
class ChallengeStoreTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    /**
     * Laminas' session Container needs a live session. It extends
     * Laminas\Stdlib\ArrayObject, which is all the store actually uses, so a
     * bare one of those exercises the same behaviour without a session.
     */
    private function store(int $ttl = 300): ChallengeStore
    {
        return new ChallengeStore(new \Laminas\Stdlib\ArrayObject(), $ttl);
    }

    public function testARoundTripReturnsTheExactBytes(): void
    {
        $store = $this->store();
        $challenge = random_bytes(32);

        $store->put(ChallengeStore::PURPOSE_REGISTER, $challenge);

        $this->assertSame($challenge, $store->take(ChallengeStore::PURPOSE_REGISTER));
    }

    public function testBinarySafeForBytesThatAreNotValidUtf8(): void
    {
        $store = $this->store();
        $challenge = "\x00\xff\xfe\x80\x01" . random_bytes(27);

        $store->put(ChallengeStore::PURPOSE_AUTHENTICATE, $challenge);

        $this->assertSame($challenge, $store->take(ChallengeStore::PURPOSE_AUTHENTICATE));
    }

    public function testAChallengeCannotBeSpentTwice(): void
    {
        $store = $this->store();
        $store->put(ChallengeStore::PURPOSE_REGISTER, random_bytes(32));

        $this->assertNotNull($store->take(ChallengeStore::PURPOSE_REGISTER));
        $this->assertNull(
            $store->take(ChallengeStore::PURPOSE_REGISTER),
            'A replayed response must find nothing to verify against.'
        );
    }

    public function testAnotherCeremonyCannotSpendIt(): void
    {
        $store = $this->store();
        $store->put(ChallengeStore::PURPOSE_REGISTER, random_bytes(32));

        $this->assertNull($store->take(ChallengeStore::PURPOSE_AUTHENTICATE));
    }

    /**
     * And the failed read still consumes it, so a wrong-purpose attempt cannot
     * be used to probe whether a challenge is outstanding.
     */
    public function testAWrongPurposeReadStillDestroysIt(): void
    {
        $store = $this->store();
        $store->put(ChallengeStore::PURPOSE_REGISTER, random_bytes(32));

        $store->take(ChallengeStore::PURPOSE_AUTHENTICATE);

        $this->assertNull($store->take(ChallengeStore::PURPOSE_REGISTER));
    }

    public function testAnExpiredChallengeIsRefused(): void
    {
        // The floor is 30s, so reach in and backdate rather than sleep.
        $store = $this->store(30);
        $store->put(ChallengeStore::PURPOSE_REGISTER, random_bytes(32));

        $property = new \ReflectionProperty(ChallengeStore::class, 'container');
        $property->setAccessible(true);
        $container = $property->getValue($store);
        $stored = $container->challenge;
        $stored['created'] = time() - 31;
        $container->challenge = $stored;

        $this->assertNull($store->take(ChallengeStore::PURPOSE_REGISTER));
    }

    public function testTakingWhenNothingWasIssuedIsNotAnError(): void
    {
        $this->assertNull($this->store()->take(ChallengeStore::PURPOSE_REGISTER));
    }

    public function testClearRemovesIt(): void
    {
        $store = $this->store();
        $store->put(ChallengeStore::PURPOSE_REGISTER, random_bytes(32));
        $store->clear();

        $this->assertNull($store->take(ChallengeStore::PURPOSE_REGISTER));
    }
}

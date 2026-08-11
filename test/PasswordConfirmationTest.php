<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Laminas\Stdlib\ArrayObject;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Stdlib\PasswordConfirmation;

/**
 * Adding or removing a passkey changes what stands between an attacker and the
 * account, so it asks for the password first — the same rule that already
 * guarded disabling TOTP and reissuing recovery codes.
 *
 * The stamp this leaves has to be narrow: bound to one account and short
 * lived, or it becomes a way to carry one person's confirmation into somebody
 * else's session.
 */
class PasswordConfirmationTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    public function testNothingIsConfirmedToStartWith(): void
    {
        $store = new PasswordConfirmation(new ArrayObject());

        $this->assertFalse($store->isConfirmed(1));
    }

    public function testConfirmingHoldsForTheSameUser(): void
    {
        $store = new PasswordConfirmation(new ArrayObject());
        $store->confirm(7);

        $this->assertTrue($store->isConfirmed(7));
    }

    /**
     * The property that matters. Log out, log in as somebody else, and the
     * previous account's confirmation must not still be standing.
     */
    public function testAConfirmationDoesNotCarryToAnotherUser(): void
    {
        $store = new PasswordConfirmation(new ArrayObject());
        $store->confirm(7);

        $this->assertFalse($store->isConfirmed(8), 'One account\'s confirmation must not vouch for another.');
    }

    public function testItExpires(): void
    {
        $container = new ArrayObject();
        $store = new PasswordConfirmation($container, 60);
        $store->confirm(7);

        $stamp = $container->confirmed;
        $stamp['at'] = time() - 61;
        $container->confirmed = $stamp;

        $this->assertFalse($store->isConfirmed(7));
    }

    public function testClearRevokesIt(): void
    {
        $store = new PasswordConfirmation(new ArrayObject());
        $store->confirm(7);
        $store->clear();

        $this->assertFalse($store->isConfirmed(7));
    }

    /**
     * A rubbish or absent user id must never be treated as "confirmed" —
     * that is the direction that hands out the privilege for free.
     */
    public function testAZeroUserIdIsNeverConfirmed(): void
    {
        $store = new PasswordConfirmation(new ArrayObject());
        $store->confirm(0);

        $this->assertFalse($store->isConfirmed(0));
    }
}

<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Omeka\Entity\User;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Authentication\Factor\PasskeyFactor;
use TwoFactorTotp\Service\PasskeyManager;

/**
 * The one property in this step with a security consequence.
 *
 * `vendor/` is not committed, so the WebAuthn library can genuinely be absent.
 * The tempting reading — "the factor cannot work, so the user is not enrolled"
 * — fails open: a user whose only factor is a passkey would then be admitted on
 * their password alone.
 */
class PasskeyFactorTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function factor(int $credentialCount, bool $libraryAvailable): PasskeyFactor
    {
        $manager = $this->createMock(PasskeyManager::class);
        $manager->method('countForUser')->willReturn($credentialCount);
        $manager->method('isAvailable')->willReturn($libraryAvailable);

        return new PasskeyFactor($manager);
    }

    public function testAUserWithACredentialIsEnrolled(): void
    {
        $this->assertTrue($this->factor(1, true)->isEnrolled(new User()));
    }

    public function testAUserWithNoCredentialIsNotEnrolled(): void
    {
        $this->assertFalse($this->factor(0, true)->isEnrolled(new User()));
    }

    /**
     * The whole point. With the library missing the passkey cannot be
     * presented — but the account still has one, and must still be stopped.
     */
    public function testStillEnrolledWhenTheLibraryIsMissing(): void
    {
        $this->assertTrue(
            $this->factor(1, false)->isEnrolled(new User()),
            'A missing library must not turn a passkey user into a password-only login.'
        );
    }

    public function testTheFactorIsNamedAndRoutedDistinctlyFromTotp(): void
    {
        $factor = $this->factor(0, true);

        $this->assertSame('passkey', $factor->getName());
        $this->assertNotSame(['two-factor', []], $factor->getChallengeRoute());
        $this->assertSame(['admin/two-factor', ['action' => 'passkeys']], $factor->getEnrollmentRoute());
    }
}

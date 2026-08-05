<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Omeka\Entity\User;
use Omeka\Settings\Settings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Authentication\SecondFactorInterface;
use TwoFactorTotp\Service\SecondFactorRegistry;

/**
 * The registry answers the one question the authentication adapter asks:
 * does this login owe a second step?
 *
 * Getting it wrong in the "no" direction lets somebody in on their password
 * alone, so these lean on that case deliberately.
 */
class SecondFactorRegistryTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function factor(string $name, bool $enrolled): SecondFactorInterface
    {
        return new class ($name, $enrolled) implements SecondFactorInterface {
            public function __construct(private string $name, private bool $enrolled)
            {
            }

            public function getName(): string
            {
                return $this->name;
            }

            public function getLabel(): string
            {
                return ucfirst($this->name);
            }

            public function isEnrolled(User $user): bool
            {
                return $this->enrolled;
            }

            public function getChallengeRoute(): array
            {
                return [$this->name, []];
            }

            public function getEnrollmentRoute(): array
            {
                return ['admin/' . $this->name, ['action' => 'setup']];
            }
        };
    }

    private function registry(array $factors, array $requiredRoles = []): SecondFactorRegistry
    {
        $settings = $this->createMock(Settings::class);
        $settings->method('get')->willReturn($requiredRoles);

        return new SecondFactorRegistry($factors, $settings);
    }

    public function testAUserWithNoFactorOwesNothing(): void
    {
        $registry = $this->registry([$this->factor('totp', false)]);

        $this->assertFalse($registry->hasAnyEnrolled(new User()));
        $this->assertSame([], $registry->getEnrolled(new User()));
    }

    /**
     * The case the registry exists for: a factor the adapter has never heard of
     * still has to stop the login.
     */
    public function testAnyEnrolledFactorMeansTheLoginOwesASecondStep(): void
    {
        $registry = $this->registry([
            $this->factor('totp', false),
            $this->factor('passkey', true),
        ]);

        $this->assertTrue($registry->hasAnyEnrolled(new User()));
        $this->assertSame(['passkey'], array_keys($registry->getEnrolled(new User())));
    }

    public function testTheChallengeGoesToAFactorTheUserActuallyHas(): void
    {
        $registry = $this->registry([
            $this->factor('totp', false),
            $this->factor('passkey', true),
        ]);

        $this->assertSame(['passkey', []], $registry->getChallengeRouteFor(new User()));
    }

    public function testNoChallengeRouteWhenNothingIsEnrolled(): void
    {
        $registry = $this->registry([$this->factor('totp', false)]);

        $this->assertNull($registry->getChallengeRouteFor(new User()));
    }

    public function testForcedByRoleButUnenrolledMustEnroll(): void
    {
        $user = new User();
        $user->setRole('editor');

        $registry = $this->registry([$this->factor('totp', false)], ['editor']);

        $this->assertTrue($registry->isRoleForced($user));
        $this->assertTrue($registry->mustEnroll($user));
    }

    /**
     * Any factor satisfies the requirement — being forced to use "a second
     * factor" must not mean being forced to use TOTP specifically.
     */
    public function testAnyEnrolledFactorSatisfiesAForcedRole(): void
    {
        $user = new User();
        $user->setRole('editor');

        $registry = $this->registry([
            $this->factor('totp', false),
            $this->factor('passkey', true),
        ], ['editor']);

        $this->assertTrue($registry->isRoleForced($user));
        $this->assertFalse($registry->mustEnroll($user));
    }

    public function testAnUnforcedRoleIsNeverPushedIntoEnrollment(): void
    {
        $user = new User();
        $user->setRole('researcher');

        $registry = $this->registry([$this->factor('totp', false)], ['editor']);

        $this->assertFalse($registry->mustEnroll($user));
    }

    public function testEnrollmentRouteIsNullWithNoFactorsRegistered(): void
    {
        // Module's route listener relies on this to avoid confining a user to
        // a page that does not exist, which would be a loop with no way out.
        $this->assertNull($this->registry([])->getEnrollmentRoute());
    }
}

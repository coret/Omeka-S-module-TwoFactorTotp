<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityRepository;
use Omeka\Entity\User;
use Omeka\Settings\Settings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Entity\TotpEnrollment;
use TwoFactorTotp\Service\Totp;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * The setup page's secret has to survive until it is confirmed.
 *
 * The controller calls beginEnrollment() on every request to the setup page,
 * including the POST that carries the code. If that call rolls a new secret,
 * it replaces the one the user just scanned before the code is ever checked,
 * and confirmation can never succeed. Re-displaying the page (a refresh, or a
 * failed attempt) must not invalidate the scan either.
 */
class EnrollmentSecretTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function manager(?TotpEnrollment &$stored): TotpManager
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->method('findOneBy')->willReturnCallback(
            function () use (&$stored) {
                return $stored;
            }
        );

        $entityManager = $this->createMock(EntityManager::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->method('persist')->willReturnCallback(
            function ($entity) use (&$stored): void {
                $stored = $entity;
            }
        );

        return new TotpManager(
            $entityManager,
            new Totp(),
            $this->createMock(Settings::class),
            $this->createMock(TrustedDeviceManager::class)
        );
    }

    public function testTheSecretSurvivesUntilTheEnrollmentIsConfirmed(): void
    {
        $stored = null;
        $manager = $this->manager($stored);
        $user = new User();

        $first = $manager->beginEnrollment($user)->getSecret();
        $second = $manager->beginEnrollment($user)->getSecret();

        $this->assertNotEmpty($first);
        $this->assertSame(
            $first,
            $second,
            'The scanned secret must not be replaced before confirmation.'
        );
    }

    public function testAFreshEnrollmentStillGetsItsOwnSecret(): void
    {
        $storedA = null;
        $storedB = null;

        $secretA = $this->manager($storedA)->beginEnrollment(new User())->getSecret();
        $secretB = $this->manager($storedB)->beginEnrollment(new User())->getSecret();

        $this->assertNotSame($secretA, $secretB);
    }
}

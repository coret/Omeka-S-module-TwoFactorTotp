<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\RecoveryCodeManager;

/**
 * Recovery codes moved out of TotpManager to the user. The generation and
 * matching rules must survive that move unchanged — people have codes on paper.
 */
class RecoveryCodeTest extends TestCase
{
    private function manager(): RecoveryCodeManager
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
        // normalize() touches nothing else, so the entity manager is never used.
        return new RecoveryCodeManager(
            $this->createMock(\Doctrine\ORM\EntityManager::class)
        );
    }

    public function testNormalisationIgnoresGroupingAndCase(): void
    {
        $manager = $this->manager();

        $this->assertSame('A3F7K9QM2X', $manager->normalize('a3f7k-9qm2x'));
        $this->assertSame('A3F7K9QM2X', $manager->normalize('A3F7K9QM2X'));
        $this->assertSame('A3F7K9QM2X', $manager->normalize('  a3f7k 9qm2x '));
        $this->assertSame('A3F7K9QM2X', $manager->normalize('a3f7k_9qm2x'));
    }

    public function testNormalisationOfRubbishIsEmptyRatherThanAMatch(): void
    {
        $manager = $this->manager();

        $this->assertSame('', $manager->normalize(''));
        $this->assertSame('', $manager->normalize('---'));
    }

    /**
     * The alphabet deliberately omits the characters that misread on paper.
     */
    public function testAlphabetHasNoAmbiguousCharacters(): void
    {
        foreach (['0', '1', 'O', 'I'] as $ambiguous) {
            $this->assertStringNotContainsString(
                $ambiguous,
                RecoveryCodeManager::ALPHABET,
                sprintf('"%s" is too easy to misread to be in a recovery code.', $ambiguous)
            );
        }
    }

    public function testTenCodesIsStillTheSetSize(): void
    {
        $this->assertSame(10, RecoveryCodeManager::CODE_COUNT);
        $this->assertSame(2, RecoveryCodeManager::LOW_WATER_MARK);
    }

    /**
     * A hash made by the old TotpManager must still verify, or the migration
     * silently locks people out of their own escape hatch.
     */
    public function testHashesMadeBeforeTheMoveStillVerify(): void
    {
        $manager = $this->manager();

        // Exactly what the old code stored: password_hash() of the normalised code.
        $legacyHash = password_hash('A3F7K9QM2X', PASSWORD_DEFAULT);

        $this->assertTrue(password_verify($manager->normalize('a3f7k-9qm2x'), $legacyHash));
    }
}

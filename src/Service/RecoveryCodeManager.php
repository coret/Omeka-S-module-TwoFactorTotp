<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use DateTime;
use Doctrine\ORM\EntityManager;
use Omeka\Entity\User;
use TwoFactorTotp\Entity\RecoveryCode;

/**
 * Recovery codes, owned by the user rather than by any one second factor.
 *
 * The generation and hashing here came out of TotpManager unchanged; what moved
 * is *where the codes live*. Tying them to the TOTP enrollment row meant an
 * account whose only factor was something else had no fallback, and that stops
 * being hypothetical the moment passkeys exist.
 */
class RecoveryCodeManager
{
    const CODE_COUNT = 10;

    /** Base32 minus the characters that misread: no 0/O, no 1/I. */
    const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    const CODE_LENGTH = 10;

    /** Below this many unused codes, nag the user to make a new set. */
    const LOW_WATER_MARK = 2;

    protected EntityManager $entityManager;

    public function __construct(EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Issue a fresh set, invalidating every code the user had before.
     *
     * @return string[] The plaintext codes — the only time they are available.
     */
    public function generate(User $user): array
    {
        $this->deleteAll($user);

        $plainCodes = [];
        $alphabetMax = strlen(self::ALPHABET) - 1;
        for ($i = 0; $i < self::CODE_COUNT; $i++) {
            $code = '';
            for ($j = 0; $j < self::CODE_LENGTH; $j++) {
                $code .= self::ALPHABET[random_int(0, $alphabetMax)];
            }
            // Grouped for legibility; the grouping is stripped on input.
            $plainCodes[] = substr($code, 0, 5) . '-' . substr($code, 5);
        }

        foreach ($plainCodes as $plainCode) {
            $entity = new RecoveryCode();
            $entity
                ->setUser($user)
                ->setCodeHash(password_hash($this->normalize($plainCode), PASSWORD_DEFAULT))
                ->setCreated(new DateTime('now'));
            $this->entityManager->persist($entity);
        }
        $this->entityManager->flush();

        return $plainCodes;
    }

    /**
     * Spend a code. Each one works exactly once.
     */
    public function consume(User $user, string $code): bool
    {
        $candidate = $this->normalize($code);
        if ('' === $candidate) {
            return false;
        }

        foreach ($this->findUnused($user) as $recoveryCode) {
            if (password_verify($candidate, (string) $recoveryCode->getCodeHash())) {
                $recoveryCode->setUsedAt(new DateTime('now'));
                $this->entityManager->flush();
                return true;
            }
        }

        return false;
    }

    public function countUnused(User $user): int
    {
        return count($this->findUnused($user));
    }

    /**
     * Drop every code, spent or not. Used when the last second factor goes.
     */
    public function deleteAll(User $user): void
    {
        if (!$user->getId()) {
            return;
        }

        $this->entityManager
            ->createQuery(
                'DELETE FROM ' . RecoveryCode::class . ' rc WHERE rc.user = :user'
            )
            ->setParameter('user', $user)
            ->execute();
    }

    /**
     * @return RecoveryCode[]
     */
    protected function findUnused(User $user): array
    {
        if (!$user->getId()) {
            return [];
        }

        return $this->entityManager
            ->getRepository(RecoveryCode::class)
            ->findBy(['user' => $user, 'usedAt' => null], ['id' => 'ASC']);
    }

    /**
     * Strip the cosmetic grouping so "a3f7k-9qm2x" and "A3F7K9QM2X" match.
     */
    public function normalize(string $code): string
    {
        return strtoupper((string) preg_replace('/[^A-Za-z0-9]/', '', $code));
    }
}

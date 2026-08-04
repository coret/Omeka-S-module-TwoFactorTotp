<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use DateTime;
use Doctrine\ORM\EntityManager;
use Omeka\Entity\User;
use Omeka\Settings\Settings;
use TwoFactorTotp\Entity\TotpEnrollment;

/**
 * Everything the rest of the module needs to know about a user's second
 * factor: whether they owe one, how to enroll them, and whether a code they
 * just typed is good.
 *
 * All the policy lives here; Totp holds only the maths.
 */
class TotpManager
{
    const RECOVERY_CODE_COUNT = 10;

    /** Characters used in recovery codes: base32 minus nothing, so no 0/1/8 to misread. */
    const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    const RECOVERY_CODE_LENGTH = 10;

    /** Below this, nag the user to regenerate. */
    const RECOVERY_LOW_WATER_MARK = 2;

    protected EntityManager $entityManager;

    protected Totp $totp;

    protected Settings $settings;

    protected TrustedDeviceManager $trustedDevices;

    public function __construct(
        EntityManager $entityManager,
        Totp $totp,
        Settings $settings,
        TrustedDeviceManager $trustedDevices
    ) {
        $this->entityManager = $entityManager;
        $this->totp = $totp;
        $this->settings = $settings;
        $this->trustedDevices = $trustedDevices;
    }

    // --------------------------------------------------------------- queries

    public function findEnrollment(User $user): ?TotpEnrollment
    {
        return $this->entityManager
            ->getRepository(TotpEnrollment::class)
            ->findOneBy(['user' => $user]);
    }

    /**
     * Has this user completed enrollment?
     */
    public function isEnabled(User $user): bool
    {
        $enrollment = $this->findEnrollment($user);
        return $enrollment && $enrollment->isConfirmed();
    }

    /**
     * Roles for which 2FA is mandatory.
     */
    public function getRequiredRoles(): array
    {
        $roles = $this->settings->get('twofactortotp_required_roles', []);
        return is_array($roles) ? $roles : [];
    }

    public function isRoleForced(User $user): bool
    {
        return in_array($user->getRole(), $this->getRequiredRoles(), true);
    }

    /**
     * Does this login have to clear a second step?
     *
     * True when the user has enrolled, and also when their role makes 2FA
     * mandatory — in the latter case they get pushed into enrollment rather
     * than being let through.
     */
    public function isSecondFactorRequired(User $user): bool
    {
        return $this->isEnabled($user) || $this->isRoleForced($user);
    }

    /**
     * Forced by role but not yet enrolled: must set 2FA up before doing
     * anything else.
     */
    public function mustEnroll(User $user): bool
    {
        return $this->isRoleForced($user) && !$this->isEnabled($user);
    }

    public function getIssuer(): string
    {
        $issuer = trim((string) $this->settings->get('twofactortotp_issuer', ''));
        if ('' !== $issuer) {
            return $issuer;
        }
        return (string) $this->settings->get('installation_title', 'Omeka S');
    }

    public function getWindow(): int
    {
        return max(0, (int) $this->settings->get('twofactortotp_window', 1));
    }

    public function getProvisioningUri(TotpEnrollment $enrollment): string
    {
        return $this->totp->provisioningUri(
            (string) $enrollment->getSecret(),
            (string) $enrollment->getUser()->getEmail(),
            $this->getIssuer()
        );
    }

    // ------------------------------------------------------------ enrollment

    /**
     * Start (or restart) enrollment with a fresh secret.
     *
     * Restarting deliberately discards any previous *unconfirmed* attempt, so
     * a half-finished setup left in another browser cannot be completed later.
     * A confirmed enrollment is never silently replaced — callers must disable
     * first.
     */
    public function beginEnrollment(User $user): TotpEnrollment
    {
        $enrollment = $this->findEnrollment($user);

        if ($enrollment && $enrollment->isConfirmed()) {
            return $enrollment;
        }

        // An enrollment already under way keeps its secret. The setup page
        // calls this on every request, including the POST carrying the code:
        // rolling a new secret here would replace the one just scanned before
        // the code is checked, so confirmation could never succeed. It would
        // also invalidate the scan on a simple page refresh.
        //
        // Reusing it is safe — an unconfirmed secret has never authenticated
        // anything. A genuinely fresh start comes from disable() or an admin
        // reset, both of which remove the enrollment row entirely.
        if ($enrollment && $enrollment->getSecret()) {
            return $enrollment;
        }

        if (!$enrollment) {
            $enrollment = new TotpEnrollment();
            $enrollment->setUser($user);
            $this->entityManager->persist($enrollment);
        }

        $enrollment
            ->setSecret($this->totp->generateSecret())
            ->setIsConfirmed(false)
            ->setLastCounter(null)
            ->setRecoveryCodes([]);

        $this->entityManager->flush();

        return $enrollment;
    }

    /**
     * Finish enrollment by proving the app produces the right code.
     *
     * @return string[]|null The plaintext recovery codes — the only time they
     *                       are ever available — or null if the code was wrong.
     */
    public function confirmEnrollment(User $user, string $code): ?array
    {
        $enrollment = $this->findEnrollment($user);
        if (!$enrollment || $enrollment->isConfirmed()) {
            return null;
        }

        $counter = $this->totp->verify((string) $enrollment->getSecret(), $code, $this->getWindow());
        if (null === $counter) {
            return null;
        }

        $plainCodes = $this->generateRecoveryCodes();

        $enrollment
            ->setIsConfirmed(true)
            ->setLastCounter($counter)
            ->setConfirmedAt(new DateTime('now'))
            ->setLastUsedAt(new DateTime('now'))
            ->setRecoveryCodes($this->hashRecoveryCodes($plainCodes));

        $this->entityManager->flush();

        return $plainCodes;
    }

    /**
     * Turn the second factor off and drop every trusted device with it —
     * otherwise a stale device cookie would outlive the factor it stands in for.
     */
    public function disable(User $user): void
    {
        $enrollment = $this->findEnrollment($user);
        if ($enrollment) {
            $this->entityManager->remove($enrollment);
        }
        $this->trustedDevices->revokeAll($user);
        $this->entityManager->flush();
    }

    // ---------------------------------------------------------- verification

    /**
     * Check a TOTP code and, if good, spend its counter.
     *
     * The counter check is what makes a code single-use: Totp::verify() will
     * happily accept the same code again inside its 30-second step, so the
     * highest counter already spent is persisted and anything at or below it
     * is refused.
     */
    public function verify(User $user, string $code): bool
    {
        $enrollment = $this->findEnrollment($user);
        if (!$enrollment || !$enrollment->isConfirmed()) {
            return false;
        }

        $counter = $this->totp->verify((string) $enrollment->getSecret(), $code, $this->getWindow());
        if (null === $counter) {
            return false;
        }

        $lastCounter = $enrollment->getLastCounter();
        if (null !== $lastCounter && $counter <= $lastCounter) {
            // Replay of a code already used.
            return false;
        }

        $enrollment
            ->setLastCounter($counter)
            ->setLastUsedAt(new DateTime('now'));
        $this->entityManager->flush();

        return true;
    }

    // -------------------------------------------------------- recovery codes

    /**
     * Spend one recovery code. Each works exactly once.
     */
    public function consumeRecoveryCode(User $user, string $code): bool
    {
        $enrollment = $this->findEnrollment($user);
        if (!$enrollment || !$enrollment->isConfirmed()) {
            return false;
        }

        $candidate = $this->normalizeRecoveryCode($code);
        if ('' === $candidate) {
            return false;
        }

        $hashes = $enrollment->getRecoveryCodes();
        foreach ($hashes as $index => $hash) {
            if (password_verify($candidate, (string) $hash)) {
                unset($hashes[$index]);
                $enrollment
                    ->setRecoveryCodes($hashes)
                    ->setLastUsedAt(new DateTime('now'));
                $this->entityManager->flush();
                return true;
            }
        }

        return false;
    }

    /**
     * Issue a fresh set, invalidating every old one.
     *
     * @return string[] The plaintext codes.
     */
    public function regenerateRecoveryCodes(User $user): array
    {
        $enrollment = $this->findEnrollment($user);
        if (!$enrollment) {
            return [];
        }

        $plainCodes = $this->generateRecoveryCodes();
        $enrollment->setRecoveryCodes($this->hashRecoveryCodes($plainCodes));
        $this->entityManager->flush();

        return $plainCodes;
    }

    public function countRecoveryCodes(User $user): int
    {
        $enrollment = $this->findEnrollment($user);
        return $enrollment ? $enrollment->countRecoveryCodes() : 0;
    }

    /**
     * @return string[]
     */
    protected function generateRecoveryCodes(): array
    {
        $codes = [];
        $alphabetMax = strlen(self::RECOVERY_ALPHABET) - 1;
        for ($i = 0; $i < self::RECOVERY_CODE_COUNT; $i++) {
            $code = '';
            for ($j = 0; $j < self::RECOVERY_CODE_LENGTH; $j++) {
                $code .= self::RECOVERY_ALPHABET[random_int(0, $alphabetMax)];
            }
            // Grouped for legibility; the groups are stripped on input.
            $codes[] = substr($code, 0, 5) . '-' . substr($code, 5);
        }
        return $codes;
    }

    /**
     * @param string[] $plainCodes
     * @return string[]
     */
    protected function hashRecoveryCodes(array $plainCodes): array
    {
        return array_map(function (string $code): string {
            return password_hash($this->normalizeRecoveryCode($code), PASSWORD_DEFAULT);
        }, $plainCodes);
    }

    /**
     * Strip the cosmetic grouping so "a3f7k-9qm2x" and "A3F7K9QM2X" match.
     */
    protected function normalizeRecoveryCode(string $code): string
    {
        return strtoupper((string) preg_replace('/[^A-Za-z0-9]/', '', $code));
    }
}

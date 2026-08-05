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
    /**
     * Recovery codes moved to RecoveryCodeManager when they stopped belonging
     * to the TOTP enrollment. Kept as aliases so callers and templates that
     * already reference them keep working.
     */
    const RECOVERY_CODE_COUNT = RecoveryCodeManager::CODE_COUNT;

    const RECOVERY_LOW_WATER_MARK = RecoveryCodeManager::LOW_WATER_MARK;

    protected EntityManager $entityManager;

    protected Totp $totp;

    protected Settings $settings;

    protected TrustedDeviceManager $trustedDevices;

    protected RecoveryCodeManager $recoveryCodes;

    public function __construct(
        EntityManager $entityManager,
        Totp $totp,
        Settings $settings,
        TrustedDeviceManager $trustedDevices,
        RecoveryCodeManager $recoveryCodes
    ) {
        $this->entityManager = $entityManager;
        $this->totp = $totp;
        $this->settings = $settings;
        $this->trustedDevices = $trustedDevices;
        $this->recoveryCodes = $recoveryCodes;
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

        $enrollment
            ->setIsConfirmed(true)
            ->setLastCounter($counter)
            ->setConfirmedAt(new DateTime('now'))
            ->setLastUsedAt(new DateTime('now'));

        $this->entityManager->flush();

        return $this->recoveryCodes->generate($user);
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
        // Recovery codes belong to the user, not the enrollment, so removing
        // them is now an explicit step. TOTP is presently the only factor, so
        // losing it leaves nothing for the codes to recover *into*. Once other
        // factors exist this must only fire when the last one goes.
        $this->recoveryCodes->deleteAll($user);
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
    /**
     * Spend a recovery code. Delegated: the codes are the user's, not this
     * factor's, but the call sites predate that and the signature is kept.
     */
    public function consumeRecoveryCode(User $user, string $code): bool
    {
        return $this->recoveryCodes->consume($user, $code);
    }

    /**
     * Issue a fresh set, invalidating every old one.
     *
     * @return string[] The plaintext codes.
     */
    public function regenerateRecoveryCodes(User $user): array
    {
        return $this->recoveryCodes->generate($user);
    }

    public function countRecoveryCodes(User $user): int
    {
        return $this->recoveryCodes->countUnused($user);
    }
}

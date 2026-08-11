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

    protected SecretCipher $cipher;

    public function __construct(
        EntityManager $entityManager,
        Totp $totp,
        Settings $settings,
        TrustedDeviceManager $trustedDevices,
        RecoveryCodeManager $recoveryCodes,
        ?SecretCipher $cipher = null
    ) {
        $this->entityManager = $entityManager;
        $this->totp = $totp;
        $this->settings = $settings;
        $this->trustedDevices = $trustedDevices;
        $this->recoveryCodes = $recoveryCodes;
        // A cipher with no key is a no-op, which is also what an install that
        // has configured nothing should get.
        $this->cipher = $cipher ?? new SecretCipher(null);
    }

    /**
     * The base32 secret itself.
     *
     * Everything that needs the actual secret — building the provisioning URI,
     * showing the manual-entry key, checking a code — goes through here rather
     * than reading the column, because the column may hold ciphertext.
     */
    public function getPlainSecret(TotpEnrollment $enrollment): string
    {
        return $this->cipher->decrypt((string) $enrollment->getSecret());
    }

    /**
     * Bring a stored secret up to date: one written before encryption was
     * configured, or one still under a retired key.
     *
     * Called after a code has verified, which is the moment we know the secret
     * is good and the user is present. That, rather than a one-shot migration,
     * is what lets an operator turn encryption on — or change the key — at any
     * time: rows convert themselves as their owners log in.
     */
    protected function encryptStoredSecretIfNeeded(TotpEnrollment $enrollment, string $plainSecret): void
    {
        if (!$this->cipher->needsRewrite((string) $enrollment->getSecret())) {
            return;
        }

        $enrollment->setSecret($this->cipher->encrypt($plainSecret));
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

    // Role policy — who *must* use a second factor — moved to
    // SecondFactorRegistry. It was never TOTP's business, and once other
    // factors exist "forced by role" has to be satisfiable by any of them.

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
            $this->getPlainSecret($enrollment),
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
            ->setSecret($this->cipher->encrypt($this->totp->generateSecret()))
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

        $counter = $this->totp->verify($this->getPlainSecret($enrollment), $code, $this->getWindow());
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
     * Turn TOTP off and drop every trusted device with it — otherwise a stale
     * device cookie would outlive the factor it stands in for.
     *
     * @param bool $dropRecoveryCodes Recovery codes belong to the user, not to
     *        this enrollment, so whether they go with it is the caller's call:
     *        they must survive as long as *some* factor is still enrolled, or
     *        an account left holding only a passkey would have no fallback.
     *        Only the caller can see the other factors — this class
     *        deliberately does not know they exist (see SecondFactorRegistry
     *        for why the dependency runs one way).
     */
    public function disable(User $user, bool $dropRecoveryCodes = true): void
    {
        $enrollment = $this->findEnrollment($user);
        if ($enrollment) {
            $this->entityManager->remove($enrollment);
        }
        $this->trustedDevices->revokeAll($user);
        if ($dropRecoveryCodes) {
            $this->recoveryCodes->deleteAll($user);
        }
        $this->entityManager->flush();
    }

    /**
     * Drop every recovery code. For the caller that has just removed the last
     * factor and so has nothing left for the codes to recover into.
     */
    public function deleteRecoveryCodes(User $user): void
    {
        $this->recoveryCodes->deleteAll($user);
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

        $plainSecret = $this->getPlainSecret($enrollment);

        $counter = $this->totp->verify($plainSecret, $code, $this->getWindow());
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
        $this->encryptStoredSecretIfNeeded($enrollment, $plainSecret);
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

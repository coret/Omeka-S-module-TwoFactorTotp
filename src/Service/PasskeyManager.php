<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use DateTime;
use Doctrine\ORM\EntityManager;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Omeka\Entity\User;
use Omeka\Settings\Settings;
use TwoFactorTotp\Entity\WebAuthnCredential;

/**
 * Passkeys: storing the credentials and driving the WebAuthn ceremonies.
 *
 * The library (lbuchs/webauthn) is a Composer dependency and `vendor/` is not
 * committed, so it can genuinely be missing on a fresh checkout. Every method
 * that needs it goes through webAuthn(), which says so plainly rather than
 * fataling on an undefined class.
 *
 * Note what is deliberately *not* guarded: countForUser() and the queries
 * behind it never touch the library. That is what lets PasskeyFactor answer
 * "is this user enrolled" truthfully even when the library is gone — see the
 * comment there for why answering "no" would be a security hole rather than a
 * graceful degradation.
 */
class PasskeyManager
{
    /**
     * 'none' is what platform authenticators send for a second factor, and all
     * we need: the credential is bound to this origin either way. Demanding
     * real attestation would mean maintaining a root certificate store to buy
     * knowledge of the hardware make, which is not what this is for.
     */
    const ATTESTATION_FORMATS = ['none'];

    /** Seconds the browser gives the user to touch the key. */
    const CEREMONY_TIMEOUT = 60;

    /**
     * A hostname and nothing else: labels of alphanumerics and inner hyphens,
     * dot-separated. Anything with a scheme, a path, a space or a stray colon
     * in it is not a host, whatever the Host header claims.
     */
    const HOSTNAME_PATTERN = '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/';

    protected EntityManager $entityManager;

    protected Settings $settings;

    protected ?HttpRequest $request;

    public function __construct(
        EntityManager $entityManager,
        Settings $settings,
        ?HttpRequest $request = null
    ) {
        $this->entityManager = $entityManager;
        $this->settings = $settings;
        $this->request = $request;
    }

    /**
     * Is the WebAuthn library actually installed?
     *
     * False means somebody has checked the module out without running
     * `composer install`. Enrollment hides itself; it must never be taken to
     * mean "this user has no passkey".
     */
    public function isAvailable(): bool
    {
        return class_exists(\lbuchs\WebAuthn\WebAuthn::class);
    }

    // ------------------------------------------------------------- credentials

    /**
     * @return WebAuthnCredential[]
     */
    public function listForUser(User $user): array
    {
        if (!$user->getId()) {
            return [];
        }

        return $this->entityManager
            ->getRepository(WebAuthnCredential::class)
            ->findBy(['user' => $user], ['lastUsedAt' => 'DESC', 'id' => 'ASC']);
    }

    public function countForUser(User $user): int
    {
        return count($this->listForUser($user));
    }

    public function findByCredentialId(string $credentialId): ?WebAuthnCredential
    {
        return $this->entityManager
            ->getRepository(WebAuthnCredential::class)
            ->findOneBy(['credentialId' => $credentialId]);
    }

    public function remove(WebAuthnCredential $credential): void
    {
        $this->entityManager->remove($credential);
        $this->entityManager->flush();
    }

    /**
     * @return int Number removed.
     */
    public function removeAllForUser(User $user): int
    {
        $credentials = $this->listForUser($user);
        foreach ($credentials as $credential) {
            $this->entityManager->remove($credential);
        }
        if ($credentials) {
            $this->entityManager->flush();
        }
        return count($credentials);
    }

    // ---------------------------------------------------------- relying party

    /**
     * The domain the credential is bound to.
     *
     * This is the whole phishing defence: the browser refuses to hand a
     * credential to any other origin. It must be the registrable domain the
     * site is served from — get it wrong and every ceremony fails.
     */
    public function getRelyingPartyId(): string
    {
        $configured = $this->toHostname((string) $this->settings->get('twofactortotp_rp_id', ''));
        if (null !== $configured) {
            return $configured;
        }

        // Fall back to the host actually serving the request, taken from the
        // injected request rather than from $_SERVER — same value, but one
        // that can be reasoned about and tested.
        return $this->toHostname($this->requestHost()) ?? 'localhost';
    }

    protected function requestHost(): string
    {
        if ($this->request) {
            return (string) $this->request->getUri()->getHost();
        }
        return (string) ($_SERVER['HTTP_HOST'] ?? '');
    }

    /**
     * Reduce a configured value or a Host header to a bare hostname, or null
     * if it is not one.
     *
     * A browser will refuse a ceremony whose relying-party id does not cover
     * the origin it is talking to, so a forged Host buys an attacker nothing
     * directly. Validating anyway keeps a header nobody controls from reaching
     * the WebAuthn library as though it were configuration.
     */
    protected function toHostname(string $value): ?string
    {
        $host = strtolower(trim($value));
        $host = (string) preg_replace('/:\d+$/', '', $host);
        $host = trim($host, '[]');

        if ('' === $host) {
            return null;
        }

        return preg_match(self::HOSTNAME_PATTERN, $host) ? $host : null;
    }

    public function getRelyingPartyName(): string
    {
        $configured = trim((string) $this->settings->get('twofactortotp_issuer', ''));
        if ('' !== $configured) {
            return $configured;
        }

        return (string) $this->settings->get('installation_title', 'Omeka S');
    }

    /**
     * @throws \RuntimeException when the library is not installed.
     */
    public function webAuthn(): \lbuchs\WebAuthn\WebAuthn
    {
        if (!$this->isAvailable()) {
            throw new \RuntimeException(
                'The WebAuthn library is not installed. Run "composer install --no-dev" in the module directory.'
            );
        }

        // Base64url encoding on: everything crossing to JavaScript is then a
        // plain string, which is also how credential ids are stored.
        return new \lbuchs\WebAuthn\WebAuthn(
            $this->getRelyingPartyName(),
            $this->getRelyingPartyId(),
            self::ATTESTATION_FORMATS,
            true
        );
    }

    // ------------------------------------------------------------- ceremonies

    /**
     * Arguments for navigator.credentials.create().
     *
     * Existing credentials are excluded so the authenticator says "already
     * registered" instead of silently creating a duplicate.
     *
     * @return array{0: \stdClass, 1: string} The arguments, and the raw
     *         challenge to stash for the verify step.
     */
    public function registrationArgs(User $user): array
    {
        $webAuthn = $this->webAuthn();

        $exclude = array_map(
            fn (WebAuthnCredential $c): string => (string) base64_decode(
                strtr((string) $c->getCredentialId(), '-_', '+/'),
                false
            ),
            $this->listForUser($user)
        );

        $args = $webAuthn->getCreateArgs(
            (string) $user->getId(),
            (string) $user->getEmail(),
            (string) ($user->getName() ?: $user->getEmail()),
            self::CEREMONY_TIMEOUT,
            false,  // no resident key: this is a second factor, not a login
            false,  // user verification not required, see below
            null,
            $exclude
        );

        return [$args, $webAuthn->getChallenge()->getBinaryString()];
    }

    /**
     * Arguments for navigator.credentials.get().
     *
     * The user is already known at this point — they typed a password — so the
     * credential list is scoped to them rather than being a discoverable-
     * credential free-for-all.
     *
     * User verification is *not* required: a PIN or fingerprint on top of the
     * password would be a third factor, and the point here is possession.
     *
     * @return array{0: \stdClass, 1: string} The arguments, and the raw challenge.
     */
    public function assertionArgs(User $user): array
    {
        $webAuthn = $this->webAuthn();

        $credentialIds = array_map(
            fn (WebAuthnCredential $c): string => (string) base64_decode(
                strtr((string) $c->getCredentialId(), '-_', '+/'),
                false
            ),
            $this->listForUser($user)
        );

        $args = $webAuthn->getGetArgs(
            $credentialIds,
            self::CEREMONY_TIMEOUT,
            true,
            true,
            true,
            true,
            true,
            false
        );

        return [$args, $webAuthn->getChallenge()->getBinaryString()];
    }

    /**
     * A signature counter that fails to advance can mean the credential has
     * been copied off its hardware. Authenticators that always report 0 are
     * common and legitimate, so only a genuine regression is suspicious.
     */
    public function isCounterRegression(WebAuthnCredential $credential, int $newCount): bool
    {
        return 0 !== $newCount && $newCount <= $credential->getSignCount();
    }

    public function recordUse(WebAuthnCredential $credential, int $signCount): void
    {
        $credential
            ->setSignCount($signCount)
            ->setLastUsedAt(new DateTime('now'));
        $this->entityManager->flush();
    }
}

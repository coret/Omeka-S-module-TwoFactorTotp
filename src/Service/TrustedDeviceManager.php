<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use DateInterval;
use DateTime;
use Doctrine\ORM\EntityManager;
use Laminas\Http\Header\SetCookie;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Omeka\Entity\User;
use Omeka\Settings\Settings;
use TwoFactorTotp\Entity\TrustedDevice;

/**
 * "Remember this device" — the optional checkbox that lets a browser skip the
 * second step for a while.
 *
 * The cookie is a split token, "selector:validator". The selector is the
 * lookup key; only a SHA-256 of the validator is stored. The validator is
 * rotated on every successful use, so a cookie that is stolen and replayed
 * after the real browser has used it will already be stale.
 */
class TrustedDeviceManager
{
    const COOKIE_NAME = 'twofactortotp_device';

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
     * Days a device stays trusted. 0 disables the feature entirely.
     */
    public function getTrustDays(): int
    {
        return max(0, (int) $this->settings->get('twofactortotp_remember_device_days', 14));
    }

    public function isEnabled(): bool
    {
        return $this->getTrustDays() > 0;
    }

    /**
     * The trusted-device record for this browser, if the cookie it presents is
     * valid *for this user*.
     *
     * Binding to the user matters: without it, a cookie issued to one account
     * would wave through a password-valid login to another.
     */
    public function findValidDevice(User $user): ?TrustedDevice
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $cookieValue = $this->readCookie();
        if (null === $cookieValue) {
            return null;
        }

        [$selector, $validator] = $this->splitToken($cookieValue);
        if (null === $selector || null === $validator) {
            return null;
        }

        $device = $this->entityManager
            ->getRepository(TrustedDevice::class)
            ->findOneBy(['selector' => $selector]);

        if (!$device) {
            return null;
        }

        if (!hash_equals((string) $device->getValidatorHash(), $this->hashValidator($validator))) {
            return null;
        }

        if ($device->getUser() !== $user) {
            return null;
        }

        if ($device->isExpired()) {
            $this->entityManager->remove($device);
            $this->entityManager->flush();
            return null;
        }

        return $device;
    }

    /**
     * Trust this browser. Returns the cookie value to send.
     */
    public function issue(User $user, ?string $label = null): ?string
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(16));

        $device = new TrustedDevice();
        $device
            ->setUser($user)
            ->setSelector($selector)
            ->setValidatorHash($this->hashValidator($validator))
            ->setExpires((new DateTime('now'))->add(new DateInterval('P' . $this->getTrustDays() . 'D')))
            ->setLabel($label ?? $this->describeCurrentClient())
            ->setLastUsedAt(new DateTime('now'));

        $this->entityManager->persist($device);
        $this->entityManager->flush();

        return $selector . ':' . $validator;
    }

    /**
     * Mint a new validator for an existing device and extend it.
     *
     * Rotation is what makes cookie theft detectable rather than silent.
     *
     * @return string The new cookie value.
     */
    public function rotate(TrustedDevice $device): string
    {
        $validator = bin2hex(random_bytes(16));

        $device
            ->setValidatorHash($this->hashValidator($validator))
            ->setExpires((new DateTime('now'))->add(new DateInterval('P' . $this->getTrustDays() . 'D')))
            ->setLastUsedAt(new DateTime('now'));

        $this->entityManager->flush();

        return $device->getSelector() . ':' . $validator;
    }

    /**
     * @return TrustedDevice[]
     */
    public function listForUser(User $user): array
    {
        return $this->entityManager
            ->getRepository(TrustedDevice::class)
            ->findBy(['user' => $user], ['lastUsedAt' => 'DESC']);
    }

    public function revoke(TrustedDevice $device): void
    {
        $this->entityManager->remove($device);
        $this->entityManager->flush();
    }

    /**
     * Drop every device for a user. Called on disable, on password change and
     * from the "revoke all" button.
     */
    public function revokeAll(User $user): int
    {
        $devices = $this->listForUser($user);
        foreach ($devices as $device) {
            $this->entityManager->remove($device);
        }
        if ($devices) {
            $this->entityManager->flush();
        }
        return count($devices);
    }

    /**
     * Housekeeping for rows whose expiry has passed unvisited.
     */
    public function purgeExpired(): int
    {
        return (int) $this->entityManager
            ->createQuery('DELETE FROM ' . TrustedDevice::class . ' d WHERE d.expires <= :now')
            ->setParameter('now', new DateTime('now'))
            ->execute();
    }

    // --------------------------------------------------------------- cookies

    public function buildSetCookie(string $value): SetCookie
    {
        $cookie = new SetCookie(
            self::COOKIE_NAME,
            $value,
            (new DateTime('now'))->add(new DateInterval('P' . $this->getTrustDays() . 'D'))->getTimestamp(),
            '/',
            null,
            $this->isHttps(),
            true // httpOnly: no script ever needs to read this
        );
        // Lax rather than Strict: the cookie must survive arriving at /login
        // from an external link, which is the normal way people log in.
        $cookie->setSameSite('Lax');
        return $cookie;
    }

    public function buildClearCookie(): SetCookie
    {
        $cookie = new SetCookie(self::COOKIE_NAME, '', 1, '/', null, $this->isHttps(), true);
        $cookie->setSameSite('Lax');
        return $cookie;
    }

    protected function readCookie(): ?string
    {
        if ($this->request) {
            $cookies = $this->request->getCookie();
            if ($cookies && isset($cookies[self::COOKIE_NAME])) {
                return (string) $cookies[self::COOKIE_NAME];
            }
            return null;
        }
        return isset($_COOKIE[self::COOKIE_NAME]) ? (string) $_COOKIE[self::COOKIE_NAME] : null;
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    protected function splitToken(string $value): array
    {
        $parts = explode(':', $value, 2);
        if (2 !== count($parts)) {
            return [null, null];
        }
        [$selector, $validator] = $parts;
        if (!preg_match('/^[a-f0-9]{32}$/', $selector) || !preg_match('/^[a-f0-9]{32}$/', $validator)) {
            return [null, null];
        }
        return [$selector, $validator];
    }

    protected function hashValidator(string $validator): string
    {
        // SHA-256, not bcrypt: the validator is 128 bits of CSPRNG output, so
        // there is nothing to brute-force and this is checked on every request.
        return hash('sha256', $validator);
    }

    protected function isHttps(): bool
    {
        if ($this->request) {
            return 'https' === $this->request->getUri()->getScheme();
        }
        return !empty($_SERVER['HTTPS']) && 'off' !== $_SERVER['HTTPS'];
    }

    /**
     * A rough "Firefox on Linux" label so the revoke list is meaningful.
     */
    protected function describeCurrentClient(): ?string
    {
        $userAgent = null;
        if ($this->request) {
            $header = $this->request->getHeader('User-Agent');
            $userAgent = $header ? $header->getFieldValue() : null;
        } else {
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        }
        if (!$userAgent) {
            return null;
        }

        $browser = 'Unknown browser';
        foreach ([
            'Edg' => 'Edge',
            'OPR' => 'Opera',
            'Chrome' => 'Chrome',
            'Safari' => 'Safari',
            'Firefox' => 'Firefox',
        ] as $needle => $name) {
            if (false !== stripos($userAgent, $needle)) {
                $browser = $name;
                break;
            }
        }

        $platform = 'Unknown platform';
        foreach ([
            'Windows' => 'Windows',
            'Android' => 'Android',
            'iPhone' => 'iOS',
            'iPad' => 'iOS',
            'Mac OS X' => 'macOS',
            'Linux' => 'Linux',
        ] as $needle => $name) {
            if (false !== stripos($userAgent, $needle)) {
                $platform = $name;
                break;
            }
        }

        return sprintf('%s on %s', $browser, $platform);
    }
}

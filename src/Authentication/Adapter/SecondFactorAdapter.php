<?php declare(strict_types=1);

namespace TwoFactorTotp\Authentication\Adapter;

use Laminas\Authentication\Adapter\AbstractAdapter;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\Result;
use Omeka\Entity\User;
use TwoFactorTotp\Service\SecondFactorRegistry;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * Wraps Omeka's PasswordAdapter (or whatever another module put in its place)
 * and downgrades a password-valid result to a failure when the user still owes
 * a TOTP code.
 *
 * This is where the module's security invariant is enforced:
 *
 *     No identity is ever written to the authentication storage until the
 *     second factor has passed.
 *
 * It holds because Laminas' AuthenticationService writes to storage only when
 * the adapter returns a valid Result (AuthenticationService::authenticate(),
 * line 115). Putting the check here rather than in the login controller means
 * every caller of $auth->authenticate() inherits it — including login forms
 * belonging to other modules, which would otherwise be a silent bypass.
 *
 * The corresponding UX (the code form) lives in the controller layer, which
 * recognises MSG_SECOND_FACTOR_REQUIRED and picks the pending user up from
 * getPendingUser().
 */
class SecondFactorAdapter extends AbstractAdapter
{
    /**
     * Marker in Result::getMessages() saying "password was right, code still
     * needed". Deliberately not a human-readable sentence: it is a protocol
     * between this adapter and our login controller, never shown to a user.
     */
    const MSG_SECOND_FACTOR_REQUIRED = 'twofactortotp:second_factor_required';

    protected AdapterInterface $innerAdapter;

    protected SecondFactorRegistry $registry;

    protected TrustedDeviceManager $trustedDevices;

    /**
     * The password-verified user awaiting a code. Never exposed as an identity.
     */
    protected ?User $pendingUser = null;

    /**
     * Set when a trusted-device cookie was accepted and rotated, so the
     * controller can send the refreshed value.
     */
    protected ?string $rotatedDeviceCookie = null;

    public function __construct(
        AdapterInterface $innerAdapter,
        SecondFactorRegistry $registry,
        TrustedDeviceManager $trustedDevices
    ) {
        $this->innerAdapter = $innerAdapter;
        $this->registry = $registry;
        $this->trustedDevices = $trustedDevices;
    }

    public function authenticate()
    {
        $this->pendingUser = null;
        $this->rotatedDeviceCookie = null;

        // Step 1 is entirely the inner adapter's business, so wrong-password
        // behaviour — and anything the Lockout module counts — is unchanged.
        $this->innerAdapter->setIdentity($this->identity);
        $this->innerAdapter->setCredential($this->credential);
        $result = $this->innerAdapter->authenticate();

        if (!$result->isValid()) {
            return $result;
        }

        $user = $result->getIdentity();
        if (!$user instanceof User) {
            // An adapter we do not understand. Fail closed rather than guess:
            // letting an unrecognised identity through would defeat the point.
            return $result;
        }

        // Asked of the registry rather than of any one factor: a user enrolled
        // in something this adapter had not heard of would otherwise be waved
        // through on their password alone.
        //
        // A user who is merely *forced* by role but not yet enrolled has no
        // second factor to present. They are let in and then confined to the
        // setup page by Module's route listener.
        if (!$this->registry->hasAnyEnrolled($user)) {
            return $result;
        }

        $device = $this->trustedDevices->findValidDevice($user);
        if ($device) {
            $this->rotatedDeviceCookie = $this->trustedDevices->rotate($device);
            return $result;
        }

        $this->pendingUser = $user;

        return new Result(
            Result::FAILURE_UNCATEGORIZED,
            null,
            [self::MSG_SECOND_FACTOR_REQUIRED]
        );
    }

    /**
     * The user whose password checked out but who still owes a code.
     */
    public function getPendingUser(): ?User
    {
        return $this->pendingUser;
    }

    public function getRotatedDeviceCookie(): ?string
    {
        return $this->rotatedDeviceCookie;
    }

    public function getInnerAdapter(): AdapterInterface
    {
        return $this->innerAdapter;
    }

    /**
     * Did this result mean "password fine, code needed"?
     */
    public static function isSecondFactorRequired(Result $result): bool
    {
        return !$result->isValid()
            && in_array(self::MSG_SECOND_FACTOR_REQUIRED, $result->getMessages(), true);
    }

    /**
     * Forward anything else to the wrapped adapter.
     *
     * Omeka's PasswordAdapter has setRepository()/getRepository(), and the
     * Guest and UserNames modules ship adapters with methods of their own.
     * Without this, wrapping would break those callers.
     *
     * @param string $name
     * @param array $arguments
     */
    public function __call($name, $arguments)
    {
        if (!method_exists($this->innerAdapter, $name)) {
            throw new \BadMethodCallException(sprintf(
                'Neither %s nor the wrapped adapter %s has a method "%s".',
                static::class,
                get_class($this->innerAdapter),
                $name
            ));
        }
        return call_user_func_array([$this->innerAdapter, $name], $arguments);
    }
}

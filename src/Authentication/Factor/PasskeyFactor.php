<?php declare(strict_types=1);

namespace TwoFactorTotp\Authentication\Factor;

use Omeka\Entity\User;
use TwoFactorTotp\Authentication\SecondFactorInterface;
use TwoFactorTotp\Service\PasskeyManager;

/**
 * A registered passkey: hardware key, Touch ID, Windows Hello.
 *
 * Registered with the factor registry but not yet reachable — the routes and
 * templates arrive in a later step. Until a user has a credential it is inert,
 * and nobody can get one yet.
 */
class PasskeyFactor implements SecondFactorInterface
{
    const NAME = 'passkey';

    protected PasskeyManager $passkeys;

    public function __construct(PasskeyManager $passkeys)
    {
        $this->passkeys = $passkeys;
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function getLabel(): string
    {
        return 'Use a passkey'; // @translate
    }

    /**
     * Does this user hold a passkey?
     *
     * Deliberately a plain credential count, with no check that the WebAuthn
     * library is installed. It is tempting to return false when the library is
     * missing — "the factor cannot work, so it is not enrolled" — but that
     * fails *open*: a user whose only factor is a passkey would then be let in
     * on their password alone, which is precisely the attack a second factor
     * exists to stop.
     *
     * Answering true with the library absent means such a user is held at step
     * two and told the truth. They still have their recovery codes, which is
     * why those moved to the user before any of this landed.
     */
    public function isEnrolled(User $user): bool
    {
        return $this->passkeys->countForUser($user) > 0;
    }

    public function getChallengeRoute(): array
    {
        return ['two-factor', ['action' => 'passkey']];
    }

    public function getEnrollmentRoute(): array
    {
        return ['admin/two-factor', ['action' => 'passkeys']];
    }
}

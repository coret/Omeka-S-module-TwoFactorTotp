<?php declare(strict_types=1);

namespace TwoFactorTotp\Service;

use Omeka\Entity\User;
use Omeka\Settings\Settings;
use TwoFactorTotp\Authentication\SecondFactorInterface;

/**
 * The set of second factors this installation knows about, and the policy for
 * who has to use one.
 *
 * Everything on the login path asks this rather than asking a particular
 * factor. That is the whole point: adding a factor should not mean revisiting
 * the authentication adapter, and forgetting to revisit it would mean a user
 * enrolled in the new factor sails through on their password.
 *
 * Note it does *not* depend on TotpManager. The dependency runs registry ->
 * factor -> manager, one way. Wiring it the other way would put the registry
 * and the entity manager in a cycle, which in this module has already once
 * meant a site-wide 500.
 */
class SecondFactorRegistry
{
    /** @var SecondFactorInterface[] keyed by name */
    protected array $factors = [];

    protected Settings $settings;

    /**
     * @param SecondFactorInterface[] $factors
     */
    public function __construct(array $factors, Settings $settings)
    {
        foreach ($factors as $factor) {
            $this->factors[$factor->getName()] = $factor;
        }
        $this->settings = $settings;
    }

    /**
     * @return SecondFactorInterface[]
     */
    public function all(): array
    {
        return $this->factors;
    }

    public function get(string $name): ?SecondFactorInterface
    {
        return $this->factors[$name] ?? null;
    }

    /**
     * The factors this user could actually present right now.
     *
     * @return SecondFactorInterface[]
     */
    public function getEnrolled(User $user): array
    {
        return array_filter(
            $this->factors,
            fn (SecondFactorInterface $factor): bool => $factor->isEnrolled($user)
        );
    }

    /**
     * Does this login owe a second step?
     *
     * The single question the authentication adapter asks.
     */
    public function hasAnyEnrolled(User $user): bool
    {
        foreach ($this->factors as $factor) {
            if ($factor->isEnrolled($user)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Where to send a login that owes a factor.
     *
     * With one enrolled factor this goes straight there. With several it will
     * become a chooser; until a second factor type exists there is nothing to
     * choose between, so the first enrolled one wins.
     */
    public function getChallengeRouteFor(User $user): ?array
    {
        $enrolled = $this->getEnrolled($user);
        $first = reset($enrolled);
        return $first ? $first->getChallengeRoute() : null;
    }

    // ------------------------------------------------------------ role policy

    /**
     * Roles for which a second factor is mandatory. Not specific to any one
     * factor — any enrolled factor satisfies it.
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
     * Forced by role but holding no factor at all: must set one up before
     * doing anything else.
     */
    public function mustEnroll(User $user): bool
    {
        return $this->isRoleForced($user) && !$this->hasAnyEnrolled($user);
    }

    /**
     * Where such a user is sent to set one up.
     *
     * Once there is a choice this becomes a picker; for now the first
     * registered factor is the only one.
     */
    public function getEnrollmentRoute(): ?array
    {
        $first = reset($this->factors);
        return $first ? $first->getEnrollmentRoute() : null;
    }
}

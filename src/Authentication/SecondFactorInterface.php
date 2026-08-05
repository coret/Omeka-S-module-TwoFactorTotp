<?php declare(strict_types=1);

namespace TwoFactorTotp\Authentication;

use Omeka\Entity\User;

/**
 * One kind of second factor: an authenticator app, a passkey, whatever comes
 * next.
 *
 * The point of this interface is that nothing on the login path should need to
 * know which kinds exist. Before it, the authentication adapter asked
 * TotpManager directly whether the user owed a second step, which meant a user
 * enrolled in anything *else* would have been waved straight through on their
 * password alone — the failure mode you least want.
 *
 * Implementations answer three things: what am I called, is this user enrolled,
 * and where do I send them.
 */
interface SecondFactorInterface
{
    /**
     * Stable machine name, used in routes and settings. Never shown to a user.
     */
    public function getName(): string;

    /**
     * Untranslated label for the factor chooser. Callers translate it.
     */
    public function getLabel(): string;

    /**
     * Has this user finished setting this factor up?
     *
     * A half-finished enrollment must answer false: the user cannot present it
     * yet, so treating it as enrolled would lock them out.
     */
    public function isEnrolled(User $user): bool;

    /**
     * Where a login that owes this factor goes to present it.
     *
     * @return array{0: string, 1: array} Route name and parameters.
     */
    public function getChallengeRoute(): array;

    /**
     * Where a user goes to set this factor up.
     *
     * @return array{0: string, 1: array} Route name and parameters.
     */
    public function getEnrollmentRoute(): array;
}

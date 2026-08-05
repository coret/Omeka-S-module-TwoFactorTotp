<?php declare(strict_types=1);

namespace TwoFactorTotp\Authentication\Factor;

use Omeka\Entity\User;
use TwoFactorTotp\Authentication\SecondFactorInterface;
use TwoFactorTotp\Service\TotpManager;

/**
 * A code from an authenticator app.
 *
 * A thin front onto TotpManager: this adds no behaviour, it only lets the
 * login path talk about "a second factor" instead of about TOTP specifically.
 */
class TotpFactor implements SecondFactorInterface
{
    const NAME = 'totp';

    protected TotpManager $totpManager;

    public function __construct(TotpManager $totpManager)
    {
        $this->totpManager = $totpManager;
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function getLabel(): string
    {
        // Extracted for translation by the callers that display it.
        return 'Code from your app'; // @translate
    }

    /**
     * True only once enrollment is confirmed — an unconfirmed secret has never
     * been proven to work, so the user could not present it.
     */
    public function isEnrolled(User $user): bool
    {
        return $this->totpManager->isEnabled($user);
    }

    public function getChallengeRoute(): array
    {
        return ['two-factor', []];
    }

    public function getEnrollmentRoute(): array
    {
        return ['admin/two-factor', ['action' => 'setup']];
    }
}

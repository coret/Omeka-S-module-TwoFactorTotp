<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Authentication\Factor\PasskeyFactor;
use TwoFactorTotp\Authentication\Factor\TotpFactor;
use TwoFactorTotp\Service\SecondFactorRegistry;

/**
 * The one place that knows which factors exist. A new factor is registered
 * here and nothing on the login path changes.
 */
class SecondFactorRegistryFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new SecondFactorRegistry(
            [
                // Order matters in one place only: a user forced to enroll but
                // holding nothing is sent to the first factor's setup page.
                // TOTP leads because it needs no special hardware.
                $services->get(TotpFactor::class),
                $services->get(PasskeyFactor::class),
            ],
            $services->get('Omeka\Settings')
        );
    }
}

<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\Totp;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;

class TotpManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new TotpManager(
            $services->get('Omeka\EntityManager'),
            $services->get(Totp::class),
            $services->get('Omeka\Settings'),
            $services->get(TrustedDeviceManager::class)
        );
    }
}

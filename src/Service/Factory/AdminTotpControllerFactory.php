<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Controller\Admin\TotpController;
use TwoFactorTotp\Service\SecondFactorRegistry;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;

class AdminTotpControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new TotpController(
            $services->get('Omeka\EntityManager'),
            $services->get(TotpManager::class),
            $services->get(TrustedDeviceManager::class),
            $services->get(SecondFactorRegistry::class)
        );
    }
}

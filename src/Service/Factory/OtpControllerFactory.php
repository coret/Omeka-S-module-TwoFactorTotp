<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Controller\OtpController;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\PendingLogin;

class OtpControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new OtpController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService'),
            $services->get(TotpManager::class),
            $services->get(TrustedDeviceManager::class),
            $services->get(PendingLogin::class)
        );
    }
}

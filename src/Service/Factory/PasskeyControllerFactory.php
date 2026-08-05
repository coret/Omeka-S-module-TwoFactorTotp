<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Controller\PasskeyController;
use TwoFactorTotp\Service\PasskeyManager;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\ChallengeStore;
use TwoFactorTotp\Stdlib\PendingLogin;

class PasskeyControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new PasskeyController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService'),
            $services->get(PasskeyManager::class),
            $services->get(TrustedDeviceManager::class),
            $services->get(PendingLogin::class),
            $services->get(ChallengeStore::class)
        );
    }
}

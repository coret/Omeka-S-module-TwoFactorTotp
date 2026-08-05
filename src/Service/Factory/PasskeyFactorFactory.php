<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Authentication\Factor\PasskeyFactor;
use TwoFactorTotp\Service\PasskeyManager;

class PasskeyFactorFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new PasskeyFactor($services->get(PasskeyManager::class));
    }
}

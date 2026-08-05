<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Authentication\Factor\TotpFactor;
use TwoFactorTotp\Service\TotpManager;

class TotpFactorFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new TotpFactor($services->get(TotpManager::class));
    }
}

<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\FactorThrottle;

class FactorThrottleFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new FactorThrottle(
            $services->get('Omeka\Settings\User'),
            $services->get('Omeka\Settings')
        );
    }
}

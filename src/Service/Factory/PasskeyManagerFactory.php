<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\PasskeyManager;

class PasskeyManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new PasskeyManager(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\Settings')
        );
    }
}

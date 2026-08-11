<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Laminas\Session\Container;
use TwoFactorTotp\Stdlib\PasswordConfirmation;

class PasswordConfirmationFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new PasswordConfirmation(
            new Container(PasswordConfirmation::CONTAINER_NAME),
            PasswordConfirmation::DEFAULT_TTL
        );
    }
}

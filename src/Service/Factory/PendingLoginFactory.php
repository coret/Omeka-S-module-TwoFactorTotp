<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Laminas\Session\Container;
use TwoFactorTotp\Stdlib\PendingLogin;

class PendingLoginFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        $settings = $services->get('Omeka\Settings');

        return new PendingLogin(
            new Container(PendingLogin::CONTAINER_NAME),
            (int) $settings->get('twofactortotp_pending_ttl', 300),
            (int) $settings->get('twofactortotp_max_attempts', 5)
        );
    }
}

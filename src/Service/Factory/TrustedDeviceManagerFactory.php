<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\TrustedDeviceManager;

class TrustedDeviceManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        // Under the CLI (jobs, omeka-s-cli) the request is a console request
        // with no cookies; the manager then simply never finds a device.
        $request = $services->get('Request');

        return new TrustedDeviceManager(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\Settings'),
            $request instanceof HttpRequest ? $request : null
        );
    }
}

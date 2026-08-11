<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\PasskeyManager;

class PasskeyManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        // Under the CLI (jobs, omeka-s-cli) the request is a console request
        // with no host; the relying-party id then has to come from the setting.
        $request = $services->get('Request');

        return new PasskeyManager(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\Settings'),
            $request instanceof HttpRequest ? $request : null
        );
    }
}

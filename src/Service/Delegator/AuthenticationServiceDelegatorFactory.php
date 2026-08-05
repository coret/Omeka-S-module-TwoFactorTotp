<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use Omeka\Authentication\Adapter\KeyAdapter;
use TwoFactorTotp\Authentication\Adapter\SecondFactorAdapter;
use TwoFactorTotp\Service\SecondFactorRegistry;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * Wraps the authentication adapter Omeka built (see
 * Omeka\Service\AuthenticationServiceFactory) in our SecondFactorAdapter.
 *
 * A delegator rather than a factory override so that this composes with any
 * other module that also decorates the authentication service, instead of one
 * of them silently winning.
 */
class AuthenticationServiceDelegatorFactory implements DelegatorFactoryInterface
{
    public function __invoke(
        ContainerInterface $services,
        $name,
        callable $callback,
        ?array $options = null
    ) {
        /** @var \Laminas\Authentication\AuthenticationService $authenticationService */
        $authenticationService = $callback();

        $adapter = $authenticationService->getAdapter();

        // API-key requests authenticate with a key pair, not a password, and
        // there is no human present to type a code. Leave them alone — wrapping
        // here would break every API client.
        if ($adapter instanceof KeyAdapter) {
            return $authenticationService;
        }

        // Already wrapped (the service was rebuilt within one request).
        if ($adapter instanceof SecondFactorAdapter) {
            return $authenticationService;
        }

        return $authenticationService->setAdapter(new SecondFactorAdapter(
            $adapter,
            $services->get(SecondFactorRegistry::class),
            $services->get(TrustedDeviceManager::class)
        ));
    }
}

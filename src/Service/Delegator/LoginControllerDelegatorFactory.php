<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use Omeka\Controller\LoginController as CoreLoginController;
use TwoFactorTotp\Controller\LoginController;
use TwoFactorTotp\Service\SecondFactorRegistry;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\PendingLogin;

/**
 * Swaps Omeka's login controller for our subclass, which understands the
 * "password fine, code needed" result that SecondFactorAdapter returns.
 *
 * Core's loginAction() prints "Email or password is invalid" for *any* invalid
 * result, so without this the second-factor case would look like a typo'd
 * password.
 */
class LoginControllerDelegatorFactory implements DelegatorFactoryInterface
{
    public function __invoke(
        ContainerInterface $services,
        $name,
        callable $callback,
        ?array $options = null
    ) {
        $controller = $callback();

        // Our subclass only knows how to stand in for core's controller. If
        // another module (Guest, UserNames, SingleSignOn, TwoFactorAuth) has
        // already replaced it, silently swapping ours in would throw that
        // module's behaviour away. Refuse loudly instead of failing open: the
        // adapter still blocks the login, so the site stays safe — the user
        // just gets a login they cannot complete, which is a visible,
        // reportable failure rather than a quiet 2FA bypass.
        if (CoreLoginController::class !== get_class($controller)) {
            $services->get('Omeka\Logger')->err(sprintf(
                'TwoFactorTotp: the login controller is %s, not %s. Another module has replaced it, '
                . 'so the two-factor login screen was not installed. Disable the conflicting module.',
                get_class($controller),
                CoreLoginController::class
            ));
            return $controller;
        }

        return new LoginController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService'),
            $services->get(TrustedDeviceManager::class),
            $services->get(PendingLogin::class),
            $services->get(SecondFactorRegistry::class)
        );
    }
}

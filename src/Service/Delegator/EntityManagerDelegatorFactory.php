<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Delegator;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\DelegatorFactoryInterface;
use TwoFactorTotp\Db\Event\Subscriber\RevokeDevicesOnPasswordChange;

/**
 * Attaches the password-change subscriber to the entity manager.
 *
 * A delegator rather than an onBootstrap hook: this runs exactly when the
 * entity manager is first built, so the module does not force it into
 * existence on requests that would never have touched the database.
 */
class EntityManagerDelegatorFactory implements DelegatorFactoryInterface
{
    public function __invoke(
        ContainerInterface $services,
        $name,
        callable $callback,
        ?array $options = null
    ) {
        /** @var \Doctrine\ORM\EntityManager $entityManager */
        $entityManager = $callback();

        // The logger is passed unresolved. Asking the container for it here
        // would re-enter this very construction — Omeka\Logger gains a user-id
        // processor (Log module) that needs Omeka\AuthenticationService, whose
        // factory asks for Omeka\EntityManager, which is not cached until this
        // delegator returns — and recurse until the stack dies.
        $entityManager->getEventManager()->addEventSubscriber(
            new RevokeDevicesOnPasswordChange(
                fn () => $services->get('Omeka\Logger')
            )
        );

        return $entityManager;
    }
}

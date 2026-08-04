<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\Common\EventManager;
use Laminas\ServiceManager\ServiceManager;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Db\Event\Subscriber\RevokeDevicesOnPasswordChange;
use TwoFactorTotp\Service\Delegator\EntityManagerDelegatorFactory;

/**
 * The entity manager delegator must not pull other services into existence
 * while the entity manager is still being built.
 *
 * Resolving Omeka\Logger there deadlocks against the Log module, whose logger
 * factory adds a user-id processor, which needs Omeka\AuthenticationService,
 * whose factory asks for Omeka\EntityManager — which is the very service still
 * under construction. The service manager cannot return the cached instance
 * yet, so it re-enters this delegator and recurses until the stack dies.
 */
class EntityManagerDelegatorTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    /**
     * A stand-in for the entity manager: all the delegator touches is
     * getEventManager()->addEventSubscriber().
     */
    private function fakeEntityManager(EventManager $eventManager): object
    {
        return new class ($eventManager) {
            public function __construct(private EventManager $eventManager)
            {
            }

            public function getEventManager(): EventManager
            {
                return $this->eventManager;
            }
        };
    }

    public function testDoesNotResolveTheLoggerWhileTheEntityManagerIsBeingBuilt(): void
    {
        $services = new ServiceManager(['factories' => [
            'Omeka\Logger' => function (): void {
                throw new \LogicException(
                    'Omeka\Logger was resolved during entity manager construction.'
                );
            },
        ]]);

        $eventManager = new EventManager();
        $entityManager = $this->fakeEntityManager($eventManager);

        $delegator = new EntityManagerDelegatorFactory();
        $returned = $delegator($services, 'Omeka\EntityManager', fn () => $entityManager);

        $this->assertSame($entityManager, $returned);
        $this->assertNotEmpty(
            $eventManager->getListeners('postFlush'),
            'The subscriber should still be attached.'
        );
    }

    public function testSubscriberDefersResolvingTheLogger(): void
    {
        $calls = 0;
        new RevokeDevicesOnPasswordChange(function () use (&$calls) {
            $calls++;
            return null;
        });

        $this->assertSame(0, $calls, 'The logger resolver must not run on construction.');
    }
}

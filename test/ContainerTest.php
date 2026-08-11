<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\ORM\EntityManager;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Laminas\ServiceManager\ServiceManager;
use Omeka\Settings\Settings;
use Omeka\Settings\UserSettings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Stdlib\ChallengeStore;
use TwoFactorTotp\Stdlib\PasswordConfirmation;
use TwoFactorTotp\Stdlib\PendingLogin;

/**
 * Every factory actually runs.
 *
 * verify-wiring.php checks that the classes named in module.config.php exist,
 * which is not the same thing: a factory whose `new Foo(...)` no longer matches
 * Foo's constructor passes that check and then throws ArgumentCountError on the
 * first request. Since the login controller is replaced by this module, "the
 * first request" means nobody can log in.
 *
 * So this builds each service and controller for real, against stub Omeka
 * services. The three session-backed stores are pre-seeded rather than built:
 * Laminas' session Container wants a live session, which the CLI has not got,
 * and their own factories are covered by the classes' own tests.
 */
class ContainerTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function container(): ServiceManager
    {
        $config = include dirname(__DIR__) . '/config/module.config.php';

        $services = new ServiceManager([
            'factories' => $config['service_manager']['factories'],
        ]);

        // Omeka's side of the world.
        $services->setService('Omeka\EntityManager', $this->createMock(EntityManager::class));
        $services->setService('Omeka\Settings', $this->createMock(Settings::class));
        $services->setService('Omeka\Settings\User', $this->createMock(UserSettings::class));
        $services->setService('Omeka\AuthenticationService', $this->createMock(\Laminas\Authentication\AuthenticationService::class));
        $services->setService('Omeka\Logger', $this->createMock(\Laminas\Log\Logger::class));
        $services->setService('Request', new HttpRequest());
        $services->setService('Config', []);

        // Session-backed, so seeded rather than built.
        $services->setService(ChallengeStore::class, new ChallengeStore(new \Laminas\Stdlib\ArrayObject()));
        $services->setService(PasswordConfirmation::class, new PasswordConfirmation(new \Laminas\Stdlib\ArrayObject()));
        $services->setService(PendingLogin::class, $this->createMock(PendingLogin::class));

        return $services;
    }

    /**
     * @dataProvider moduleServices
     */
    public function testEveryServiceBuilds(string $name): void
    {
        $this->assertInstanceOf($name, $this->container()->get($name));
    }

    public function moduleServices(): array
    {
        $config = include dirname(__DIR__) . '/config/module.config.php';

        // The seeded three are not exercised here; see the class comment.
        $seeded = [ChallengeStore::class, PasswordConfirmation::class, PendingLogin::class];

        $cases = [];
        foreach (array_keys($config['service_manager']['factories']) as $service) {
            if (!in_array($service, $seeded, true)) {
                $cases[$service] = [$service];
            }
        }

        return $cases;
    }

    /**
     * The ones that matter most: a controller that cannot be built is a page
     * nobody can reach, and two of these three are on the login path.
     *
     * @dataProvider moduleControllers
     */
    public function testEveryControllerBuilds(string $name, string $factory): void
    {
        $services = $this->container();

        $this->assertInstanceOf($name, (new $factory())($services, $name));
    }

    public function moduleControllers(): array
    {
        $config = include dirname(__DIR__) . '/config/module.config.php';

        $cases = [];
        foreach ($config['controllers']['factories'] as $controller => $factory) {
            $cases[$controller] = [$controller, $factory];
        }

        return $cases;
    }
}

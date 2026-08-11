<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\DBAL\Connection;
use Laminas\ServiceManager\ServiceManager;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__) . '/Module.php';

/**
 * upgrade() runs in a crippled container.
 *
 * Raising the version in module.ini puts the module into `needs_upgrade`, and
 * Omeka merges the config of *active* modules only (Omeka\Mvc\Application::init
 * asks getModulesByState(STATE_ACTIVE)). So at the moment upgrade() runs, none
 * of this module's own services are registered — asking for one throws
 * ServiceNotFoundException, the upgrade aborts part-way, and Omeka never
 * records the new version. The module then stays in needs_upgrade for ever,
 * which for this module means two-factor authentication stays off.
 *
 * The pre-existing migrateRecoveryCodes() took only a Connection for exactly
 * this reason. This test makes the rule enforceable rather than remembered.
 */
class UpgradeTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    /**
     * Exactly what Omeka hands upgrade(): core services, and nothing of ours.
     */
    private function crippledContainer(array $moduleConfig = []): ServiceManager
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('executeStatement')->willReturn(0);
        $connection->method('fetchAllAssociative')->willReturn([]);
        $connection->method('fetchOne')->willReturn(1);

        $services = new ServiceManager();
        $services->setService('Omeka\Connection', $connection);
        $services->setService('Config', ['twofactortotp' => $moduleConfig]);

        return $services;
    }

    public function testUpgradingFromTheReleasedVersionDoesNotNeedTheModulesOwnServices(): void
    {
        $module = new \TwoFactorTotp\Module();

        $module->upgrade('0.2.2', '0.3.0', $this->crippledContainer());

        // Reaching here at all is the assertion: the previous implementation
        // threw ServiceNotFoundException on TwoFactorTotp\Service\SecretCipher.
        $this->addToAssertionCount(1);
    }

    /**
     * And with a key configured, because that is the path that actually wants
     * the cipher — the one that broke.
     */
    public function testUpgradingWithAnEncryptionKeyConfiguredAlsoWorks(): void
    {
        $module = new \TwoFactorTotp\Module();

        $module->upgrade('0.2.2', '0.3.0', $this->crippledContainer([
            'encryption_key' => 'a-key-set-in-local-config',
        ]));

        $this->addToAssertionCount(1);
    }

    /**
     * The full span, in case somebody upgrades straight from 0.1.
     */
    public function testUpgradingFromTheOldestVersionWorksToo(): void
    {
        $module = new \TwoFactorTotp\Module();

        $module->upgrade('0.1', '0.3.0', $this->crippledContainer([
            'encryption_key' => 'a-key-set-in-local-config',
        ]));

        $this->addToAssertionCount(1);
    }

    /**
     * The module's own classes load with nothing but Module.php.
     *
     * This has to run in a subprocess, because the point is the *absence* of
     * something this test suite always has: bootstrap.php registers a PSR-4
     * autoloader for TwoFactorTotp\, and Omeka does not. Omeka registers a
     * module's autoloader (AbstractModule::getAutoloaderConfig) only for
     * modules it loads, and it does not load one awaiting upgrade — it just
     * does `new TwoFactorTotp\Module` and calls upgrade() on it.
     *
     * So in-process this property is untestable: the suite's own autoloader
     * makes it pass whether or not it is true. It did exactly that, and the
     * upgrade failed in production regardless.
     */
    public function testTheModulesClassesLoadWithoutTheSuitesAutoloader(): void
    {
        $moduleDir = dirname(__DIR__);
        $vendor = getenv('OMEKA_VENDOR') ?: dirname($moduleDir, 2) . '/vendor';

        if (!is_readable($vendor . '/autoload.php')) {
            $this->markTestSkipped('Needs Omeka\'s vendor/; set OMEKA_VENDOR.');
        }

        $script = sprintf(
            'require %s; require %s; ' .
            'exit(class_exists(%s) && class_exists(%s) ? 0 : 1);',
            var_export($vendor . '/autoload.php', true),
            var_export($moduleDir . '/Module.php', true),
            var_export(\TwoFactorTotp\Service\SecretCipher::class, true),
            var_export(\TwoFactorTotp\Service\TotpManager::class, true)
        );

        exec(sprintf('%s -r %s 2>&1', escapeshellarg(PHP_BINARY), escapeshellarg($script)), $output, $status);

        $this->assertSame(
            0,
            $status,
            "Module.php must make the module's own classes loadable, because upgrade() "
            . "runs before Omeka has registered anything for it.\n" . implode("\n", $output)
        );
    }
}

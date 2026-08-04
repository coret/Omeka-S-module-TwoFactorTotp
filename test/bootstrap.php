<?php declare(strict_types=1);

/**
 * Minimal bootstrap for the TwoFactorTotp unit tests.
 *
 * The crypto core (TwoFactorTotp\Service\Totp) is deliberately dependency-free,
 * so these tests need neither Omeka nor Composer — just a PSR-4 autoloader.
 */

/**
 * Omeka's Composer autoloader, when it can be found. Only the tests that
 * exercise service wiring need it; they skip themselves when it is absent.
 * Set OMEKA_VENDOR to point at it when the module is not sitting in modules/.
 */
$vendor = getenv('OMEKA_VENDOR') ?: dirname(__DIR__, 3) . '/vendor';
if (is_readable($vendor . '/autoload.php')) {
    require_once $vendor . '/autoload.php';
}
define('TWOFACTORTOTP_HAS_COMPOSER', class_exists(Laminas\ServiceManager\ServiceManager::class));

spl_autoload_register(function (string $class): void {
    $prefix = 'TwoFactorTotp\\';
    if (0 !== strncmp($prefix, $class, strlen($prefix))) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_readable($file)) {
        require_once $file;
    }
});

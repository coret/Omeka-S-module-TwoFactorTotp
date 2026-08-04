<?php
/**
 * Static verification of the TwoFactorTotp module: everything that can be
 * checked without touching the live database.
 */
declare(strict_types=1);

define('OMEKA_PATH', '/home/http/goudatijdmachine.nl/omeka-s-4.2.0');
require OMEKA_PATH . '/vendor/autoload.php';

$moduleDir = OMEKA_PATH . '/modules/TwoFactorTotp';

spl_autoload_register(function (string $class) use ($moduleDir): void {
    $prefix = 'TwoFactorTotp\\';
    if (0 !== strncmp($prefix, $class, strlen($prefix))) {
        return;
    }
    $file = $moduleDir . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_readable($file)) {
        require_once $file;
    }
});

$pass = 0;
$fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  ok    $label\n";
    } else {
        $fail++;
        echo "  FAIL  $label" . ($detail ? " — $detail" : '') . "\n";
    }
}

echo "\n== module.ini ==\n";
$ini = parse_ini_file($moduleDir . '/config/module.ini', true)['info'];
check('name is TwoFactorTotp', 'TwoFactorTotp' === $ini['name'], $ini['name']);
check('version is 0.1', '0.1' === $ini['version'], $ini['version']);
check(
    'omeka_version_constraint satisfied by 4.2.0',
    Composer\Semver\Semver::satisfies('4.2.0', $ini['omeka_version_constraint'])
);
check('configurable', !empty($ini['configurable']));

echo "\n== config classes exist ==\n";
$config = include $moduleDir . '/config/module.config.php';

foreach ($config['service_manager']['factories'] as $service => $factory) {
    check("service $service", class_exists($service) || interface_exists($service));
    check("  factory $factory", class_exists($factory));
}
foreach ($config['service_manager']['delegators'] as $service => $delegators) {
    foreach ($delegators as $d) {
        check("delegator for $service: " . basename(str_replace('\\', '/', $d)), class_exists($d));
    }
}
foreach ($config['controllers']['factories'] as $controller => $factory) {
    check("controller $controller", class_exists($controller));
    check("  factory " . basename(str_replace('\\', '/', $factory)), class_exists($factory));
}
foreach ($config['controllers']['delegators'] as $service => $delegators) {
    foreach ($delegators as $d) {
        check("controller delegator for $service", class_exists($d));
    }
}
foreach ($config['form_elements']['factories'] as $form => $factory) {
    check("form $form", class_exists($form));
    check("  factory " . basename(str_replace('\\', '/', $factory)), class_exists($factory));
}

echo "\n== inheritance / interfaces ==\n";
check(
    'LoginController extends the core one',
    is_subclass_of(TwoFactorTotp\Controller\LoginController::class, Omeka\Controller\LoginController::class)
);
check(
    'SecondFactorAdapter is a Laminas auth adapter',
    is_subclass_of(
        TwoFactorTotp\Authentication\Adapter\SecondFactorAdapter::class,
        Laminas\Authentication\Adapter\AdapterInterface::class
    )
);
foreach ([
    TwoFactorTotp\Service\Delegator\AuthenticationServiceDelegatorFactory::class,
    TwoFactorTotp\Service\Delegator\LoginControllerDelegatorFactory::class,
] as $d) {
    check(
        basename(str_replace('\\', '/', $d)) . ' implements DelegatorFactoryInterface',
        is_subclass_of($d, Laminas\ServiceManager\Factory\DelegatorFactoryInterface::class)
    );
}
check(
    'RevokeDevicesOnPasswordChange is a Doctrine EventSubscriber',
    is_subclass_of(
        TwoFactorTotp\Db\Event\Subscriber\RevokeDevicesOnPasswordChange::class,
        Doctrine\Common\EventSubscriber::class
    )
);
check(
    'entities extend Omeka AbstractEntity',
    is_subclass_of(TwoFactorTotp\Entity\TotpEnrollment::class, Omeka\Entity\AbstractEntity::class)
    && is_subclass_of(TwoFactorTotp\Entity\TrustedDevice::class, Omeka\Entity\AbstractEntity::class)
);

echo "\n== Doctrine entity mapping ==\n";
// Match Omeka: Setup::createAnnotationMetadataConfiguration() defaults to the
// SimpleAnnotationReader, which resolves bare @Entity/@Id/@Column against
// Doctrine\ORM\Mapping and ignores `use` imports.
$emSetup = Doctrine\ORM\Tools\Setup::createAnnotationMetadataConfiguration(
    [$moduleDir . '/src/Entity'],
    true,
    sys_get_temp_dir(),
    new Doctrine\Common\Cache\ArrayCache()
);
$driver = $emSetup->getMetadataDriverImpl();
$found = $driver->getAllClassNames();
check('both entities discovered', 2 === count($found), implode(', ', $found));

foreach ($found as $entityClass) {
    try {
        $metadata = new Doctrine\ORM\Mapping\ClassMetadata($entityClass);
        $driver->loadMetadataForClass($entityClass, $metadata);
        $short = basename(str_replace('\\', '/', $entityClass));
        check("$short maps to table {$metadata->table['name']}", !empty($metadata->table['name']));
        check("  $short has fields", count($metadata->fieldMappings) > 0, (string) count($metadata->fieldMappings));
        check("  $short has the user association", isset($metadata->associationMappings['user']));
    } catch (Throwable $e) {
        check("mapping $entityClass", false, $e->getMessage());
    }
}

$enrollmentMeta = new Doctrine\ORM\Mapping\ClassMetadata(TwoFactorTotp\Entity\TotpEnrollment::class);
$driver->loadMetadataForClass(TwoFactorTotp\Entity\TotpEnrollment::class, $enrollmentMeta);
check(
    'enrollment.user is a unique one-to-one with cascade delete',
    ($enrollmentMeta->associationMappings['user']['type'] ?? null) === Doctrine\ORM\Mapping\ClassMetadata::ONE_TO_ONE
    && 'CASCADE' === ($enrollmentMeta->associationMappings['user']['joinColumns'][0]['onDelete'] ?? null)
);
check(
    'recovery_codes is a json column',
    'json' === ($enrollmentMeta->fieldMappings['recoveryCodes']['type'] ?? null)
);
check(
    'last_counter is bigint and nullable',
    'bigint' === ($enrollmentMeta->fieldMappings['lastCounter']['type'] ?? null)
    && !empty($enrollmentMeta->fieldMappings['lastCounter']['nullable'])
);

echo "\n== routes assemble ==\n";
$router = Laminas\Router\Http\TreeRouteStack::factory([
    'routes' => array_replace_recursive(
        (include OMEKA_PATH . '/application/config/routes.config.php')['router']['routes'],
        $config['router']['routes']
    ),
]);
foreach ([
    ['two-factor', [], '/two-factor'],
    ['two-factor', ['action' => 'recovery'], '/two-factor/recovery'],
    ['two-factor', ['action' => 'cancel'], '/two-factor/cancel'],
    // 'setup' is the route default, so the optional segment is omitted; the
    // match test below proves /admin/two-factor still dispatches to setup.
    ['admin/two-factor', ['action' => 'setup'], '/admin/two-factor'],
    ['admin/two-factor', ['action' => 'devices'], '/admin/two-factor/devices'],
    ['admin/two-factor', ['action' => 'reset'], '/admin/two-factor/reset'],
] as [$name, $params, $expected]) {
    try {
        $url = $router->assemble($params, ['name' => $name]);
        check("assemble $name " . json_encode($params) . " => $expected", $url === $expected, $url);
    } catch (Throwable $e) {
        check("assemble $name", false, $e->getMessage());
    }
}

echo "\n== routes match (and reach the right controller) ==\n";
foreach ([
    ['/two-factor', TwoFactorTotp\Controller\OtpController::class, 'otp'],
    ['/two-factor/recovery', TwoFactorTotp\Controller\OtpController::class, 'recovery'],
    ['/admin/two-factor/setup', TwoFactorTotp\Controller\Admin\TotpController::class, 'setup'],
    ['/admin/two-factor/reset', TwoFactorTotp\Controller\Admin\TotpController::class, 'reset'],
    // Must still work: our routes may not shadow core's.
    ['/login', Omeka\Controller\LoginController::class === null ? '' : 'Login', 'login'],
] as [$path, $expectedController, $expectedAction]) {
    $request = new Laminas\Http\PhpEnvironment\Request();
    $request->setUri('http://example.org' . $path);
    $match = $router->match($request);
    if (!$match) {
        check("match $path", false, 'no route matched');
        continue;
    }
    $controller = $match->getParam('controller');
    $action = $match->getParam('action');
    $okController = str_contains((string) $controller, (string) $expectedController);
    check(
        "match $path -> $controller/$action",
        $okController && $action === $expectedAction,
        "got $controller/$action"
    );
}

echo "\n== view templates resolve ==\n";
// Laminas InjectTemplateListener maps Foo\Controller\Admin\BarController -> foo/admin/bar
$listener = new Laminas\Mvc\View\Http\InjectTemplateListener();
$reflection = new ReflectionMethod($listener, 'mapController');
$reflection->setAccessible(true);

$expectedTemplates = [
    [TwoFactorTotp\Controller\OtpController::class, ['otp', 'recovery']],
    [TwoFactorTotp\Controller\Admin\TotpController::class, ['setup', 'disable', 'recovery-codes', 'devices', 'reset']],
];
foreach ($expectedTemplates as [$controller, $actions]) {
    $base = $reflection->invoke($listener, $controller);
    foreach ($actions as $action) {
        $template = $base . '/' . $action;
        $file = $moduleDir . '/view/' . $template . '.phtml';
        check("template $template", is_readable($file), $file);
    }
}
foreach (['two-factor-totp/common/user-tab', 'two-factor-totp/common/config-form', 'two-factor-totp/admin/totp/recovery-codes'] as $template) {
    check("partial $template", is_readable($moduleDir . '/view/' . $template . '.phtml'));
}

// Any template a controller names explicitly overrides the action's default,
// so a missing or misspelt one only shows up when that branch is reached.
$controllerFiles = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($moduleDir . '/src/Controller')
);
foreach ($controllerFiles as $controllerFile) {
    if (!$controllerFile->isFile() || 'php' !== $controllerFile->getExtension()) {
        continue;
    }
    preg_match_all(
        '/setTemplate\(\s*[\'"]([^\'"]+)[\'"]\s*\)/',
        (string) file_get_contents($controllerFile->getPathname()),
        $setTemplates
    );
    foreach (array_unique($setTemplates[1]) as $template) {
        // Ours, or one of Omeka's own (LoginController reuses omeka/login/login).
        $candidates = [
            $moduleDir . '/view/' . $template . '.phtml',
            OMEKA_PATH . '/application/view/' . $template . '.phtml',
        ];
        check(
            "setTemplate('$template') resolves",
            (bool) array_filter($candidates, 'is_readable'),
            $controllerFile->getBasename()
        );
    }
}

echo "\n== views name the CSRF element the way Omeka does ==\n";
// Omeka\Form\Initializer\Csrf names it "<formname>_csrf" for any form that has
// a name, and every form pulled from the form manager has one. A view asking
// for a bare 'csrf' therefore throws InvalidElementException at render time.
$viewFiles = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($moduleDir . '/view')
);
foreach ($viewFiles as $viewFile) {
    if (!$viewFile->isFile() || 'phtml' !== $viewFile->getExtension()) {
        continue;
    }
    $contents = (string) file_get_contents($viewFile->getPathname());
    $relative = substr($viewFile->getPathname(), strlen($moduleDir) + 1);
    check(
        "$relative does not hard-code get('csrf')",
        !preg_match('/->get\(\s*[\'"]csrf[\'"]\s*\)/', $contents),
        'use $form->getName() . \'_csrf\''
    );
}

echo "\n== labels Omeka will not translate for us are translated here ==\n";
// Omeka\View\Helper\SectionNav escapes the tab labels but never translates
// them, unlike flash messages (Omeka\View\Helper\Messages does translate).
// A bare literal there shows up in English on an otherwise Dutch page.
$moduleSource = (string) file_get_contents($moduleDir . '/Module.php');
preg_match_all('/\$sectionNav\[[^\]]+\]\s*=\s*([^;]+);/', $moduleSource, $sectionNavAssignments);
check(
    'Module.php assigns at least one section_nav label',
    (bool) $sectionNavAssignments[1],
    'pattern not found - has addUserSectionNav been renamed?'
);
foreach ($sectionNavAssignments[1] as $assignment) {
    check(
        'section_nav label is translated: ' . trim($assignment),
        str_contains($assignment, 'translate('),
        'wrap it in $view->translate()'
    );
}

echo "\n== every variable a template reads is set by its action ==\n";
// The failure this catches: a template renders a variable the action never
// set. It only shows up when that branch is actually reached in a browser.
$localNames = function (string $code): array {
    preg_match_all('/\$([a-zA-Z_]\w*)\s*=(?!=)/', $code, $assigned);
    preg_match_all('/as\s+\$([a-zA-Z_]\w*)\s*(?:=>\s*\$([a-zA-Z_]\w*))?/', $code, $loop);
    preg_match_all('/function\s*\(([^)]*)\)/', $code, $fn);
    $params = [];
    foreach ($fn[1] as $signature) {
        preg_match_all('/\$([a-zA-Z_]\w*)/', $signature, $p);
        $params = array_merge($params, $p[1]);
    }
    return array_unique(array_merge(
        $assigned[1], $loop[1], array_filter($loop[2]), $params, ['this']
    ));
};
$defaultBase = [
    'TotpController' => 'two-factor-totp/admin/totp',
    'OtpController' => 'two-factor-totp/otp',
];
$controllerFiles = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($moduleDir . '/src/Controller')
);
foreach ($controllerFiles as $controllerFile) {
    if (!$controllerFile->isFile() || 'php' !== $controllerFile->getExtension()) {
        continue;
    }
    $source = (string) file_get_contents($controllerFile->getPathname());
    $class = $controllerFile->getBasename('.php');
    preg_match_all('/function\s+(\w+)Action\s*\(/', $source, $found, PREG_OFFSET_CAPTURE);
    foreach ($found[1] as $i => [$action, $offset]) {
        $body = substr($source, $offset, ($found[1][$i + 1][1] ?? strlen($source)) - $offset);
        preg_match_all('/setVariable\(\s*[\'"](\w+)[\'"]/', $body, $set);
        preg_match_all('/setTemplate\(\s*[\'"]([^\'"]+)[\'"]/', $body, $explicit);
        $templates = array_unique($explicit[1]);
        // More ViewModels than setTemplate calls => one uses the default.
        if (substr_count($body, 'new ViewModel') > count($templates)
            && isset($defaultBase[$class])
        ) {
            $templates[] = $defaultBase[$class] . '/'
                . strtolower(preg_replace('/([a-z])([A-Z])/', '$1-$2', $action));
        }
        foreach ($templates as $template) {
            $path = $moduleDir . '/view/' . $template . '.phtml';
            if (!is_readable($path)) {
                continue; // core template
            }
            $code = (string) file_get_contents($path);
            preg_match_all('/\$([a-zA-Z_]\w*)/', $code, $used);
            $missing = array_diff(
                array_unique($used[1]),
                $localNames($code),
                array_unique($set[1])
            );
            check(
                "$class::{$action}Action -> $template",
                !$missing,
                'template reads unset: ' . implode(', ', $missing)
            );
        }
    }
}

echo "\n== assets referenced by views exist ==\n";
foreach (['vendor/qrcode-generator/qrcode.js', 'js/totp-setup.js'] as $asset) {
    check("asset $asset", is_readable($moduleDir . '/asset/' . $asset));
}

echo "\n----------------------------------------\n";
printf("%d passed, %d failed\n\n", $pass, $fail);
exit($fail > 0 ? 1 : 0);

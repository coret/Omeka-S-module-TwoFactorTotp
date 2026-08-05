<?php declare(strict_types=1);

namespace TwoFactorTotp;

use Laminas\EventManager\Event;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\View\Renderer\PhpRenderer;
use Omeka\Module\AbstractModule;
use Omeka\Module\Exception\ModuleCannotInstallException;
use Omeka\Permissions\Acl;
use TwoFactorTotp\Form\ConfigForm;
use TwoFactorTotp\Service\TotpManager;

// Omeka core never loads a module's Composer autoloader, so the module must do
// it itself. Two deliberate details:
//
//   - Guarded, because `vendor/` is not committed (it is installed on deploy).
//     A checkout without it must still boot: this module replaces the login
//     controller, so a fatal here locks everybody out of the site.
//   - At file scope rather than in init(), because Omeka instantiates a bare
//     module object to run upgrade() on a module that is not loaded
//     (Omeka\Module\Manager::getModuleObject()), and init() never fires on it.
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

/**
 * TwoFactorTotp — second-factor authentication with time-based one-time
 * passwords (RFC 6238) from an authenticator app.
 *
 * @copyright Bob Coret, 2026
 * @license https://www.gnu.org/licenses/gpl-3.0.html GPL-3.0
 */
class Module extends AbstractModule
{
    const NAMESPACE = __NAMESPACE__;

    /**
     * Routes a user who is forced to enroll may still reach.
     */
    const ENROLLMENT_ESCAPE_ROUTES = [
        'admin/two-factor',
        'login',
        'logout',
        'two-factor',
    ];

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function onBootstrap(MvcEvent $event)
    {
        parent::onBootstrap($event);

        $this->addAclRules();

        // After Omeka's own route listeners (all at the default priority 1),
        // so redirect-to-login and friends have already had their say.
        $event->getApplication()->getEventManager()->attach(
            MvcEvent::EVENT_ROUTE,
            [$this, 'confineUsersAwaitingEnrollment'],
            -100
        );
    }

    // ------------------------------------------------------------ life cycle

    public function install(\Laminas\ServiceManager\ServiceLocatorInterface $serviceLocator)
    {
        $this->preventConflictingModule($serviceLocator);

        $connection = $serviceLocator->get('Omeka\Connection');

        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS two_factor_totp_enrollment (
                id INT AUTO_INCREMENT NOT NULL,
                user_id INT NOT NULL,
                secret VARCHAR(64) NOT NULL,
                is_confirmed TINYINT(1) NOT NULL,
                last_counter BIGINT DEFAULT NULL,
                recovery_codes JSON NOT NULL,
                created DATETIME NOT NULL,
                confirmed_at DATETIME DEFAULT NULL,
                last_used_at DATETIME DEFAULT NULL,
                UNIQUE INDEX UNIQ_two_factor_totp_enrollment_user (user_id),
                PRIMARY KEY(id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
            SQL);

        $connection->executeStatement(<<<'SQL'
            CREATE TABLE IF NOT EXISTS two_factor_totp_trusted_device (
                id INT AUTO_INCREMENT NOT NULL,
                user_id INT NOT NULL,
                selector VARCHAR(32) NOT NULL,
                validator_hash VARCHAR(64) NOT NULL,
                expires DATETIME NOT NULL,
                label VARCHAR(255) DEFAULT NULL,
                created DATETIME NOT NULL,
                last_used_at DATETIME DEFAULT NULL,
                UNIQUE INDEX UNIQ_two_factor_totp_device_selector (selector),
                INDEX idx_two_factor_totp_device_expires (expires),
                INDEX IDX_two_factor_totp_device_user (user_id),
                PRIMARY KEY(id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
            SQL);

        // ON DELETE CASCADE: deleting a user must not leave their secret or
        // their trusted devices behind.
        $connection->executeStatement(
            'ALTER TABLE two_factor_totp_enrollment
             ADD CONSTRAINT FK_two_factor_totp_enrollment_user
             FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE'
        );
        $connection->executeStatement(
            'ALTER TABLE two_factor_totp_trusted_device
             ADD CONSTRAINT FK_two_factor_totp_device_user
             FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE'
        );

        $this->writeDefaultSettings($serviceLocator);
    }

    public function uninstall(\Laminas\ServiceManager\ServiceLocatorInterface $serviceLocator)
    {
        $connection = $serviceLocator->get('Omeka\Connection');
        $connection->executeStatement('DROP TABLE IF EXISTS two_factor_totp_trusted_device');
        $connection->executeStatement('DROP TABLE IF EXISTS two_factor_totp_enrollment');

        $settings = $serviceLocator->get('Omeka\Settings');
        foreach (array_keys($this->defaultSettings()) as $key) {
            $settings->delete($key);
        }
    }

    /**
     * Refuse to install next to a module that also replaces the login
     * controller — the two would fight, and the loser would be whichever
     * module happened to load second.
     */
    protected function preventConflictingModule($serviceLocator): void
    {
        $moduleManager = $serviceLocator->get('Omeka\ModuleManager');
        $conflicting = $moduleManager->getModule('TwoFactorAuth');
        if ($conflicting && \Omeka\Module\Manager::STATE_ACTIVE === $conflicting->getState()) {
            throw new ModuleCannotInstallException(
                'The TwoFactorAuth module is active. Both modules replace the login controller, so they cannot run together. Disable TwoFactorAuth first.' // @translate
            );
        }
    }

    protected function defaultSettings(): array
    {
        $config = $this->getConfig();
        return $config['twofactortotp']['settings'] ?? [];
    }

    protected function writeDefaultSettings($serviceLocator): void
    {
        $settings = $serviceLocator->get('Omeka\Settings');
        foreach ($this->defaultSettings() as $key => $value) {
            if (null === $settings->get($key)) {
                $settings->set($key, $value);
            }
        }
    }

    // ------------------------------------------------------------------- ACL

    protected function addAclRules(): void
    {
        /** @var Acl $acl */
        $acl = $this->getServiceLocator()->get('Omeka\Acl');

        // Step 2 of the login happens *before* the identity exists, so it has
        // to be reachable with no role at all.
        $acl->allow(null, [Controller\OtpController::class]);

        $allRoles = array_keys($acl->getRoleLabels());

        // Managing your own second factor: any signed-in role. The controller
        // takes the user from the session, never from a request parameter, so
        // there is no other account these actions could touch.
        $acl->allow(
            $allRoles,
            [Controller\Admin\TotpController::class],
            ['setup', 'disable', 'recovery-codes', 'devices', 'revoke-device']
        );

        // Resetting somebody else's second factor. Restricted to the roles
        // that can already promote users to administrator; the action
        // re-checks 'change-role-admin' against the specific target user.
        $acl->allow(
            [Acl::ROLE_GLOBAL_ADMIN, Acl::ROLE_SITE_ADMIN],
            [Controller\Admin\TotpController::class],
            ['reset']
        );
    }


    // ---------------------------------------------------------- MVC listener

    /**
     * Keep a user whose role requires 2FA on the setup page until they finish.
     *
     * They are genuinely logged in at this point — the password was correct
     * and they have no second factor yet to check — so confinement, not
     * rejection, is the right tool.
     */
    public function confineUsersAwaitingEnrollment(MvcEvent $event)
    {
        $routeMatch = $event->getRouteMatch();
        if (!$routeMatch) {
            return;
        }

        $services = $event->getApplication()->getServiceManager();
        $status = $services->get('Omeka\Status');

        // API and key-authenticated requests have no interactive user to send
        // to a setup page.
        if ($status->isApiRequest() || $routeMatch->getParam('__KEYAUTH__')) {
            return;
        }

        $auth = $services->get('Omeka\AuthenticationService');
        if (!$auth->hasIdentity()) {
            return;
        }

        if (in_array($routeMatch->getMatchedRouteName(), self::ENROLLMENT_ESCAPE_ROUTES, true)) {
            return;
        }

        /** @var TotpManager $totpManager */
        $totpManager = $services->get(TotpManager::class);
        if (!$totpManager->mustEnroll($auth->getIdentity())) {
            return;
        }

        $url = $event->getRouter()->assemble(
            ['action' => 'setup'],
            ['name' => 'admin/two-factor']
        );

        $messenger = new \Omeka\Mvc\Controller\Plugin\Messenger;
        $messenger->addWarning(
            'Two-factor authentication is required for your role. Set it up to continue.' // @translate
        );

        $response = $event->getResponse();
        $response->getHeaders()->addHeaderLine('Location', $url);
        $response->setStatusCode(302);
        $response->sendHeaders();
        return $response;
    }

    // -------------------------------------------------------------- listeners

    public function attachListeners(SharedEventManagerInterface $sharedEventManager)
    {
        // The "Two-factor authentication" tab on the user edit page.
        $sharedEventManager->attach(
            'Omeka\Controller\Admin\User',
            'view.edit.section_nav',
            [$this, 'addUserSectionNav']
        );
        $sharedEventManager->attach(
            'Omeka\Controller\Admin\User',
            'view.edit.form.after',
            [$this, 'addUserSection']
        );
    }

    public function addUserSectionNav(Event $event): void
    {
        /** @var PhpRenderer $view */
        $view = $event->getTarget();

        // Omeka's sectionNav helper escapes these labels but does not
        // translate them, so the label has to arrive already translated.
        $sectionNav = $event->getParam('section_nav');
        $sectionNav['two-factor-totp'] = $view->translate('Two-factor authentication'); // @translate
        $event->setParam('section_nav', $sectionNav);
    }

    public function addUserSection(Event $event): void
    {
        /** @var PhpRenderer $view */
        $view = $event->getTarget();
        $services = $this->getServiceLocator();

        $user = $view->vars()->offsetGet('user');
        if (!$user) {
            return;
        }

        $userEntity = $user->getEntity();
        $identity = $services->get('Omeka\AuthenticationService')->getIdentity();
        $isSelf = $identity && $identity->getId() === $userEntity->getId();

        /** @var TotpManager $totpManager */
        $totpManager = $services->get(TotpManager::class);
        $trustedDevices = $services->get(Service\TrustedDeviceManager::class);

        echo $view->partial('two-factor-totp/common/user-tab', [
            'user' => $user,
            'userEntity' => $userEntity,
            'isSelf' => $isSelf,
            'isEnabled' => $totpManager->isEnabled($userEntity),
            'isForced' => $totpManager->isRoleForced($userEntity),
            'recoveryCodesRemaining' => $totpManager->countRecoveryCodes($userEntity),
            'lowWaterMark' => TotpManager::RECOVERY_LOW_WATER_MARK,
            'deviceCount' => count($trustedDevices->listForUser($userEntity)),
            'trustedDevicesEnabled' => $trustedDevices->isEnabled(),
            'canReset' => $view->userIsAllowed($userEntity, 'change-role-admin'),
        ]);
    }

    // ---------------------------------------------------------- module config

    public function getConfigForm(PhpRenderer $renderer)
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        $form = $services->get('FormElementManager')->get(ConfigForm::class);

        $data = [];
        foreach (array_keys($this->defaultSettings()) as $key) {
            $data[$key] = $settings->get($key);
        }
        $form->setData($data);

        return $renderer->render('two-factor-totp/common/config-form', [
            'form' => $form,
            // Clock drift is the single most common cause of "every code is
            // wrong", so put the server's own time in front of the admin.
            'serverTime' => (new \DateTime('now'))->format('Y-m-d H:i:s T'),
        ]);
    }

    public function handleConfigForm(\Laminas\Mvc\Controller\AbstractController $controller)
    {
        $services = $this->getServiceLocator();
        $settings = $services->get('Omeka\Settings');

        $form = $services->get('FormElementManager')->get(ConfigForm::class);
        $form->setData($controller->params()->fromPost());

        if (!$form->isValid()) {
            $controller->messenger()->addFormErrors($form);
            return false;
        }

        $data = $form->getData();
        foreach (array_keys($this->defaultSettings()) as $key) {
            if (array_key_exists($key, $data)) {
                $settings->set($key, $data[$key]);
            }
        }

        return true;
    }
}

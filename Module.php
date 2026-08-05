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
        'two-factor-passkey',
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

        $connection->executeStatement(self::SQL_CREATE_RECOVERY_CODE);
        $connection->executeStatement(self::SQL_CREATE_WEBAUTHN_CREDENTIAL);

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
        foreach (self::USER_FOREIGN_KEYS as $constraint => $table) {
            $connection->executeStatement(sprintf(
                'ALTER TABLE %s ADD CONSTRAINT %s
                 FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE',
                $table,
                $constraint
            ));
        }

        $this->writeDefaultSettings($serviceLocator);
    }

    /**
     * Recovery codes belong to the user, so that an account whose only factor
     * is not TOTP still has a way back in.
     */
    const SQL_CREATE_RECOVERY_CODE = <<<'SQL'
        CREATE TABLE IF NOT EXISTS two_factor_totp_recovery_code (
            id INT AUTO_INCREMENT NOT NULL,
            user_id INT NOT NULL,
            code_hash VARCHAR(255) NOT NULL,
            created DATETIME NOT NULL,
            used_at DATETIME DEFAULT NULL,
            INDEX idx_two_factor_totp_recovery_user (user_id),
            PRIMARY KEY(id)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
        SQL;

    /**
     * Many per user: a phone, a laptop, a hardware key.
     *
     * credential_id is ascii_bin so matching stays byte-exact — base64url is
     * case-significant, and a case-insensitive comparison here would let one
     * credential stand in for another.
     */
    const SQL_CREATE_WEBAUTHN_CREDENTIAL = <<<'SQL'
        CREATE TABLE IF NOT EXISTS two_factor_totp_webauthn_credential (
            id INT AUTO_INCREMENT NOT NULL,
            user_id INT NOT NULL,
            credential_id VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            public_key TEXT NOT NULL,
            sign_count BIGINT UNSIGNED DEFAULT 0 NOT NULL,
            label VARCHAR(255) DEFAULT NULL,
            transports VARCHAR(100) DEFAULT NULL,
            aaguid VARCHAR(64) DEFAULT NULL,
            created DATETIME NOT NULL,
            last_used_at DATETIME DEFAULT NULL,
            UNIQUE INDEX UNIQ_two_factor_totp_webauthn_credential (credential_id),
            INDEX idx_two_factor_totp_webauthn_user (user_id),
            PRIMARY KEY(id)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
        SQL;

    /** Constraint name => table, for the tables added in 0.2. */
    const USER_FOREIGN_KEYS = [
        'FK_two_factor_totp_recovery_user' => 'two_factor_totp_recovery_code',
        'FK_two_factor_totp_webauthn_user' => 'two_factor_totp_webauthn_credential',
    ];

    /**
     * Every statement here is safe to run twice.
     *
     * Deliberate, not incidental: raising the version in module.ini puts the
     * module into `needs_upgrade`, and Omeka loads only *active* modules — so
     * between the bump and an administrator running the upgrade, this module's
     * config is not loaded at all and two-factor authentication is off site
     * wide. The way to keep that window near zero is to apply the migration by
     * hand first and then let Omeka run it again over the top.
     */
    public function upgrade($oldVersion, $newVersion, \Laminas\ServiceManager\ServiceLocatorInterface $serviceLocator)
    {
        $connection = $serviceLocator->get('Omeka\Connection');

        if (version_compare((string) $oldVersion, '0.2', '<')) {
            $connection->executeStatement(self::SQL_CREATE_RECOVERY_CODE);
            $connection->executeStatement(self::SQL_CREATE_WEBAUTHN_CREDENTIAL);

            // ALTER TABLE ... ADD CONSTRAINT has no IF NOT EXISTS, so ask first.
            foreach (self::USER_FOREIGN_KEYS as $constraint => $table) {
                $exists = (int) $connection->fetchOne(
                    'SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
                      WHERE CONSTRAINT_SCHEMA = DATABASE()
                        AND TABLE_NAME = ?
                        AND CONSTRAINT_NAME = ?',
                    [$table, $constraint]
                );
                if (!$exists) {
                    $connection->executeStatement(sprintf(
                        'ALTER TABLE %s ADD CONSTRAINT %s
                         FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE',
                        $table,
                        $constraint
                    ));
                }
            }

            $this->migrateRecoveryCodes($connection);

            // The legacy column stays, still holding the old hashes: it makes
            // rolling back to 0.1 a plain `git checkout` with no data loss, and
            // it costs nothing to keep. A later version drops it, once 0.2 has
            // proven itself.
            //
            // It must become nullable though — it is NOT NULL today and nothing
            // writes it any more, so the next enrollment would otherwise fail.
            //
            // The NULL keyword is spelled out on purpose: on MariaDB (12.0
            // tested) `MODIFY ... JSON DEFAULT NULL` alone leaves the column
            // NOT NULL and reports success, so the change silently does
            // nothing.
            $connection->executeStatement(
                'ALTER TABLE two_factor_totp_enrollment MODIFY recovery_codes JSON NULL DEFAULT NULL'
            );
        }
    }

    /**
     * Copy recovery codes off the enrollment row onto the user.
     *
     * Only for users who have none yet, so running this twice cannot double
     * anybody's set. The hashes move verbatim — they are password_hash() output
     * and stay valid, so codes people have already written down keep working.
     * That matters: for an account that has lost its phone, these are the only
     * way back in.
     *
     * @return int Number of codes moved.
     */
    protected function migrateRecoveryCodes(\Doctrine\DBAL\Connection $connection): int
    {
        $rows = $connection->fetchAllAssociative(
            'SELECT e.user_id, e.recovery_codes, e.confirmed_at
               FROM two_factor_totp_enrollment e
              WHERE e.recovery_codes IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1 FROM two_factor_totp_recovery_code r
                     WHERE r.user_id = e.user_id
                )'
        );

        $migrated = 0;
        foreach ($rows as $row) {
            $hashes = json_decode((string) $row['recovery_codes'], true);
            if (!is_array($hashes)) {
                continue;
            }
            $created = $row['confirmed_at'] ?: date('Y-m-d H:i:s');
            foreach ($hashes as $hash) {
                if (!is_string($hash) || '' === $hash) {
                    continue;
                }
                $connection->executeStatement(
                    'INSERT INTO two_factor_totp_recovery_code (user_id, code_hash, created)
                     VALUES (?, ?, ?)',
                    [(int) $row['user_id'], $hash, $created]
                );
                $migrated++;
            }
        }

        return $migrated;
    }

    public function uninstall(\Laminas\ServiceManager\ServiceLocatorInterface $serviceLocator)
    {
        $connection = $serviceLocator->get('Omeka\Connection');
        $connection->executeStatement('DROP TABLE IF EXISTS two_factor_totp_webauthn_credential');
        $connection->executeStatement('DROP TABLE IF EXISTS two_factor_totp_recovery_code');
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
        $acl->allow(null, [
            Controller\OtpController::class,
            // Same reasoning: the user has cleared the password but holds no
            // identity yet, and will not until the factor passes.
            Controller\PasskeyController::class,
        ]);

        $allRoles = array_keys($acl->getRoleLabels());

        // Managing your own second factor: any signed-in role. The controller
        // takes the user from the session, never from a request parameter, so
        // there is no other account these actions could touch.
        $acl->allow(
            $allRoles,
            [Controller\Admin\TotpController::class],
            [
                'setup', 'disable', 'recovery-codes', 'devices', 'revoke-device',
                'passkeys', 'passkey-challenge', 'passkey-verify', 'passkey-remove',
            ]
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

        // Any enrolled factor satisfies the requirement, so this asks the
        // registry rather than TOTP: someone with a passkey and no
        // authenticator app must not be herded towards the TOTP setup page.
        /** @var Service\SecondFactorRegistry $registry */
        $registry = $services->get(Service\SecondFactorRegistry::class);
        if (!$registry->mustEnroll($auth->getIdentity())) {
            return;
        }

        $enrollmentRoute = $registry->getEnrollmentRoute();
        if (!$enrollmentRoute) {
            // No factor is registered at all, so there is nowhere to send them.
            // Confining them anyway would be a redirect loop with no way out.
            return;
        }
        [$routeName, $routeParams] = $enrollmentRoute;
        $url = $event->getRouter()->assemble($routeParams, ['name' => $routeName]);

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
            'isForced' => $services->get(Service\SecondFactorRegistry::class)->isRoleForced($userEntity),
            'recoveryCodesRemaining' => $totpManager->countRecoveryCodes($userEntity),
            'lowWaterMark' => TotpManager::RECOVERY_LOW_WATER_MARK,
            'deviceCount' => count($trustedDevices->listForUser($userEntity)),
            'passkeyCount' => $services->get(Service\PasskeyManager::class)->countForUser($userEntity),
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

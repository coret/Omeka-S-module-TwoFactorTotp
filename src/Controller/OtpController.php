<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container;
use Laminas\View\Model\ViewModel;
use Omeka\Entity\User;
use TwoFactorTotp\Form\OtpForm;
use TwoFactorTotp\Form\RecoveryCodeForm;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\PendingLogin;

/**
 * Step 2 of the login.
 *
 * Reachable anonymously — by definition the visitor is not authenticated yet —
 * so every action starts from the pending login in the session and refuses to
 * do anything without one.
 */
class OtpController extends AbstractActionController
{
    protected EntityManager $entityManager;

    protected AuthenticationService $auth;

    protected TotpManager $totpManager;

    protected TrustedDeviceManager $trustedDevices;

    protected PendingLogin $pendingLogin;

    public function __construct(
        EntityManager $entityManager,
        AuthenticationService $auth,
        TotpManager $totpManager,
        TrustedDeviceManager $trustedDevices,
        PendingLogin $pendingLogin
    ) {
        $this->entityManager = $entityManager;
        $this->auth = $auth;
        $this->totpManager = $totpManager;
        $this->trustedDevices = $trustedDevices;
        $this->pendingLogin = $pendingLogin;
    }

    public function otpAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('admin');
        }

        $user = $this->pendingUser();
        if (!$user) {
            return $this->expired();
        }

        $offerRemember = $this->trustedDevices->isEnabled();

        /** @var OtpForm $form */
        $form = $this->getForm(OtpForm::class, [
            'offer_remember_device' => $offerRemember,
            'remember_device_days' => $this->trustedDevices->getTrustDays(),
        ]);
        $form->setAttribute('action', $this->url()->fromRoute('two-factor'));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();

                if ($this->totpManager->verify($user, (string) $data['code'])) {
                    $rememberDevice = $offerRemember && !empty($data['remember_device']);
                    return $this->completeLogin($user, $rememberDevice);
                }

                return $this->rejectAttempt($user, 'code');
            }
            $this->messenger()->addFormErrors($form);
        }

        $view = new ViewModel;
        $view->setVariable('form', $form);
        $view->setVariable('user', $user);
        $view->setVariable('secondsRemaining', $this->pendingLogin->getSecondsRemaining());
        $view->setVariable('remainingAttempts', $this->pendingLogin->getRemainingAttempts());
        $view->setVariable('recoveryUrl', $this->url()->fromRoute('two-factor', ['action' => 'recovery']));
        return $view;
    }

    public function recoveryAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('admin');
        }

        $user = $this->pendingUser();
        if (!$user) {
            return $this->expired();
        }

        $form = $this->getForm(RecoveryCodeForm::class);
        $form->setAttribute('action', $this->url()->fromRoute('two-factor', ['action' => 'recovery']));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();

                if ($this->totpManager->consumeRecoveryCode($user, (string) $data['recovery_code'])) {
                    $remaining = $this->totpManager->countRecoveryCodes($user);
                    // A recovery code means the app is probably gone, so never
                    // hand out a trusted-device cookie on this path.
                    $response = $this->completeLogin($user, false);

                    if ($remaining <= TotpManager::RECOVERY_LOW_WATER_MARK) {
                        $this->messenger()->addWarning(sprintf(
                            'You have %d recovery codes left. Generate a new set from your user page.', // @translate
                            $remaining
                        ));
                    } else {
                        $this->messenger()->addNotice(sprintf(
                            'Recovery code accepted. You have %d left.', // @translate
                            $remaining
                        ));
                    }

                    return $response;
                }

                return $this->rejectAttempt($user, 'recovery code', 'recovery');
            }
            $this->messenger()->addFormErrors($form);
        }

        $view = new ViewModel;
        $view->setVariable('form', $form);
        $view->setVariable('user', $user);
        $view->setVariable('otpUrl', $this->url()->fromRoute('two-factor'));
        return $view;
    }

    /**
     * Abandon the pending login and go back to the password form.
     */
    public function cancelAction()
    {
        $this->pendingLogin->clear();
        return $this->redirect()->toRoute('login');
    }

    // --------------------------------------------------------------- helpers

    /**
     * The password-verified user this session is waiting on, if any.
     */
    protected function pendingUser(): ?User
    {
        $userId = $this->pendingLogin->getUserId();
        if (!$userId) {
            return null;
        }

        $user = $this->entityManager->find(User::class, $userId);

        // The account could have been deactivated or deleted in the seconds
        // between the two steps.
        if (!$user || !$user->isActive()) {
            $this->pendingLogin->clear();
            return null;
        }

        return $user;
    }

    /**
     * Grant the identity. This is the only place in the module that does.
     */
    protected function completeLogin(User $user, bool $rememberDevice)
    {
        $redirectUrl = $this->pendingLogin->getRedirectUrl();

        $sessionManager = Container::getDefaultManager();
        // New session id at the moment privilege is granted, so a session
        // fixed before login is worthless.
        $sessionManager->regenerateId();

        $this->pendingLogin->clear();

        $this->auth->getStorage()->write($user);

        if ($rememberDevice) {
            $cookieValue = $this->trustedDevices->issue($user);
            if ($cookieValue) {
                $this->getResponse()->getHeaders()
                    ->addHeader($this->trustedDevices->buildSetCookie($cookieValue));
            }
        }

        $this->messenger()->addSuccess('Successfully logged in'); // @translate

        // Fire the same event core fires, so Lockout, Statistics and anything
        // else listening still see a login happen.
        $this->getEventManager()->trigger('user.login', $user);

        if ($redirectUrl) {
            return $this->redirect()->toUrl($redirectUrl);
        }
        if ($this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')) {
            return $this->redirect()->toRoute('admin');
        }
        return $this->redirect()->toRoute('top');
    }

    /**
     * Count a wrong code and either send the user back to try again or throw
     * the pending login away.
     */
    protected function rejectAttempt(User $user, string $what, string $action = 'otp')
    {
        $this->logger()->warn(sprintf(
            'TwoFactorTotp: invalid %s for user "%s" (id %s) from %s.',
            $what,
            $user->getEmail(),
            $user->getId(),
            $this->clientIp()
        ));

        if (!$this->pendingLogin->recordFailure()) {
            $this->messenger()->addError(
                'Too many incorrect codes. Please log in again.' // @translate
            );
            return $this->redirect()->toRoute('login');
        }

        $this->messenger()->addError(sprintf(
            'Invalid code. %d attempts remaining.', // @translate
            $this->pendingLogin->getRemainingAttempts()
        ));

        return $this->redirect()->toRoute(
            'two-factor',
            'otp' === $action ? [] : ['action' => $action]
        );
    }

    protected function expired()
    {
        $this->messenger()->addError(
            'Your login timed out. Please log in again.' // @translate
        );
        return $this->redirect()->toRoute('login');
    }

    protected function clientIp(): string
    {
        // Deliberately the raw connecting address: X-Forwarded-For is
        // attacker-controlled unless the proxy chain is known, and this value
        // only ever goes into a log line.
        return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }
}

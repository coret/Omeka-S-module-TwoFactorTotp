<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller\Admin;

use Doctrine\ORM\EntityManager;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Omeka\Entity\User;
use Omeka\Form\ConfirmForm;
use Omeka\Mvc\Exception\PermissionDeniedException;
use TwoFactorTotp\Entity\TrustedDevice;
use TwoFactorTotp\Form\ConfirmOtpForm;
use TwoFactorTotp\Form\PasswordConfirmForm;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * Managing your own second factor: enrolling, disabling, recovery codes and
 * trusted devices — plus the one action an administrator may take against
 * somebody else's account, resetting it.
 */
class TotpController extends AbstractActionController
{
    protected EntityManager $entityManager;

    protected TotpManager $totpManager;

    protected TrustedDeviceManager $trustedDevices;

    public function __construct(
        EntityManager $entityManager,
        TotpManager $totpManager,
        TrustedDeviceManager $trustedDevices
    ) {
        $this->entityManager = $entityManager;
        $this->totpManager = $totpManager;
        $this->trustedDevices = $trustedDevices;
    }

    /**
     * Scan the QR, type a code, get recovery codes.
     */
    public function setupAction()
    {
        $user = $this->requireSelf();

        if ($this->totpManager->isEnabled($user)) {
            $this->messenger()->addNotice(
                'Two-factor authentication is already enabled for your account.' // @translate
            );
            return $this->redirectToUser($user);
        }

        $enrollment = $this->totpManager->beginEnrollment($user);
        $form = $this->getForm(ConfirmOtpForm::class);
        $form->setAttribute('action', $this->url()->fromRoute('admin/two-factor', ['action' => 'setup']));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();
                $recoveryCodes = $this->totpManager->confirmEnrollment($user, (string) $data['code']);

                if (null !== $recoveryCodes) {
                    $this->logger()->info(sprintf(
                        'TwoFactorTotp: user "%s" (id %s) enabled two-factor authentication.',
                        $user->getEmail(),
                        $user->getId()
                    ));
                    $this->messenger()->addSuccess('Two-factor authentication is now enabled.'); // @translate

                    // Shown exactly once, on this response only — never stored
                    // in plaintext and never retrievable again.
                    $view = new ViewModel;
                    $view->setTemplate('two-factor-totp/admin/totp/recovery-codes');
                    $view->setVariable('user', $user);
                    $view->setVariable('recoveryCodes', $recoveryCodes);
                    $view->setVariable('isInitial', true);
                    return $view;
                }

                $this->messenger()->addError(
                    'That code was not correct. Check your app and try again.' // @translate
                );
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        $view = new ViewModel;
        $view->setVariable('user', $user);
        $view->setVariable('form', $form);
        $view->setVariable('secret', $enrollment->getSecret());
        $view->setVariable('provisioningUri', $this->totpManager->getProvisioningUri($enrollment));
        $view->setVariable('isForced', $this->totpManager->isRoleForced($user));
        return $view;
    }

    /**
     * Turn the second factor off. Requires the account password.
     */
    public function disableAction()
    {
        $user = $this->requireSelf();

        if (!$this->totpManager->isEnabled($user)) {
            return $this->redirectToUser($user);
        }

        if ($this->totpManager->isRoleForced($user)) {
            $this->messenger()->addError(
                'Two-factor authentication is required for your role and cannot be turned off.' // @translate
            );
            return $this->redirectToUser($user);
        }

        $form = $this->getForm(PasswordConfirmForm::class, [
            'button_label' => 'Disable two-factor authentication', // @translate
        ]);
        $form->setAttribute('action', $this->url()->fromRoute('admin/two-factor', ['action' => 'disable']));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();
                if (!$user->verifyPassword($data['password'])) {
                    $this->messenger()->addError('The password entered was invalid.'); // @translate
                    return $this->redirect()->toRoute('admin/two-factor', ['action' => 'disable']);
                }

                $this->totpManager->disable($user);
                $this->logger()->warn(sprintf(
                    'TwoFactorTotp: user "%s" (id %s) disabled two-factor authentication.',
                    $user->getEmail(),
                    $user->getId()
                ));
                $this->messenger()->addSuccess('Two-factor authentication is now disabled.'); // @translate
                return $this->redirectToUser($user);
            }
            $this->messenger()->addFormErrors($form);
        }

        $view = new ViewModel;
        $view->setVariable('user', $user);
        $view->setVariable('form', $form);
        return $view;
    }

    /**
     * Issue a fresh set of recovery codes, invalidating the old ones.
     */
    public function recoveryCodesAction()
    {
        $user = $this->requireSelf();

        if (!$this->totpManager->isEnabled($user)) {
            return $this->redirectToUser($user);
        }

        $form = $this->getForm(PasswordConfirmForm::class, [
            'button_label' => 'Generate new recovery codes', // @translate
        ]);
        $form->setAttribute('action', $this->url()->fromRoute('admin/two-factor', ['action' => 'recovery-codes']));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();
                if (!$user->verifyPassword($data['password'])) {
                    $this->messenger()->addError('The password entered was invalid.'); // @translate
                    return $this->redirect()->toRoute('admin/two-factor', ['action' => 'recovery-codes']);
                }

                $recoveryCodes = $this->totpManager->regenerateRecoveryCodes($user);
                $this->messenger()->addSuccess(
                    'New recovery codes generated. Your previous codes no longer work.' // @translate
                );

                $view = new ViewModel;
                $view->setTemplate('two-factor-totp/admin/totp/recovery-codes');
                $view->setVariable('user', $user);
                $view->setVariable('recoveryCodes', $recoveryCodes);
                $view->setVariable('isInitial', false);
                return $view;
            }
            $this->messenger()->addFormErrors($form);
        }

        // Not the default template for this action: that one displays a set of
        // codes and is what the POST returns. This is the password prompt that
        // leads to it.
        $view = new ViewModel;
        $view->setTemplate('two-factor-totp/admin/totp/recovery-codes-form');
        $view->setVariable('user', $user);
        $view->setVariable('form', $form);
        $view->setVariable('remaining', $this->totpManager->countRecoveryCodes($user));
        return $view;
    }

    /**
     * The list of browsers that may skip the second step.
     */
    public function devicesAction()
    {
        $user = $this->requireSelf();

        // One CSRF-bearing form reused by every revoke button on the page.
        $confirmForm = $this->getForm(ConfirmForm::class);

        $view = new ViewModel;
        $view->setVariable('user', $user);
        $view->setVariable('devices', $this->trustedDevices->listForUser($user));
        $view->setVariable('currentDevice', $this->trustedDevices->findValidDevice($user));
        $view->setVariable('confirmForm', $confirmForm);
        return $view;
    }

    public function revokeDeviceAction()
    {
        $user = $this->requireSelf();

        if (!$this->getRequest()->isPost()) {
            return $this->redirect()->toRoute('admin/two-factor', ['action' => 'devices']);
        }

        $form = $this->getForm(ConfirmForm::class);
        $form->setData($this->params()->fromPost());
        if (!$form->isValid()) {
            $this->messenger()->addError('Invalid or missing CSRF token'); // @translate
            return $this->redirect()->toRoute('admin/two-factor', ['action' => 'devices']);
        }

        $deviceId = (int) $this->params()->fromPost('device_id');
        if ($deviceId) {
            $device = $this->entityManager->find(TrustedDevice::class, $deviceId);
            // Ownership check: the id comes from the request.
            if ($device && $device->getUser() === $user) {
                $this->trustedDevices->revoke($device);
                $this->messenger()->addSuccess('Device revoked.'); // @translate
            }
        } else {
            $count = $this->trustedDevices->revokeAll($user);
            $this->messenger()->addSuccess(sprintf(
                'Revoked %d devices.', // @translate
                $count
            ));
        }

        return $this->redirect()->toRoute('admin/two-factor', ['action' => 'devices']);
    }

    /**
     * An administrator clearing somebody else's second factor.
     *
     * This is the escape hatch for a lost phone, so it is deliberately
     * available — and deliberately loud: it is logged and the user is emailed.
     */
    public function resetAction()
    {
        $userId = (int) $this->params()->fromQuery('user_id', $this->params()->fromPost('user_id'));
        $targetUser = $userId ? $this->entityManager->find(User::class, $userId) : null;

        if (!$targetUser) {
            throw new \Omeka\Mvc\Exception\NotFoundException;
        }

        // Same permission that gates promoting somebody to administrator:
        // anyone who can do that can already take the account over.
        if (!$this->userIsAllowed($targetUser, 'change-role-admin')) {
            throw new PermissionDeniedException(
                'User does not have permission to reset two-factor authentication for other users.'
            );
        }

        $form = $this->getForm(ConfirmForm::class);
        $form->setAttribute(
            'action',
            $this->url()->fromRoute('admin/two-factor', ['action' => 'reset'], ['query' => ['user_id' => $userId]])
        );
        $form->setButtonLabel('Reset two-factor authentication'); // @translate

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $this->totpManager->disable($targetUser);

                $this->logger()->warn(sprintf(
                    'TwoFactorTotp: user "%s" (id %s) reset two-factor authentication for "%s" (id %s).',
                    $this->identity() ? $this->identity()->getEmail() : 'unknown',
                    $this->identity() ? $this->identity()->getId() : '?',
                    $targetUser->getEmail(),
                    $targetUser->getId()
                ));

                $this->notifyReset($targetUser);

                $this->messenger()->addSuccess(sprintf(
                    'Two-factor authentication was reset for %s.', // @translate
                    $targetUser->getEmail()
                ));
                return $this->redirect()->toUrl(
                    $this->url()->fromRoute('admin/id', ['controller' => 'user', 'action' => 'edit', 'id' => $userId])
                );
            }
            $this->messenger()->addError('Invalid or missing CSRF token'); // @translate
        }

        $view = new ViewModel;
        $view->setVariable('targetUser', $targetUser);
        $view->setVariable('form', $form);
        $view->setVariable('isEnabled', $this->totpManager->isEnabled($targetUser));
        return $view;
    }

    // --------------------------------------------------------------- helpers

    /**
     * Every self-service action here operates on the logged-in user and no
     * one else. Taking the user from the session rather than from a request
     * parameter means there is no id to tamper with.
     */
    protected function requireSelf(): User
    {
        $user = $this->identity();
        if (!$user) {
            throw new PermissionDeniedException('Not logged in.');
        }
        return $user;
    }

    protected function redirectToUser(User $user)
    {
        return $this->redirect()->toUrl($this->url()->fromRoute(
            'admin/id',
            ['controller' => 'user', 'action' => 'edit', 'id' => $user->getId()],
            ['fragment' => 'two-factor-totp']
        ));
    }

    /**
     * Tell the user their second factor was removed. If they did not ask for
     * it, this mail is how they find out.
     */
    protected function notifyReset(User $user): void
    {
        try {
            $translate = $this->viewHelpers()->get('translate');
            $mailer = $this->mailer();
            $message = $mailer->createMessage();
            $message
                ->addTo($user->getEmail(), $user->getName())
                ->setSubject(sprintf(
                    $translate('[%s] Two-factor authentication was reset'),
                    $mailer->getInstallationTitle()
                ))
                ->setBody(sprintf(
                    $translate('An administrator has reset two-factor authentication on your account. You can log in with your password alone until you set it up again. If you did not expect this, contact your administrator immediately.') . "\n\n%s",
                    $this->url()->fromRoute('admin', [], ['force_canonical' => true])
                ));
            $mailer->send($message);
        } catch (\Exception $e) {
            // A failed notification must not block the escape hatch itself.
            $this->logger()->err(sprintf('TwoFactorTotp: could not send reset notification: %s', $e->getMessage()));
        }
    }
}

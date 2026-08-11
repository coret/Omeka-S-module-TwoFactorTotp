<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller\Admin;

use Doctrine\ORM\EntityManager;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use Omeka\Entity\User;
use Omeka\Form\ConfirmForm;
use Omeka\Mvc\Exception\PermissionDeniedException;
use TwoFactorTotp\Entity\TrustedDevice;
use TwoFactorTotp\Entity\WebAuthnCredential;
use TwoFactorTotp\Stdlib\ChallengeStore;
use TwoFactorTotp\Stdlib\PasswordConfirmation;
use TwoFactorTotp\Form\ConfirmOtpForm;
use TwoFactorTotp\Form\PasswordConfirmForm;
use TwoFactorTotp\Service\PasskeyManager;
use TwoFactorTotp\Service\SecondFactorRegistry;
use TwoFactorTotp\Service\TotpManager;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * Managing your own second factor: enrolling, disabling, recovery codes and
 * trusted devices — plus the one action an administrator may take against
 * somebody else's account, resetting it.
 */
class TotpController extends AbstractActionController
{
    use \TwoFactorTotp\Controller\JsonEndpointTrait;

    protected EntityManager $entityManager;

    protected TotpManager $totpManager;

    protected TrustedDeviceManager $trustedDevices;

    protected SecondFactorRegistry $registry;

    protected PasskeyManager $passkeys;

    protected ChallengeStore $challenges;

    protected PasswordConfirmation $passwordConfirmation;

    public function __construct(
        EntityManager $entityManager,
        TotpManager $totpManager,
        TrustedDeviceManager $trustedDevices,
        SecondFactorRegistry $registry,
        PasskeyManager $passkeys,
        ChallengeStore $challenges,
        PasswordConfirmation $passwordConfirmation
    ) {
        $this->entityManager = $entityManager;
        $this->totpManager = $totpManager;
        $this->trustedDevices = $trustedDevices;
        $this->registry = $registry;
        $this->passkeys = $passkeys;
        $this->challenges = $challenges;
        $this->passwordConfirmation = $passwordConfirmation;
    }

    // ---------------------------------------------------------------- passkeys

    /**
     * List this account's passkeys, and register another.
     *
     * Behind a password prompt, because everything on this page changes what
     * protects the account. See requirePasswordConfirmation().
     */
    public function passkeysAction()
    {
        $user = $this->requireSelf();

        if ($prompt = $this->requirePasswordConfirmation($user, 'passkeys')) {
            return $prompt;
        }

        $view = new ViewModel;
        $view->setVariable('user', $user);
        $view->setVariable('credentials', $this->passkeys->listForUser($user));
        $view->setVariable('isAvailable', $this->passkeys->isAvailable());
        $view->setVariable('confirmForm', $this->getForm(ConfirmForm::class));
        $view->setVariable('challengeUrl', $this->url()->fromRoute('admin/two-factor', ['action' => 'passkey-challenge']));
        $view->setVariable('verifyUrl', $this->url()->fromRoute('admin/two-factor', ['action' => 'passkey-verify']));
        $view->setVariable('removeUrl', $this->url()->fromRoute('admin/two-factor', ['action' => 'passkey-remove']));
        return $view;
    }

    /**
     * Registration options, plus the challenge stashed for the verify step.
     */
    public function passkeyChallengeAction()
    {
        $user = $this->requireSelf();

        if (!$this->isSameOriginXhrPost()) {
            return $this->json(['error' => 'bad_request'], 400);
        }
        if (!$this->passwordConfirmation->isConfirmed((int) $user->getId())) {
            return $this->json(['error' => 'confirm_password'], 403);
        }

        if (!$this->passkeys->isAvailable()) {
            return $this->json(['error' => 'unavailable'], 503);
        }

        [$args, $challenge] = $this->passkeys->registrationArgs($user);
        $this->challenges->put(ChallengeStore::PURPOSE_REGISTER, $challenge);

        return $this->json($args);
    }

    /**
     * Store what the authenticator produced.
     */
    public function passkeyVerifyAction()
    {
        $user = $this->requireSelf();

        if (!$this->isSameOriginXhrPost()) {
            return $this->json(['error' => 'bad_request'], 400);
        }
        // The registration is only stored if the password was confirmed for
        // *this* account within the window. Without it a hijacked session could
        // plant a factor that then survives the victim changing their password.
        if (!$this->passwordConfirmation->isConfirmed((int) $user->getId())) {
            return $this->json(['error' => 'confirm_password'], 403);
        }

        if (!$this->passkeys->isAvailable()) {
            return $this->json(['error' => 'unavailable'], 503);
        }

        $challenge = $this->challenges->take(ChallengeStore::PURPOSE_REGISTER);
        if (null === $challenge) {
            return $this->json(['error' => 'no_challenge'], 409);
        }

        $posted = json_decode((string) $this->getRequest()->getContent(), true);
        foreach (['clientDataJSON', 'attestationObject'] as $field) {
            if (empty($posted[$field]) || !is_string($posted[$field])) {
                return $this->json(['error' => 'malformed'], 400);
            }
        }

        try {
            $data = $this->passkeys->webAuthn()->processCreate(
                base64_decode($posted['clientDataJSON'], true) ?: '',
                base64_decode($posted['attestationObject'], true) ?: '',
                $challenge,
                false,
                true,
                false
            );
        } catch (\Throwable $e) {
            $this->logger()->warn(sprintf(
                'TwoFactorTotp: passkey registration rejected for user "%s" (id %s): %s',
                $user->getEmail(),
                $user->getId(),
                $e->getMessage()
            ));
            return $this->json(['error' => 'rejected'], 400);
        }

        $credentialId = rtrim(strtr(base64_encode($data->credentialId), '+/', '-_'), '=');

        if ($this->passkeys->findByCredentialId($credentialId)) {
            return $this->json(['error' => 'already_registered'], 409);
        }

        $credential = new WebAuthnCredential();
        $credential
            ->setUser($user)
            ->setCredentialId($credentialId)
            ->setPublicKey((string) $data->credentialPublicKey)
            ->setSignCount((int) ($data->signatureCounter ?? 0))
            ->setLabel(isset($posted['label']) ? trim((string) $posted['label']) : null)
            ->setTransports(isset($posted['transports']) && is_array($posted['transports'])
                ? implode(',', array_map('strval', $posted['transports']))
                : null)
            ->setAaguid(isset($data->AAGUID) ? bin2hex((string) $data->AAGUID) : null)
            ->setCreated(new \DateTime('now'));

        $this->entityManager->persist($credential);
        $this->entityManager->flush();

        $this->logger()->info(sprintf(
            'TwoFactorTotp: user "%s" (id %s) registered a passkey.',
            $user->getEmail(),
            $user->getId()
        ));

        return $this->json(['ok' => true, 'redirect' => $this->url()->fromRoute(
            'admin/two-factor',
            ['action' => 'passkeys']
        )]);
    }

    /**
     * Remove one. Ownership is checked: the id comes from the request.
     */
    public function passkeyRemoveAction()
    {
        $user = $this->requireSelf();

        if (!$this->getRequest()->isPost()) {
            return $this->redirect()->toRoute('admin/two-factor', ['action' => 'passkeys']);
        }

        // Removing a factor is as much a change to the account's protection as
        // adding one, so it is held to the same standard.
        if ($prompt = $this->requirePasswordConfirmation($user, 'passkeys')) {
            return $prompt;
        }

        $form = $this->getForm(ConfirmForm::class);
        $form->setData($this->params()->fromPost());
        if (!$form->isValid()) {
            $this->messenger()->addError('Invalid or missing CSRF token'); // @translate
            return $this->redirect()->toRoute('admin/two-factor', ['action' => 'passkeys']);
        }

        $credential = $this->entityManager->find(
            WebAuthnCredential::class,
            (int) $this->params()->fromPost('credential_id')
        );
        if ($credential && $credential->getUser() === $user) {
            $this->passkeys->remove($credential);
            $this->logger()->warn(sprintf(
                'TwoFactorTotp: user "%s" (id %s) removed a passkey.',
                $user->getEmail(),
                $user->getId()
            ));
            $this->messenger()->addSuccess('Passkey removed.'); // @translate
        }

        return $this->redirect()->toRoute('admin/two-factor', ['action' => 'passkeys']);
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
        $view->setVariable('secret', $this->totpManager->getPlainSecret($enrollment));
        $view->setVariable('provisioningUri', $this->totpManager->getProvisioningUri($enrollment));
        $view->setVariable('isForced', $this->registry->isRoleForced($user));
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

        if ($this->registry->isRoleForced($user)) {
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

                // Recovery codes are kept if a passkey (or anything else) is
                // still enrolled: they are the fallback for whatever remains,
                // not for TOTP alone.
                $this->totpManager->disable($user, false);
                if (!$this->registry->hasAnyEnrolled($user)) {
                    $this->totpManager->deleteRecoveryCodes($user);
                }
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
                // Every factor, not just TOTP. This is the escape hatch for
                // somebody who cannot get in, so leaving their passkeys behind
                // would leave them exactly as locked out as before.
                $this->totpManager->disable($targetUser, true);
                $removedPasskeys = $this->passkeys->removeAllForUser($targetUser);

                $this->logger()->warn(sprintf(
                    'TwoFactorTotp: user "%s" (id %s) reset two-factor authentication for "%s" (id %s), '
                    . 'removing %d passkey(s).',
                    $this->identity() ? $this->identity()->getEmail() : 'unknown',
                    $this->identity() ? $this->identity()->getId() : '?',
                    $targetUser->getEmail(),
                    $targetUser->getId(),
                    $removedPasskeys
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
        // Any factor, not just TOTP: a passkey-only account has something to
        // reset, and telling the administrator otherwise was how it stayed
        // locked out.
        $view->setVariable('isEnabled', $this->registry->hasAnyEnrolled($targetUser));
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

    /**
     * Hold a page behind the account password.
     *
     * Returns a view model to render — the password prompt — when the password
     * has not been confirmed recently, and null when the caller may carry on.
     * The `if ($prompt = ...) return $prompt;` shape at the call sites is
     * deliberate: forgetting the return is then a visibly broken page rather
     * than a silently unguarded one.
     *
     * The POST is handled here so every guarded action gets identical
     * behaviour, including that a wrong password re-renders the prompt instead
     * of falling through.
     *
     * @param string $action Where to send the form back to.
     * @return ViewModel|null
     */
    protected function requirePasswordConfirmation(User $user, string $action)
    {
        if ($this->passwordConfirmation->isConfirmed((int) $user->getId())) {
            return null;
        }

        $form = $this->getForm(PasswordConfirmForm::class, [
            'button_label' => 'Confirm', // @translate
        ]);
        $form->setAttribute('action', $this->url()->fromRoute('admin/two-factor', ['action' => $action]));

        if ($this->getRequest()->isPost()) {
            $form->setData($this->params()->fromPost());
            if ($form->isValid()) {
                $data = $form->getData();
                if ($user->verifyPassword($data['password'])) {
                    $this->passwordConfirmation->confirm((int) $user->getId());
                    return null;
                }
                $this->messenger()->addError('The password entered was invalid.'); // @translate
            } else {
                // A post that is not the password form — the passkey remove
                // button, say — must not be reported as a bad password.
                if (null !== $this->params()->fromPost('password')) {
                    $this->messenger()->addFormErrors($form);
                }
            }
        }

        $view = new ViewModel;
        $view->setTemplate('two-factor-totp/admin/totp/confirm-password');
        $view->setVariable('user', $user);
        $view->setVariable('form', $form);
        return $view;
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

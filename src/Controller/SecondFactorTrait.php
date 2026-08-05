<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller;

use Laminas\Session\Container;
use Omeka\Entity\User;

/**
 * The parts of step two that are the same whichever factor is being presented:
 * who is waiting, what happens when they succeed, and what happens when the
 * wait ran out.
 *
 * Shared rather than duplicated because completeLogin() is the *only* place in
 * the module that grants an identity. A second copy of it is a second place for
 * the session handling or the trusted-device cookie to drift out of step.
 *
 * Requires: $pendingLogin, $entityManager, $auth, $trustedDevices.
 */
trait SecondFactorTrait
{
    /**
     * The password-verified user waiting to present a factor.
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
     * Grant the identity. The single point at which a login becomes a session.
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

    protected function expired()
    {
        $this->messenger()->addError(
            'Your login timed out. Please log in again.' // @translate
        );
        return $this->redirect()->toRoute('login');
    }
}

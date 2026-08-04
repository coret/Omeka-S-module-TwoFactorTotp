<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Session\Container;
use Laminas\View\Model\ViewModel;
use Omeka\Controller\LoginController as CoreLoginController;
use Omeka\Form\LoginForm;
use TwoFactorTotp\Authentication\Adapter\SecondFactorAdapter;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\PendingLogin;

/**
 * Stands in for Omeka's login controller, overriding only loginAction().
 *
 * logoutAction(), forgotPasswordAction() and createPasswordAction() are
 * inherited unchanged — there is deliberately no copy of them here to drift
 * out of sync with core.
 *
 * @see \TwoFactorTotp\Service\Delegator\LoginControllerDelegatorFactory
 */
class LoginController extends CoreLoginController
{
    protected TrustedDeviceManager $trustedDevices;

    protected PendingLogin $pendingLogin;

    public function __construct(
        EntityManager $entityManager,
        AuthenticationService $auth,
        TrustedDeviceManager $trustedDevices,
        PendingLogin $pendingLogin
    ) {
        parent::__construct($entityManager, $auth);
        $this->trustedDevices = $trustedDevices;
        $this->pendingLogin = $pendingLogin;
    }

    /**
     * Core's loginAction with one extra branch: a result that means "password
     * fine, code needed" parks a pending login and redirects to step 2 instead
     * of reporting a bad password.
     *
     * @see \Omeka\Controller\LoginController::loginAction()
     */
    public function loginAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('admin');
        }

        // Arriving at the login form abandons any half-finished second step.
        $this->pendingLogin->clear();

        $form = $this->getForm(LoginForm::class);

        if ($this->getRequest()->isPost()) {
            $data = $this->getRequest()->getPost();
            $form->setData($data);
            if ($form->isValid()) {
                $sessionManager = Container::getDefaultManager();
                $sessionManager->regenerateId();
                $validatedData = $form->getData();
                $adapter = $this->auth->getAdapter();
                $adapter->setIdentity($validatedData['email']);
                $adapter->setCredential($validatedData['password']);
                $result = $this->auth->authenticate();

                if ($result->isValid()) {
                    // A trusted device carried this login; refresh its cookie
                    // with the rotated validator.
                    if ($adapter instanceof SecondFactorAdapter
                        && ($cookieValue = $adapter->getRotatedDeviceCookie())
                    ) {
                        $this->getResponse()->getHeaders()
                            ->addHeader($this->trustedDevices->buildSetCookie($cookieValue));
                    }

                    $this->messenger()->addSuccess('Successfully logged in'); // @translate
                    $this->getEventManager()->trigger('user.login', $this->auth->getIdentity());
                    $session = $sessionManager->getStorage();
                    if ($redirectUrl = $session->offsetGet('redirect_url')) {
                        return $this->redirect()->toUrl($redirectUrl);
                    }
                    if ($this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')) {
                        return $this->redirect()->toRoute('admin');
                    }
                    return $this->redirect()->toRoute('top');
                }

                if ($adapter instanceof SecondFactorAdapter
                    && SecondFactorAdapter::isSecondFactorRequired($result)
                ) {
                    $pendingUser = $adapter->getPendingUser();
                    if ($pendingUser) {
                        $session = $sessionManager->getStorage();
                        $this->pendingLogin->start(
                            (int) $pendingUser->getId(),
                            $session->offsetGet('redirect_url')
                        );
                        return $this->redirect()->toRoute('two-factor');
                    }
                }

                $this->messenger()->addError('Email or password is invalid'); // @translate
            } else {
                $this->messenger()->addFormErrors($form);
            }
        }

        $view = new ViewModel;
        $view->setVariable('form', $form);
        // Render core's login template, not one of ours.
        $view->setTemplate('omeka/login/login');
        return $view;
    }

    /**
     * Logging out drops any pending second step with the session.
     */
    public function logoutAction()
    {
        $this->pendingLogin->clear();
        return parent::logoutAction();
    }
}

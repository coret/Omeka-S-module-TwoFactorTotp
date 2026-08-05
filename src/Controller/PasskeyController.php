<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\View\Model\ViewModel;
use TwoFactorTotp\Service\PasskeyManager;
use TwoFactorTotp\Service\TrustedDeviceManager;
use TwoFactorTotp\Stdlib\ChallengeStore;
use TwoFactorTotp\Stdlib\PendingLogin;

/**
 * Step two, presented with a passkey.
 *
 * Three actions: a page to stand on, a JSON endpoint handing out the challenge,
 * and a JSON endpoint verifying what the authenticator signed. The browser does
 * the middle part; this side only ever sees the result.
 *
 * Anonymous access is deliberate and matches OtpController: the user has proved
 * their password but holds no identity yet, and will not until completeLogin().
 */
class PasskeyController extends AbstractActionController
{
    use SecondFactorTrait;

    protected EntityManager $entityManager;

    protected AuthenticationService $auth;

    protected PasskeyManager $passkeys;

    protected TrustedDeviceManager $trustedDevices;

    protected PendingLogin $pendingLogin;

    protected ChallengeStore $challenges;

    public function __construct(
        EntityManager $entityManager,
        AuthenticationService $auth,
        PasskeyManager $passkeys,
        TrustedDeviceManager $trustedDevices,
        PendingLogin $pendingLogin,
        ChallengeStore $challenges
    ) {
        $this->entityManager = $entityManager;
        $this->auth = $auth;
        $this->passkeys = $passkeys;
        $this->trustedDevices = $trustedDevices;
        $this->pendingLogin = $pendingLogin;
        $this->challenges = $challenges;
    }

    /**
     * The page the user lands on: a button, and a link back to the other ways in.
     */
    public function indexAction()
    {
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('admin');
        }

        $user = $this->pendingUser();
        if (!$user) {
            return $this->expired();
        }

        $offerRemember = $this->trustedDevices->isEnabled();

        $view = new ViewModel;
        $view->setVariable('user', $user);
        $view->setVariable('offerRemember', $offerRemember);
        $view->setVariable('rememberDays', $this->trustedDevices->getTrustDays());
        $view->setVariable('secondsRemaining', $this->pendingLogin->getSecondsRemaining());
        $view->setVariable('isAvailable', $this->passkeys->isAvailable());
        $view->setVariable('challengeUrl', $this->url()->fromRoute('two-factor-passkey', ['action' => 'challenge']));
        $view->setVariable('verifyUrl', $this->url()->fromRoute('two-factor-passkey', ['action' => 'verify']));
        $view->setVariable('otpUrl', $this->url()->fromRoute('two-factor'));
        $view->setVariable('recoveryUrl', $this->url()->fromRoute('two-factor', ['action' => 'recovery']));
        return $view;
    }

    /**
     * Hand out the assertion options, and stash the challenge to check against.
     */
    public function challengeAction()
    {
        $user = $this->pendingUser();
        if (!$user) {
            return $this->json(['error' => 'expired'], 440);
        }

        if (!$this->passkeys->isAvailable()) {
            return $this->json(['error' => 'unavailable'], 503);
        }

        if (!$this->passkeys->countForUser($user)) {
            return $this->json(['error' => 'no_credentials'], 409);
        }

        [$args, $challenge] = $this->passkeys->assertionArgs($user);
        $this->challenges->put(ChallengeStore::PURPOSE_AUTHENTICATE, $challenge);

        return $this->json($args);
    }

    /**
     * Check the signature, and on success grant the identity.
     */
    public function verifyAction()
    {
        $user = $this->pendingUser();
        if (!$user) {
            return $this->json(['error' => 'expired'], 440);
        }

        if (!$this->passkeys->isAvailable()) {
            return $this->json(['error' => 'unavailable'], 503);
        }

        // Taken, not peeked at: a replayed response must find nothing here.
        $challenge = $this->challenges->take(ChallengeStore::PURPOSE_AUTHENTICATE);
        if (null === $challenge) {
            return $this->json(['error' => 'no_challenge'], 409);
        }

        $posted = json_decode((string) $this->getRequest()->getContent(), true);
        foreach (['id', 'clientDataJSON', 'authenticatorData', 'signature'] as $field) {
            if (empty($posted[$field]) || !is_string($posted[$field])) {
                return $this->reject($user, 'malformed response');
            }
        }

        $credential = $this->passkeys->findByCredentialId($posted['id']);

        // Ownership. Without this any passkey registered anywhere on the
        // installation would satisfy anybody's second factor.
        if (!$credential || $credential->getUser() !== $user) {
            return $this->reject($user, 'unknown credential');
        }

        try {
            $webAuthn = $this->passkeys->webAuthn();
            $webAuthn->processGet(
                base64_decode($posted['clientDataJSON'], true) ?: '',
                base64_decode($posted['authenticatorData'], true) ?: '',
                base64_decode($posted['signature'], true) ?: '',
                (string) $credential->getPublicKey(),
                $challenge,
                $credential->getSignCount() ?: null,
                false,
                true
            );
        } catch (\Throwable $e) {
            return $this->reject($user, 'signature rejected: ' . $e->getMessage());
        }

        $signCount = (int) $webAuthn->getSignatureCounter();
        if ($this->passkeys->isCounterRegression($credential, $signCount)) {
            // Not fatal on its own — plenty of authenticators never increment —
            // but a counter going backwards is the documented cloning signal.
            $this->logger()->warn(sprintf(
                'TwoFactorTotp: signature counter regression for user "%s" (id %s), credential %s.',
                $user->getEmail(),
                $user->getId(),
                $credential->getId()
            ));
        }
        $this->passkeys->recordUse($credential, $signCount);

        $remember = !empty($posted['remember_device']) && $this->trustedDevices->isEnabled();
        $this->completeLogin($user, $remember);

        // completeLogin() builds a redirect the browser cannot follow from
        // fetch(), so hand the destination back and let the script go there.
        return $this->json([
            'ok' => true,
            'redirect' => $this->getResponse()->getHeaders()->get('Location')
                ? $this->getResponse()->getHeaders()->get('Location')->getUri()
                : $this->url()->fromRoute('admin'),
        ]);
    }

    /**
     * A failed attempt costs the same as a wrong code, so a passkey cannot be
     * used to sit outside the attempt limit.
     */
    protected function reject(\Omeka\Entity\User $user, string $reason)
    {
        $this->logger()->warn(sprintf(
            'TwoFactorTotp: failed passkey attempt for user "%s" (id %s) from %s — %s.',
            $user->getEmail(),
            $user->getId(),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $reason
        ));

        if (!$this->pendingLogin->recordFailure()) {
            return $this->json(['error' => 'too_many_attempts'], 429);
        }

        return $this->json([
            'error' => 'rejected',
            'remaining' => $this->pendingLogin->getRemainingAttempts(),
        ], 401);
    }

    /**
     * Written straight onto the response: Omeka registers only
     * Omeka\ViewApiJsonStrategy, so a JsonModel would not render here.
     */
    protected function json($data, int $status = 200)
    {
        $response = $this->getResponse();
        $response->setStatusCode($status);
        $response->getHeaders()->addHeaderLine('Content-Type', 'application/json');
        $response->setContent(json_encode($data));
        return $response;
    }
}

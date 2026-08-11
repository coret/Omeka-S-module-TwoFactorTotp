<?php declare(strict_types=1);

namespace TwoFactorTotp\Controller;

/**
 * The bits shared by the four WebAuthn JSON endpoints — two on the login path,
 * two in admin.
 *
 * They are not ordinary form posts: the browser talks to them with fetch() and
 * gets JSON back, so they need their own request check and their own way of
 * writing a response.
 */
trait JsonEndpointTrait
{
    /**
     * A same-origin XHR, and nothing else.
     *
     * These endpoints carry no CSRF token. In practice the WebAuthn challenge
     * already makes them unforgeable — an attacker cannot read the challenge
     * they would have to produce a signature over — but that is a property of
     * the protocol rather than a decision in this code, and it would quietly
     * stop being true if an endpoint were ever added that did not issue one.
     *
     * X-Requested-With cannot be set on a cross-origin request without a
     * preflight, which this application never answers, so requiring it makes
     * the protection explicit and costs one header.
     */
    protected function isSameOriginXhrPost(): bool
    {
        $request = $this->getRequest();
        if (!$request->isPost()) {
            return false;
        }

        $header = $request->getHeader('X-Requested-With');

        return $header && 'xmlhttprequest' === strtolower(trim((string) $header->getFieldValue()));
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

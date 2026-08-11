<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\ORM\EntityManager;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Omeka\Settings\Settings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\TrustedDeviceManager;

/**
 * The trusted-device cookie is a bearer token that stands in for the whole
 * second factor, so the Secure flag is not a nicety.
 *
 * It used to be set only when HTTPS could be detected from the request, which
 * silently omitted it behind any proxy that signals TLS in a way Laminas does
 * not read. Secure is now the default and comes off only for the local
 * development hosts where a browser has no HTTPS to offer.
 */
class TrustedDeviceCookieTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function managerFor(string $url): TrustedDeviceManager
    {
        $settings = $this->createMock(Settings::class);
        $settings->method('get')->willReturn(14);

        $request = new HttpRequest();
        $request->setUri($url);

        // Nothing here reaches the database: buildSetCookie only reads the
        // trust-days setting and the request.
        return new TrustedDeviceManager(
            $this->createMock(EntityManager::class),
            $settings,
            $request
        );
    }

    public function testSecureOverHttps(): void
    {
        $this->assertTrue($this->managerFor('https://example.org/login')->buildSetCookie('a:b')->isSecure());
    }

    /**
     * The case the old code got wrong: a TLS-terminating proxy that forwards
     * plain HTTP without a header Laminas recognises.
     */
    public function testSecureOverPlainHttpToAPublicHost(): void
    {
        $this->assertTrue(
            $this->managerFor('http://example.org/login')->buildSetCookie('a:b')->isSecure(),
            'A public host must get a Secure cookie even when TLS is not detectable from the request.'
        );
    }

    /**
     * ...but not at the cost of breaking development, where there is no HTTPS
     * to be had and a Secure cookie would simply never come back.
     */
    public function testNotSecureOnAPlainLocalDevelopmentHost(): void
    {
        foreach (['http://localhost:8080/login', 'http://127.0.0.1/login', 'http://omeka.test/login'] as $url) {
            $this->assertFalse(
                $this->managerFor($url)->buildSetCookie('a:b')->isSecure(),
                "$url should not demand a Secure cookie."
            );
        }
    }

    public function testAlwaysHttpOnlyAndSameSiteLax(): void
    {
        $cookie = $this->managerFor('https://example.org/login')->buildSetCookie('a:b');

        $this->assertTrue($cookie->isHttponly());
        $this->assertSame('Lax', $cookie->getSameSite());
    }

    public function testTheClearCookieCarriesTheSameFlags(): void
    {
        $manager = $this->managerFor('http://example.org/login');

        $this->assertTrue($manager->buildClearCookie()->isSecure());
        $this->assertTrue($manager->buildClearCookie()->isHttponly());
    }
}

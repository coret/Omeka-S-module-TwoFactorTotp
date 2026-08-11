<?php declare(strict_types=1);

namespace TwoFactorTotp\Test;

use Doctrine\ORM\EntityManager;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Omeka\Settings\Settings;
use PHPUnit\Framework\TestCase;
use TwoFactorTotp\Service\PasskeyManager;

/**
 * The relying-party id is what binds a passkey to a domain, and the whole
 * phishing defence rests on it. It used to be read straight out of
 * $_SERVER['HTTP_HOST'] with no validation, which is both untestable and the
 * shape host-header bugs come in.
 */
class RelyingPartyIdTest extends TestCase
{
    protected function setUp(): void
    {
        if (!TWOFACTORTOTP_HAS_COMPOSER) {
            $this->markTestSkipped('Needs Omeka\'s Composer autoloader; set OMEKA_VENDOR.');
        }
    }

    private function manager(string $configuredRpId, ?string $url): PasskeyManager
    {
        $settings = $this->createMock(Settings::class);
        $settings->method('get')->willReturnCallback(
            fn (string $id, $default = null) => 'twofactortotp_rp_id' === $id ? $configuredRpId : $default
        );

        $request = null;
        if (null !== $url) {
            $request = new HttpRequest();
            $request->setUri($url);
        }

        return new PasskeyManager($this->createMock(EntityManager::class), $settings, $request);
    }

    public function testAConfiguredValueWins(): void
    {
        $this->assertSame(
            'example.org',
            $this->manager('example.org', 'https://other.example.net/x')->getRelyingPartyId()
        );
    }

    public function testFallsBackToTheHostServingTheRequest(): void
    {
        $this->assertSame('example.org', $this->manager('', 'https://example.org/login')->getRelyingPartyId());
    }

    public function testThePortIsNotPartOfTheRelyingPartyId(): void
    {
        $this->assertSame('localhost', $this->manager('', 'http://localhost:8080/login')->getRelyingPartyId());
    }

    public function testCaseIsNormalised(): void
    {
        $this->assertSame('example.org', $this->manager('EXAMPLE.ORG', 'https://example.org/x')->getRelyingPartyId());
    }

    /**
     * A Host header is attacker-supplied. A browser would refuse the ceremony
     * anyway, but a value that is not a hostname has no business being handed
     * to the library as one.
     */
    public function testAHostThatIsNotAHostnameIsRefused(): void
    {
        foreach (['evil.example.org/path', 'http://evil.example.org', 'a b', '', '-bad-.org'] as $junk) {
            $this->assertSame(
                'localhost',
                $this->manager($junk, null)->getRelyingPartyId(),
                "\"$junk\" should not be accepted as a relying-party id."
            );
        }
    }

    public function testNoRequestAtAllStillYieldsSomethingUsable(): void
    {
        $this->assertSame('localhost', $this->manager('', null)->getRelyingPartyId());
    }
}

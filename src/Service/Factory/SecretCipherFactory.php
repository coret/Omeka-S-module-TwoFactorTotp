<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Factory;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Service\SecretCipher;

/**
 * The keys come from the *application* config, which is where Omeka merges
 * config/local.config.php:
 *
 *     'twofactortotp' => [
 *         'encryption_key' => 'a long random string',
 *         'previous_encryption_keys' => ['the key being retired'],
 *     ],
 *
 * Deliberately not a module setting. A setting lives in the database next to
 * the secrets it would protect, so the same SELECT would leak both and the
 * encryption would buy nothing.
 *
 * The current key goes first; retired keys follow and are only ever used to
 * read. There is no default: see the note in SecretCipher.
 */
class SecretCipherFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return SecretCipher::fromConfig($services->get('Config'));
    }
}

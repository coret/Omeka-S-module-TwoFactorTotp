<?php declare(strict_types=1);

namespace TwoFactorTotp\Service\Form;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use TwoFactorTotp\Form\ConfigForm;

class ConfigFormFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        $form = new ConfigForm(null, $options ?? []);
        $form->setAcl($services->get('Omeka\Acl'));
        return $form;
    }
}

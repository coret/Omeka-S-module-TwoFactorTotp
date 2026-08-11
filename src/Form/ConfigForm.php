<?php declare(strict_types=1);

namespace TwoFactorTotp\Form;

use Laminas\Form\Form;
use Omeka\Permissions\Acl;

class ConfigForm extends Form
{
    protected ?Acl $acl = null;

    public function setAcl(Acl $acl): self
    {
        $this->acl = $acl;
        return $this;
    }

    public function init(): void
    {
        $this->add([
            'name' => 'twofactortotp_issuer',
            'type' => 'Text',
            'options' => [
                'label' => 'Issuer name', // @translate
                'info' => 'The name shown next to the account in the authenticator app. Leave empty to use the installation title.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_issuer',
            ],
        ]);

        $this->add([
            'type' => 'text',
            'name' => 'twofactortotp_rp_id',
            'options' => [
                'label' => 'Passkey domain', // @translate
                'info' => 'The domain passkeys are bound to. Leave empty to use the host the site is served from, which is right unless the site answers on more than one name. Changing it invalidates every passkey already registered.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_rp_id',
                'placeholder' => 'example.org',
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_required_roles',
            'type' => 'MultiCheckbox',
            'options' => [
                'label' => 'Require two-factor authentication for these roles', // @translate
                'info' => 'Users with a selected role are held on the setup page, anywhere on the site, until they have enrolled in a second factor. Any factor satisfies it. Existing sessions are not affected.', // @translate
                'value_options' => $this->acl ? $this->acl->getRoleLabels() : [],
            ],
            'attributes' => [
                'id' => 'twofactortotp_required_roles',
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_remember_device_days',
            'type' => 'Number',
            'options' => [
                'label' => 'Remember a device for (days)', // @translate
                'info' => 'How long a device stays trusted after the user ticks "remember this device". Set to 0 to remove the option entirely.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_remember_device_days',
                'min' => 0,
                'max' => 365,
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_window',
            'type' => 'Number',
            'options' => [
                'label' => 'Accepted time steps either side', // @translate
                'info' => 'How much clock drift between server and phone to tolerate, in 30-second steps. 1 is the usual value; raising it widens the window in which a code stays valid.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_window',
                'min' => 0,
                'max' => 10,
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_pending_ttl',
            'type' => 'Number',
            'options' => [
                'label' => 'Time allowed to enter the code (seconds)', // @translate
                'info' => 'How long a password-verified login may wait at the code screen before it is discarded.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_pending_ttl',
                'min' => 30,
                'max' => 3600,
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_max_attempts',
            'type' => 'Number',
            'options' => [
                'label' => 'Wrong codes allowed per login', // @translate
                'info' => 'After this many wrong codes the login is discarded and the user starts again from the password screen.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_max_attempts',
                'min' => 1,
                'max' => 20,
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_lockout_threshold',
            'type' => 'Number',
            'options' => [
                'label' => 'Failed attempts before the account is locked', // @translate
                'info' => 'Counted per account rather than per login, so starting a new login does not hand out a fresh set of guesses. Recovery codes are never locked, so nobody is left with no way in. Set to 0 to turn the lockout off.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_lockout_threshold',
                'min' => 0,
                'max' => 100,
            ],
        ]);

        $this->add([
            'name' => 'twofactortotp_lockout_seconds',
            'type' => 'Number',
            'options' => [
                'label' => 'How long the account stays locked (seconds)', // @translate
                'info' => 'The length of the first lockout. Each further lockout on the same account is twice as long as the one before, up to a day.', // @translate
            ],
            'attributes' => [
                'id' => 'twofactortotp_lockout_seconds',
                'min' => 30,
                'max' => 86400,
            ],
        ]);

        $inputFilter = $this->getInputFilter();
        $inputFilter->add(['name' => 'twofactortotp_issuer', 'required' => false]);
        $inputFilter->add(['name' => 'twofactortotp_required_roles', 'required' => false]);
        $inputFilter->add(['name' => 'twofactortotp_rp_id', 'required' => false]);
    }
}

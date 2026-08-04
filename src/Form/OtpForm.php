<?php declare(strict_types=1);

namespace TwoFactorTotp\Form;

use Laminas\Form\Form;

/**
 * Step 2 of the login: the six digits from the authenticator app.
 *
 * Options (passed through getForm()):
 *  - offer_remember_device (bool)
 *  - remember_device_days (int)
 */
class OtpForm extends Form
{
    public function init(): void
    {
        $this->setAttribute('class', 'disable-unsaved-warning');

        $offerRemember = (bool) $this->getOption('offer_remember_device');
        $days = (int) ($this->getOption('remember_device_days') ?: 14);

        $this->add([
            'name' => 'code',
            'type' => 'Text',
            'options' => [
                'label' => 'Authentication code', // @translate
                'info' => 'The 6-digit code from your authenticator app.', // @translate
            ],
            'attributes' => [
                'id' => 'totp-code',
                'required' => true,
                // Together these make phones offer the code from the clipboard
                // or the notification shade instead of a full keyboard.
                'inputmode' => 'numeric',
                'pattern' => '[0-9 ]*',
                'autocomplete' => 'one-time-code',
                'autofocus' => 'autofocus',
                'maxlength' => 7,
                'placeholder' => '000000',
                'spellcheck' => 'false',
            ],
        ]);

        if ($offerRemember) {
            $this->add([
                'name' => 'remember_device',
                'type' => 'Checkbox',
                'options' => [
                    'label' => sprintf(
                        'Remember this device for %d days', // @translate
                        $days
                    ),
                    'info' => 'Only tick this on a device that is yours alone.', // @translate
                ],
                'attributes' => [
                    'id' => 'totp-remember-device',
                ],
            ]);
        }

        $this->add([
            'name' => 'submit',
            'type' => 'Submit',
            'attributes' => [
                'id' => 'totp-submit',
                'value' => 'Verify', // @translate
            ],
        ]);

        $inputFilter = $this->getInputFilter();
        $inputFilter->add([
            'name' => 'code',
            'required' => true,
            'filters' => [
                ['name' => 'StringTrim'],
            ],
        ]);
        if ($offerRemember) {
            $inputFilter->add([
                'name' => 'remember_device',
                'required' => false,
            ]);
        }
    }
}

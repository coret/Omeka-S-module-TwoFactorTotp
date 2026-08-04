<?php declare(strict_types=1);

namespace TwoFactorTotp\Form;

use Laminas\Form\Form;

/**
 * Re-prompt for the account password before a destructive change (turning the
 * second factor off, or reissuing recovery codes).
 *
 * An unlocked, unattended browser should not be enough to strip an account's
 * second factor.
 */
class PasswordConfirmForm extends Form
{
    public function init(): void
    {
        $buttonLabel = (string) ($this->getOption('button_label') ?: 'Confirm'); // @translate

        $this->add([
            'name' => 'password',
            'type' => 'Password',
            'options' => [
                'label' => 'Your password', // @translate
            ],
            'attributes' => [
                'id' => 'totp-confirm-password',
                'required' => true,
                'autocomplete' => 'current-password',
            ],
        ]);

        $this->add([
            'name' => 'submit',
            'type' => 'Submit',
            'attributes' => [
                'id' => 'totp-password-submit',
                'value' => $buttonLabel,
            ],
        ]);

        $this->getInputFilter()->add([
            'name' => 'password',
            'required' => true,
        ]);
    }
}

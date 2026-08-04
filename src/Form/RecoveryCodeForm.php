<?php declare(strict_types=1);

namespace TwoFactorTotp\Form;

use Laminas\Form\Form;

/**
 * The way back in when the authenticator app is gone.
 */
class RecoveryCodeForm extends Form
{
    public function init(): void
    {
        $this->setAttribute('class', 'disable-unsaved-warning');

        $this->add([
            'name' => 'recovery_code',
            'type' => 'Text',
            'options' => [
                'label' => 'Recovery code', // @translate
                'info' => 'One of the codes you saved when you set up two-factor authentication. Each code works once.', // @translate
            ],
            'attributes' => [
                'id' => 'totp-recovery-code',
                'required' => true,
                'autocomplete' => 'off',
                'autofocus' => 'autofocus',
                'spellcheck' => 'false',
                'placeholder' => 'XXXXX-XXXXX',
            ],
        ]);

        $this->add([
            'name' => 'submit',
            'type' => 'Submit',
            'attributes' => [
                'id' => 'totp-recovery-submit',
                'value' => 'Use recovery code', // @translate
            ],
        ]);

        $this->getInputFilter()->add([
            'name' => 'recovery_code',
            'required' => true,
            'filters' => [
                ['name' => 'StringTrim'],
            ],
        ]);
    }
}

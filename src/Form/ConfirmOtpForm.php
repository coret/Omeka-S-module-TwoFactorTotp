<?php declare(strict_types=1);

namespace TwoFactorTotp\Form;

use Laminas\Form\Form;

/**
 * Enrollment step 2: prove the authenticator app really holds the secret
 * before it becomes something that can lock the user out.
 */
class ConfirmOtpForm extends Form
{
    public function init(): void
    {
        $this->add([
            'name' => 'code',
            'type' => 'Text',
            'options' => [
                'label' => 'Code from your app', // @translate
                'info' => 'Enter the 6-digit code your authenticator app shows now.', // @translate
            ],
            'attributes' => [
                'id' => 'totp-confirm-code',
                'required' => true,
                'inputmode' => 'numeric',
                'pattern' => '[0-9 ]*',
                'autocomplete' => 'one-time-code',
                'maxlength' => 7,
                'placeholder' => '000000',
            ],
        ]);

        $this->add([
            'name' => 'submit',
            'type' => 'Submit',
            'attributes' => [
                'id' => 'totp-confirm-submit',
                'value' => 'Enable two-factor authentication', // @translate
            ],
        ]);

        $this->getInputFilter()->add([
            'name' => 'code',
            'required' => true,
            'filters' => [
                ['name' => 'StringTrim'],
            ],
        ]);
    }
}

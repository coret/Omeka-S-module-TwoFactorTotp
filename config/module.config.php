<?php declare(strict_types=1);

namespace TwoFactorTotp;

use Laminas\Form\ElementFactory;
use Laminas\Router\Http\Segment;
use Laminas\ServiceManager\Factory\InvokableFactory;

return [
    'entity_manager' => [
        'mapping_classes_paths' => [
            dirname(__DIR__) . '/src/Entity',
        ],
        'proxy_paths' => [
            dirname(__DIR__) . '/data/doctrine-proxies',
        ],
    ],

    'service_manager' => [
        'factories' => [
            Service\Totp::class => InvokableFactory::class,
            Service\RecoveryCodeManager::class => Service\Factory\RecoveryCodeManagerFactory::class,
            Service\TotpManager::class => Service\Factory\TotpManagerFactory::class,
            Service\TrustedDeviceManager::class => Service\Factory\TrustedDeviceManagerFactory::class,
            Stdlib\PendingLogin::class => Service\Factory\PendingLoginFactory::class,
        ],
        'delegators' => [
            // Wrap the adapter so that *every* caller of authenticate() has to
            // clear the second factor, not just the login form.
            'Omeka\AuthenticationService' => [
                Service\Delegator\AuthenticationServiceDelegatorFactory::class,
            ],
            // Revoke trusted devices when a password changes.
            'Omeka\EntityManager' => [
                Service\Delegator\EntityManagerDelegatorFactory::class,
            ],
        ],
    ],

    'controllers' => [
        'factories' => [
            Controller\OtpController::class => Service\Factory\OtpControllerFactory::class,
            Controller\Admin\TotpController::class => Service\Factory\AdminTotpControllerFactory::class,
        ],
        'delegators' => [
            // Swap core's login controller for our subclass, which understands
            // the "password fine, code needed" result.
            'Omeka\Controller\Login' => [
                Service\Delegator\LoginControllerDelegatorFactory::class,
            ],
        ],
    ],

    'form_elements' => [
        'factories' => [
            // ElementFactory passes creation options into the form constructor.
            Form\OtpForm::class => ElementFactory::class,
            Form\RecoveryCodeForm::class => ElementFactory::class,
            Form\ConfirmOtpForm::class => ElementFactory::class,
            Form\PasswordConfirmForm::class => ElementFactory::class,
            Form\ConfigForm::class => Service\Form\ConfigFormFactory::class,
        ],
    ],

    'router' => [
        'routes' => [
            // Step 2 of the login. A top-level route rather than /login/otp:
            // core's "login" route is a Regex (/login(/.*)?) that forces
            // action => login, so anything under /login is unreachable.
            'two-factor' => [
                'type' => Segment::class,
                'options' => [
                    'route' => '/two-factor[/:action]',
                    'constraints' => [
                        'action' => 'otp|recovery|cancel',
                    ],
                    'defaults' => [
                        '__NAMESPACE__' => 'TwoFactorTotp\Controller',
                        'controller' => Controller\OtpController::class,
                        'action' => 'otp',
                    ],
                ],
            ],
            'admin' => [
                'child_routes' => [
                    'two-factor' => [
                        'type' => Segment::class,
                        'options' => [
                            'route' => '/two-factor[/:action]',
                            'constraints' => [
                                'action' => '[a-zA-Z][a-zA-Z0-9_-]*',
                            ],
                            'defaults' => [
                                '__NAMESPACE__' => 'TwoFactorTotp\Controller\Admin',
                                'controller' => Controller\Admin\TotpController::class,
                                'action' => 'setup',
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],

    'view_manager' => [
        'template_path_stack' => [
            dirname(__DIR__) . '/view',
        ],
    ],

    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => dirname(__DIR__) . '/language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],

    'twofactortotp' => [
        'settings' => [
            'twofactortotp_issuer' => '',
            'twofactortotp_required_roles' => [],
            'twofactortotp_remember_device_days' => 14,
            'twofactortotp_window' => 1,
            'twofactortotp_pending_ttl' => 300,
            'twofactortotp_max_attempts' => 5,
        ],
    ],
];

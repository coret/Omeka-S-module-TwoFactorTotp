/**
 * Registering a passkey.
 *
 * The mirror of passkey.js: same base64url plumbing, but navigator.credentials
 * .create() instead of .get(), and the result is stored rather than checked.
 */
(function () {
    'use strict';

    function base64urlToBuffer(value) {
        var base64 = String(value).replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        var binary = window.atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function bufferToBase64(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var root = document.getElementById('totp-passkey-register');
        if (!root) {
            return;
        }

        var button = document.getElementById('totp-passkey-add');
        var status = document.getElementById('totp-passkey-register-status');
        var label = document.getElementById('totp-passkey-label');

        function say(message, isError) {
            status.textContent = message;
            status.className = isError ? 'error' : '';
        }

        if (!window.PublicKeyCredential || !navigator.credentials) {
            button.disabled = true;
            say(root.dataset.unsupported, true);
            return;
        }

        button.addEventListener('click', function () {
            button.disabled = true;
            say(root.dataset.waiting, false);

            fetch(root.dataset.challengeUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error(root.dataset.failed);
                }
                return response.json();
            }).then(function (options) {
                var publicKey = options.publicKey;
                publicKey.challenge = base64urlToBuffer(publicKey.challenge);
                publicKey.user.id = base64urlToBuffer(publicKey.user.id);
                // Already-registered keys are excluded so the authenticator
                // refuses rather than silently making a second credential.
                (publicKey.excludeCredentials || []).forEach(function (credential) {
                    credential.id = base64urlToBuffer(credential.id);
                });
                return navigator.credentials.create({publicKey: publicKey});
            }).then(function (credential) {
                var transports = [];
                if (credential.response.getTransports) {
                    transports = credential.response.getTransports() || [];
                }
                return fetch(root.dataset.verifyUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                        attestationObject: bufferToBase64(credential.response.attestationObject),
                        label: label ? label.value : '',
                        transports: transports
                    })
                });
            }).then(function (response) {
                return response.json().then(function (body) {
                    return {ok: response.ok, body: body};
                });
            }).then(function (result) {
                if (result.ok && result.body.redirect) {
                    window.location.href = result.body.redirect;
                    return;
                }
                button.disabled = false;
                say(
                    result.body && result.body.error === 'already_registered'
                        ? root.dataset.duplicate
                        : root.dataset.failed,
                    true
                );
            }).catch(function (error) {
                button.disabled = false;
                // InvalidStateError is what the browser throws when
                // excludeCredentials matched: this key is already registered.
                if (error && error.name === 'InvalidStateError') {
                    say(root.dataset.duplicate, true);
                    return;
                }
                say(
                    error && error.name === 'NotAllowedError'
                        ? root.dataset.cancelled
                        : root.dataset.failed,
                    true
                );
            });
        });
    });
})();

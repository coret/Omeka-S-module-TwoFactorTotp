/**
 * The browser half of the passkey second step.
 *
 * WebAuthn deals in ArrayBuffers, JSON does not, so everything crossing the
 * wire is base64url and gets converted at the edges. The server hands out
 * options with base64url ids already (the library is constructed with
 * useBase64UrlEncoding), so only the decode direction is needed on the way in.
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
        var root = document.getElementById('totp-passkey');
        if (!root) {
            return;
        }

        var button = document.getElementById('totp-passkey-start');
        var status = document.getElementById('totp-passkey-status');
        var remember = document.getElementById('totp-passkey-remember');

        function say(message, isError) {
            status.textContent = message;
            status.className = isError ? 'error' : '';
        }

        // No WebAuthn at all: say so rather than presenting a button that
        // cannot work. The other ways in are already on the page.
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
                (publicKey.allowCredentials || []).forEach(function (credential) {
                    credential.id = base64urlToBuffer(credential.id);
                });
                return navigator.credentials.get({publicKey: publicKey});
            }).then(function (assertion) {
                return fetch(root.dataset.verifyUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        id: assertion.id,
                        clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
                        authenticatorData: bufferToBase64(assertion.response.authenticatorData),
                        signature: bufferToBase64(assertion.response.signature),
                        remember_device: remember ? remember.checked : false
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
                // Attempts are spent server side, so a failure here has cost
                // the user one and the page must say so.
                if (result.body && result.body.error === 'too_many_attempts') {
                    window.location.href = root.dataset.loginUrl;
                    return;
                }
                button.disabled = false;
                say(root.dataset.failed, true);
            }).catch(function (error) {
                button.disabled = false;
                // A user who cancels the prompt gets the neutral wording; the
                // browser throws the same way for cancel and for no-such-key.
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

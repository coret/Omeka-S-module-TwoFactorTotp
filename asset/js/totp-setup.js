/**
 * Draws the enrollment QR code in the browser.
 *
 * Client-side on purpose: the otpauth:// URI contains the shared secret, so
 * handing it to an external QR service would post the secret off-site.
 */
(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        var target = document.getElementById('totp-qrcode');
        if (!target || typeof qrcode !== 'function') {
            return;
        }

        var uri = target.getAttribute('data-uri');
        if (!uri) {
            return;
        }

        try {
            // Type 0 lets the library pick the smallest version that fits;
            // 'M' tolerates ~15% damage, which is ample on a screen.
            var qr = qrcode(0, 'M');
            qr.addData(uri);
            qr.make();
            target.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 4, scalable: true });
        } catch (e) {
            target.textContent = 'Could not draw the QR code. Use the setup key instead.';
        }
    });
})();

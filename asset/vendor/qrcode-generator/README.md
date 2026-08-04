# qrcode-generator

Vendored third-party library — **do not edit**.

- **Library:** QR Code Generator for JavaScript
- **Author:** Kazuhiko Arase — <http://www.d-project.com/>
- **Version:** 1.4.4 (npm `qrcode-generator`)
- **Source:** <https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js>
- **License:** MIT (see the header of `qrcode.js`)

Kept unminified so it can be read and audited in place.

## Why it is bundled

The enrollment page draws the `otpauth://` QR code in the browser. Rendering it
client-side means the shared secret is never sent to an external QR service,
and it keeps the module free of any server-side image or QR dependency.

Omeka modules are distributed as zips, so the library is vendored here rather
than fetched from a CDN — a CDN would also be an outbound request carrying the
secret in the URL.

## Verification

The bundled copy was checked by encoding a real provisioning URI and decoding
the result with an independent implementation (OpenCV's `QRCodeDetector`); the
decoded string matched the input exactly.

"QR Code" is a registered trademark of DENSO WAVE INCORPORATED.

# TwoFactorTotp (Omeka S module)

Two-factor authentication for Omeka S using **time-based one-time passwords**
(TOTP, [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)) from an
authenticator app — Google Authenticator, Aegis, FreeOTP, 1Password, Bitwarden
or any other TOTP app.

- **Version:** 0.2 — pre-release. Usable, not yet promised stable.
- **Requires:** Omeka S ^4.0.0, PHP 8.1+ — see [Requirements](#requirements)
- **License:** GPL-3.0 (matching Omeka S core)

## Why this module exists

It comes out of a 2023 feature request on the Omeka forum:
[*Two factor authentication [module proposal]*](https://forum.omeka.org/t/two-factor-authentication-module-proposal/19522).
Out of the box Omeka S protects admin accounts with an email/password pair and
nothing else; the [Lockout](https://omeka.org/s/modules/Lockout/) module slows
brute force down but adds no second factor.

There is already a two-factor module for Omeka S —
[**TwoFactorAuth** by Daniel Berthereau](https://gitlab.com/Daniel-KM/Omeka-S-module-TwoFactorAuth)
([omeka.org listing](https://omeka.org/s/modules/TwoFactorAuth/)) — and it is
good work that solves the hard plumbing. This module differs in two ways:

**1. The second factor is TOTP, not an emailed code.**
TwoFactorAuth mails the user a four-digit code; its README still lists "OTP" as
an unimplemented TODO. An emailed code inherits the security of the mailbox,
and mailbox compromise is exactly the scenario two-factor authentication is
supposed to survive. A TOTP secret lives on the phone, never travels, and works
with no mail server and no connectivity at all.

**2. Almost no dependencies.**
No `Common` module, and nothing to keep in step at upgrade time. The RFC
4226/6238 implementation is ~200 lines of `hash_hmac` and base32 in
`src/Service/Totp.php`, pinned to the published RFC test vectors. The only
bundled third-party file is a QR-code renderer (MIT) used **in the browser**, so
the shared secret is never sent to an external QR service.

There is exactly one Composer package, `lbuchs/webauthn`, for the passkey work
described under [TODO](#todo) — chosen partly because it has **no transitive
dependencies of its own**, so it cannot drag conflicting versions of anything
into an Omeka install. See [Dependencies](#dependencies).

The two modules **cannot run side by side** — both replace Omeka's login
controller. Installation aborts with a clear message if TwoFactorAuth is active.

## What it does

- **Per-user opt-in** from a "Two-factor authentication" tab on the user's own
  page: scan a QR code, confirm with a live code, done.
- **Passkeys** (hardware key, Touch ID / Face ID, Windows Hello) as an
  alternative second factor, several per account. **Not** a replacement for the
  password — see below — and see [TODO](#todo): not yet tested against a real
  authenticator.
- **10 single-use recovery codes**, shown once at enrollment, stored hashed.
- **"Remember this device"** for a configurable number of days (default 14,
  `0` disables the feature).
- **Force 2FA for chosen roles** — those users are held on the setup page until
  they enroll.
- **Administrator reset** for a user who has lost both phone and recovery codes.
- English and Dutch interface (`en`, `nl`, `nl_NL`).

## How it is enforced

> **No identity is ever written to the authentication storage until the second
> factor has passed.**

The check lives in an authentication *adapter*
(`src/Authentication/Adapter/SecondFactorAdapter.php`) that wraps Omeka's
`PasswordAdapter`, not in the login controller. Laminas'
`AuthenticationService` writes to storage only when the adapter returns a valid
result, so a password-only login is never a session. Because every login path
goes through the adapter, a login form belonging to another module inherits the
second factor instead of silently bypassing it.

The adapter asks a *registry* (`src/Service/SecondFactorRegistry.php`) whether
the user owes a second step, rather than asking any particular factor. That is
the difference between "does this account have a second factor" and "does this
account have TOTP" — and the second question fails open, waving through anyone
enrolled in something the adapter had not been told about.

API-key requests (`KeyAdapter`) are deliberately left alone — there is no human
present to type a code, and wrapping them would break every API client.

### Passkeys here are a second factor, not a passwordless login

There is **no passkey button on the login page**, and that is deliberate rather
than unfinished. The order is: email and password first, *then* the passkey
instead of a code. At the point the login form is submitted the module does not
yet know who you are, so it has nothing to scope a credential request to.

The other arrangement — a button on `/login` that logs you in with no password
at all — is a real and reasonable design, and a common one. It is not this one.
It would make the passkey the *only* thing between an attacker and the account,
so an unlocked device becomes a full compromise where here it still leaves the
password. Passkeys are registered without requiring a discoverable credential
(`requireResidentKey = false`) precisely because that flow is not offered.

Adding passwordless login later would mean re-registering existing passkeys.

Other things worth knowing:

- A TOTP code is **single-use**: the highest counter already spent is persisted
  and anything at or below it is refused, so a code observed over someone's
  shoulder is not reusable for the rest of its 30-second step.
- The trusted-device cookie is a split `selector:validator` token; only a
  SHA-256 of the validator is stored, and it is **rotated on every use**.
- Changing an account's password revokes all of its trusted devices.
- The pending login between the two steps holds a user id — never the password —
  expires after 5 minutes, and is destroyed after 5 wrong codes.

## Requirements

| | |
|---|---|
| **Omeka S** | `^4.0.0` (enforced by `module.ini`). Verified against 4.2.1. |
| **PHP** | 8.1 or newer. Verified on 8.4 and 8.5. |
| **PHP extensions** | `hash`, `json`, `mbstring`, `openssl`. |
| **Composer** | One package; run `composer install --no-dev` (see [Dependencies](#dependencies)). |
| **Database** | MySQL 5.7+ / MariaDB 10.2+ — recovery codes live in a `json` column. |
| **Server clock** | Synchronised (NTP). TOTP is time-based; see the note below. |
| **Sessions & cookies** | Used for the pending login between the two steps and for trusted devices. |

`hash` and `json` are compiled in on any normal PHP build; **`mbstring` is the one
worth checking**, as it is genuinely optional in some distributions. Omeka S
already requires all three, so a working Omeka is a working environment for this.
`openssl` is needed only by the passkey work and is present on essentially every
PHP install.

**Passkeys additionally require the site to be served over HTTPS** — WebAuthn
refuses to run on plain HTTP (bar `localhost`). TOTP has no such requirement.

JavaScript draws the QR code and runs the passkey ceremony. Without it TOTP
still works — the setup page shows the secret as text for manual entry — but
passkeys cannot work at all, and the pages say so rather than offering a button
that would fail.

## Dependencies

**One Composer package**, and no `Common` module.

| Package | Version | Licence | Why |
|---|---|---|---|
| [`lbuchs/webauthn`](https://github.com/lbuchs/WebAuthn) | `^2.2` | MIT | Passkey registration and verification. |

It was picked over the more widely known `web-auth/webauthn-lib` specifically
because it has **zero transitive dependencies**. That matters more than it
sounds: Omeka loads a module's Composer autoloader *prepended*, so any package a
module bundles shadows Omeka's own copy for the whole application. The
alternative allows `psr/log ^1|^2|^3` and would therefore install 3.x, whose
`LoggerInterface` is typed, over the untyped 1.x that Omeka S 4.2 ships and its
`PsrLoggerAdapter` is built against — breaking logging site-wide.

Install it with:

```sh
composer install --no-dev
```

`vendor/` is deliberately **not** committed. The module is written to boot
without it: the autoloader is loaded only `if (file_exists(...))`, because this
module replaces the login controller and a fatal there would lock everyone out.
Until `composer install` has run, passkey features are simply unavailable and
say so — TOTP, recovery codes and login are unaffected. An account that already
holds a passkey still counts as needing a second factor in that state, so it is
held at the second step rather than admitted on its password; its recovery codes
still work.

The RFC 4226/6238 implementation is about 200 lines of `hash_hmac` and base32 in
`src/Service/Totp.php`, pinned to the published RFC test vectors, and needs
nothing from Composer.

*Bundled* third-party code — one file, already included, nothing to fetch:

| File | Version | Licence | Why |
|---|---|---|---|
| `asset/vendor/qrcode-generator/qrcode.js` | 1.4.4 | MIT (Kazuhiko Arase) | Draws the QR code **in the browser**, so the shared secret is never sent to an external QR-code service. |

Kept unminified so it can be audited in place — see
`asset/vendor/qrcode-generator/README.md` for its provenance.

From Omeka S core the module uses the password authentication adapter, the
entity manager, settings, the logger, the mailer and `ConfirmForm` — all part of
a standard install.

### Conflicts

**[TwoFactorAuth](https://gitlab.com/Daniel-KM/Omeka-S-module-TwoFactorAuth)
cannot be active at the same time.** Both modules replace the login controller,
so installation aborts with a clear message if TwoFactorAuth is enabled. Disable
it first.

## Installation

1. Copy the `TwoFactorTotp` directory into `modules/`. If you are installing from
   a git checkout rather than a release zip, run `composer install --no-dev`
   inside it — `vendor/` is not committed.
2. Install it from **Admin → Modules**. This creates the four tables it needs —
   `two_factor_totp_enrollment`, `two_factor_totp_trusted_device`,
   `two_factor_totp_recovery_code` and `two_factor_totp_webauthn_credential` —
   and writes the default settings. Uninstalling drops all four and removes the
   settings.

   Upgrading from 0.1 adds the last two and moves existing recovery codes into
   `two_factor_totp_recovery_code`. The codes themselves do not change, so any
   you have already written down keep working.
3. Optionally configure it (**Modules → TwoFactorTotp → Configure**).
4. Each user enables it for themselves from their own user page.

### Settings

| Setting | Default | |
|---|---|---|
| Issuer name | installation title | Shown next to the account in the app. |
| Passkey domain | site's host | The domain passkeys are bound to. Changing it invalidates every registered passkey. |
| Required roles | none | Roles that must use 2FA. |
| Remember a device for (days) | 14 | `0` removes the option entirely. |
| Accepted time steps either side | 1 | Clock-drift tolerance, in 30s steps. |
| Time allowed to enter the code | 300 s | Lifetime of a pending login. |
| Wrong codes allowed per login | 5 | Then back to the password screen. |

## If you get locked out

In order of preference:

1. **Use a recovery code** — the link is on the code screen.
2. **Ask another administrator** to reset it from your user page
   (*Reset two-factor authentication*). You will be emailed, and it is logged.
3. **Last resort, direct SQL** — for when the only administrator has locked
   themselves out:

   ```sql
   DELETE FROM two_factor_totp_enrollment
    WHERE user_id = (SELECT id FROM user WHERE email = 'you@example.org');
   DELETE FROM two_factor_totp_webauthn_credential
    WHERE user_id = (SELECT id FROM user WHERE email = 'you@example.org');
   ```

   That account then logs in with its password alone. Removing every factor is
   what matters; leftover rows in `two_factor_totp_recovery_code` are harmless,
   since a recovery code is only ever offered when a second factor is owed, and
   enrolling again replaces the whole set.

4. **Turn the whole module off from the database.** The nuclear option, for the
   case where the module itself is what is broken — it replaces the login
   controller, so a fatal error there means *nobody* can log in, including the
   administrator who would normally disable it:

   ```sql
   UPDATE module SET is_active = 0 WHERE id = 'TwoFactorTotp';
   ```

   Omeka then stops loading the module's config entirely and the stock login
   form comes back. Enrollments and trusted devices are left untouched, so
   re-activating restores everyone's second factor exactly as it was.

   The module deliberately fails **closed**: if its tables are missing or the
   database errors mid-login, you get an error rather than a login that skips
   the second factor. That is the safe direction for security and the
   inconvenient one for you, which is why this hatch exists.

### "Every code is rejected"

Almost always server clock drift. The module's configuration page shows the
server's own time — if it is more than ~30 seconds out, fix NTP rather than
raising the tolerance setting.

## Development

Three layers, cheapest first. The crypto is the easy part to get right; the
wiring is where the bugs live, so the last two matter more than they look.

```sh
# 0. Dependencies (once). vendor/ is not committed.
composer install --no-dev

# 1. Unit — RFC 4226 / RFC 6238 vectors, plus service-wiring regressions.
#    OMEKA_VENDOR is only needed when the module is not sitting in modules/;
#    the wiring tests skip themselves without it.
../../vendor/bin/phpunit
OMEKA_VENDOR=/path/to/omeka-s/vendor ../../vendor/bin/phpunit

# 2. Static — config, DI, entity mapping, routes, templates, assets, and the
#    contract that every variable a template reads is one its action sets.
php test/verify-wiring.php

# 3. End-to-end — real HTTP against a running site. The only layer that
#    dispatches requests, and the only one that catches render-time faults.
#    Needs a throwaway account; see the header of the file.
omeka-s-cli user:add e2e@example.com 'E2E' editor 'the-password'
TOTP_E2E_URL=https://example.org/omeka \
TOTP_E2E_EMAIL=e2e@example.com \
TOTP_E2E_PASSWORD=the-password \
php test/e2e.php
omeka-s-cli user:delete e2e@example.com
```

Point `test/e2e.php` at a throwaway account only — it enrolls, resets and logs
in as that user.

Translations are generated — see `language/README.md`.

## TODO

- **WebAuthn / passkeys** as a second factor (hardware keys, Touch ID / Face ID,
  Windows Hello) — **feature-complete on the `passkeys` branch, awaiting
  testing against real authenticators.** Phishing-resistant
  in a way TOTP is not: a TOTP code can still be relayed through a proxy in real
  time, whereas a passkey is bound to the origin. An *additional* factor type
  alongside TOTP, not a replacement — TOTP needs no special hardware and works on
  any phone.

  Done so far: the dependency (`lbuchs/webauthn`), the credential table,
  recovery codes moved off the TOTP enrollment onto the user — so an account
  whose only factor is a passkey will still have a way back in — the factor
  registry, the passkey manager, challenge store and factor, and both halves of
  the ceremony: registering a passkey from the user page, and presenting one at
  the second step. Settings gained a **Passkey domain**.

  **Not yet exercised against a real authenticator.** The end-to-end tests cover
  the server contract — both endpoints refuse a request with no pending login,
  a challenge is refused for an account holding no credential, and verify is
  refused with no outstanding challenge — but `curl` cannot produce a signature,
  so the ceremony itself needs a hardware key, a platform authenticator, or a
  virtual one driven over the Chrome DevTools protocol. Treat it as untested
  until that has been done.

  One design note worth keeping: a user holding a passkey counts as enrolled
  even when the WebAuthn library is missing. Reporting otherwise would let them
  log in on their password alone, so the module holds them at the second step
  and says what is wrong. Their recovery codes still work.
- Publish to [omeka.org/s/modules](https://omeka.org/s/modules/) and reply on
  the forum thread.
- Optional encryption of the stored secret, keyed from
  `config/local.config.php`, so a database dump alone yields nothing usable.
- Per-site (non-admin) two-factor authentication, for use with the Guest module.

Out of scope: SMS (weaker than both alternatives), and integration with
CAS / LDAP / Single Sign-On — those systems own their own second factor.

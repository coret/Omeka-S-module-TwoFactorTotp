# TwoFactorTotp (Omeka S module)

Two-factor authentication for Omeka S using **time-based one-time passwords**
(TOTP, [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)) from an
authenticator app — Google Authenticator, Aegis, FreeOTP, 1Password, Bitwarden
or any other TOTP app.

- **Version:** 1.0.0 — stable. Breaking changes will mean a new major version.
- **Requires:** Omeka S ^4.0.0, PHP 8.1+ — see [Requirements](#requirements)
- **License:** GPL-3.0-or-later (Omeka S core is GPL-3.0)

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

There is exactly one Composer package, `lbuchs/webauthn`, which provides the
passkey support — chosen partly because it has **no transitive dependencies of
its own**, so it cannot drag conflicting versions of anything into an Omeka
install. See [Dependencies](#dependencies).

The two modules **cannot run side by side** — both replace Omeka's login
controller. Installation aborts with a clear message if TwoFactorAuth is active.

## What it does

- **Per-user opt-in** from a "Two-factor authentication" tab on the user's own
  page: scan a QR code, confirm with a live code, done.
- **Passkeys** (hardware key, Touch ID / Face ID, Windows Hello) as an
  alternative second factor, several per account. **Not** a replacement for the
  password — see below.
- **10 single-use recovery codes**, shown once at enrollment, stored hashed.
- **Account-wide lockout** after repeated wrong codes, with exponential backoff.
  Recovery codes are exempt, so it is never a dead end.
- **Optional encryption of the TOTP secret at rest**, keyed from
  `local.config.php` rather than from the database.
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

### Guessing is bounded per account, not per login

There are two limits, and only the second one actually bounds an attacker.

The **per-login** limit (*Wrong codes allowed per login*, default 5) throws the
pending login away and sends the user back to the password screen. On its own
that bounds a sitting rather than an account: a new pending login is one
password submission away, so somebody who already holds the password can spend
the budget, re-post the login form, and get another one. With a window of 1
there are three valid codes out of a million at any moment, which at a modest
request rate is a couple of hours' work.

So there is also a **per-account** limit (*Failed attempts before the account is
locked*, default 10). It is kept in user settings, survives new logins, and
locks the second step for a while — 15 minutes by default, doubling with each
further lockout on the same account, capped at a day. A correct code, passkey
or recovery code clears it.

Recovery codes are deliberately **not** subject to it. Ten characters from a
32-character alphabet leaves nothing to brute-force, and exempting them means
the lockout can never leave somebody with no way into their own account.

### The TOTP secret can be encrypted at rest

Optional, off unless you configure a key, and worth doing. Everything else the
module stores is already protected — recovery codes are hashed, device
validators are digested, only public keys are kept for passkeys — but the TOTP
secret has to be recoverable, because the server computes HMACs with it. Read
access to the database alone is therefore a permanent second-factor bypass for
every enrolled account.

Add a key to Omeka's `config/local.config.php` — **not** to a module setting,
which would sit in the same database as the secrets it is meant to protect:

```php
'twofactortotp' => [
    'encryption_key' => 'a long random string, e.g. from `openssl rand -base64 48`',
],
```

Secrets are then stored AES-256-GCM encrypted. Existing enrollments are
converted when the module upgrades, and any that are missed — because the key
was added later — convert themselves the next time their owner logs in, so you
can turn this on at any point without locking anybody out.

There is deliberately **no default key**. One shipped in the source would be
known to anyone who can read the repository, so it would turn "stored in clear,
and an audit will say so" into "looks protected, is not" — which is worse,
because it silences the check that would otherwise notice. The module's
configuration page tells you which state you are in.

**Changing the key later.** Keep the old one while the change works through:

```php
'twofactortotp' => [
    'encryption_key' => 'the new key',
    'previous_encryption_keys' => ['the key it replaces'],
],
```

Retired keys are only ever used to read. A secret still under one is rewritten
under the current key the next time its owner logs in, so a rotation completes
by itself; once everybody has been through, drop `previous_encryption_keys`. If
you have accounts that never log in, `disable`/re-enroll is the only other way
to move them.

**Keep at least one key that each row was written under.** Lose them all and
those secrets are unreadable, and the module says so loudly rather than quietly
rejecting every code: you get an error naming the setting, which is the
difference between a five-minute fix and a day of guessing. Recovery codes are
unaffected either way, and the "If you get locked out" recipes below still
work.

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

Managing passkeys asks for the account password first, and the confirmation
lasts five minutes. Turning TOTP off and reissuing recovery codes already did;
adding a passkey is the same kind of change, and arguably a worse one to leave
open, because a passkey an attacker plants on a hijacked session survives the
victim changing their password.

Also out of scope: SMS, which is weaker than either factor offered here, and
integration with CAS, LDAP or Single Sign-On — those systems own their own
second factor.

Why offer passkeys at all when TOTP already works: a TOTP code can be relayed
through a proxy in real time, whereas a passkey is bound to the origin and
cannot be. TOTP stays because it needs no special hardware and works on any
phone — the two sit alongside each other, and an account may hold either or
both.

One thing to know when reading `two_factor_totp_webauthn_credential`: a
`sign_count` that stays at zero is normal. Plenty of platform authenticators
never increment it, so only a counter going *backwards* is treated as a
possible cloning signal.

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

   Upgrading to 0.3 widens `two_factor_totp_enrollment.secret` to make room for
   the encrypted form, and encrypts what is already stored if you have
   configured a key. Both steps are safe to run twice and neither loses data. If
   you have not configured a key, nothing about how secrets are stored changes.
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
| Wrong codes allowed per login | 5 | Then back to the password screen. Per sitting. |
| Failed attempts before the account is locked | 10 | Per account, and the limit that actually bounds guessing. `0` turns it off. |
| How long the account stays locked | 900 s | Doubles with each further lockout, capped at a day. |

The TOTP encryption key is deliberately **not** here — it goes in Omeka's
`config/local.config.php`; see [above](#the-totp-secret-can-be-encrypted-at-rest).

## If you get locked out

In order of preference:

0. **Wait, if the account is locked.** Repeated wrong codes lock the second step
   for a while; the message says how long. A recovery code works throughout —
   the lockout deliberately does not apply to it.

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

   To clear a lockout by hand instead of waiting it out:

   ```sql
   DELETE FROM user_setting
    WHERE id LIKE 'twofactortotp_factor_%'
      AND user_id = (SELECT id FROM user WHERE email = 'you@example.org');
   ```

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

Code style is [Omeka S's own](https://omeka.org/s/docs/developer/contributing/):
PSR-2 plus their extras. `.php-cs-fixer.dist.php` is Omeka's `.php_cs_module`
copied verbatim, so it stays in step with upstream — including that it defines
no `->in()`, which is why the path is given on the command line:

```sh
php-cs-fixer fix .            # or --dry-run --diff to see what it would change
```

The test suite is three layers, cheapest first: PHPUnit over the RFC 4226 / RFC 6238
vectors, a static check of config, DI, entity mapping, routes and templates,
and an end-to-end pass that dispatches real HTTP against a running site. The
crypto is the easy part to get right; the wiring is where the bugs live, so the
last two matter more than they look. `test/README.md` has the commands.

Tests and the translation build scripts are tracked in git but kept out of the
*published module*, by `export-ignore` in `.gitattributes` and by the prune step
in the release script. That is the right place for the distinction: a released
zip has no business carrying them, and neither has a repository any business
being the only copy of them.

Translations are generated — see `language/README.md`.

## License

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either **version 3 of the License, or (at your option) any later
version**.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details — the full text is
in [`LICENSE`](LICENSE).

GPL-3.0 matches Omeka S itself, which this module is a part of at runtime. The
two bundled third-party components stay under their own terms, both MIT and both
compatible with the above: [`lbuchs/webauthn`](https://github.com/lbuchs/WebAuthn)
and the QR-code renderer in `asset/vendor/qrcode-generator/` — see
[Dependencies](#dependencies).

Note that GitHub reports this repository as "GNU General Public License v3.0".
That is expected: the licence *text* is identical for the version-3-only and
or-later variants, so file-based detection cannot tell them apart, and GitHub has
no or-later identifier. The grant above is what applies.

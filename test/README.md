# Working-tree tooling

Tracked, but not published. `/test/` and `phpunit.xml.dist` are in git — they
are the evidence the module works, and a repository that does not hold them is
one `rm -rf` away from not having them at all. They are kept out of the
*released module* instead, by `export-ignore` in `.gitattributes` and by the
prune step in `release.sh`, which then asserts the archive contains no `test/`.

The commands below used to sit in the module's `README.md` and
`language/README.md`; they live here because they are of no use to somebody who
has installed the module rather than checked it out.

## Tests

Three layers, cheapest first. The crypto is the easy part to get right; the
wiring is where the bugs live, so the last two matter more than they look.

```sh
cd modules/TwoFactorTotp

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

## Translations

The `.po` files under `language/` are **generated** — edit
`test/build-translations.php`, not the catalogues, or your changes will be
overwritten. See `language/README.md` for what each catalogue is and for the
concatenation caveat when adding strings.

```sh
cd modules/TwoFactorTotp

# 1. Extract. Two extractors are needed: Omeka's own tool reads the
#    'string', // @translate idiom, and ours reads $translate('…') calls.
#    (xgettext is not used: its PHP lexer trips over .phtml.)
mkdir -p /tmp/tfa && cp Module.php /tmp/tfa/ && cp -r src/* /tmp/tfa/
php ../../vendor/bin/extract-tagged-strings.php /tmp/tfa > /tmp/tagged.pot
php test/extract-strings.php view src Module.php > /tmp/calls.pot
msgcat --no-wrap --use-first -o language/template.pot /tmp/tagged.pot /tmp/calls.pot

# 2. Translate. This fails loudly and exits non-zero if any string is missing
#    from the map, or if the map has entries no longer in the code.
php test/build-translations.php

# 3. Compile.
for f in language/*.po; do msgfmt --check -o "${f%.po}.mo" "$f"; done
```

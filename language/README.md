# Translations

Shipped catalogues:

| File | Locale | Notes |
|---|---|---|
| `template.pot` | — | Extracted source strings (129). |
| `en.po` / `en.mo` | `en` | Identity catalogue. English is the source language, but an explicit `en` locale then resolves instead of falling through to the raw msgid. |
| `nl_NL.po` / `nl_NL.mo` | `nl_NL` | Dutch. Matches the filename Omeka core uses (`application/language/nl_NL.po`). |
| `nl.po` / `nl.mo` | `nl` | Same Dutch content, so a plain `nl` locale resolves too. |

Register and terminology follow Omeka S's own Dutch catalogue: informal *je*,
*Wachtwoord*, *Gebruikers*, *Annuleer*.

## Regenerating after changing a string

The `.po` files are **generated** — edit `test/build-translations.php`, not the
catalogues, or your changes will be overwritten.

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

## A caveat when adding strings

Neither extractor can follow string **concatenation**, so write translatable
text as a single literal:

```php
// Not extractable:
'One long sentence, '
. 'split across lines.' // @translate

// Extractable:
'One long sentence, split across lines.' // @translate
```

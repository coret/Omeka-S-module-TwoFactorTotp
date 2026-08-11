# Translations

Shipped catalogues:

| File | Locale | Notes |
|---|---|---|
| `template.pot` | — | Extracted source strings (135). |
| `en.po` / `en.mo` | `en` | Identity catalogue. English is the source language, but an explicit `en` locale then resolves instead of falling through to the raw msgid. |
| `nl_NL.po` / `nl_NL.mo` | `nl_NL` | Dutch. Matches the filename Omeka core uses (`application/language/nl_NL.po`). |
| `nl.po` / `nl.mo` | `nl` | Same Dutch content, so a plain `nl` locale resolves too. |

Register and terminology follow Omeka S's own Dutch catalogue: informal *je*,
*Wachtwoord*, *Gebruikers*, *Annuleer*.

## Regenerating after changing a string

The `.po` files are **generated** — edit the string map in the build script,
not the catalogues, or your changes will be overwritten.

Two extractors are needed: Omeka's own tool reads the `'string', // @translate`
idiom, and ours reads `$translate('…')` calls. (xgettext is not used: its PHP
lexer trips over `.phtml`.) The build then fails loudly and exits non-zero if
any string is missing from the map, or if the map has entries no longer in the
code, and `msgfmt --check` compiles the result.

Both extractors and the build script live in the module's working tree and are
not published with the module; the recipe is in the working tree's
`test/README.md`.

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

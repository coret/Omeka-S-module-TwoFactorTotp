<?php declare(strict_types=1);

/**
 * Extract $translate(…) strings from the module's views and PHP sources.
 *
 * Omeka's own extract-tagged-strings tool only understands the
 * `'string', // @translate` idiom used in PHP source; the views instead call
 * $translate('…') / $this->translate('…'). xgettext's PHP lexer trips over
 * .phtml, so this walks the token stream directly.
 *
 * Usage: php test/extract-strings.php [dir|file ...] > strings.pot
 *        (defaults to view/ and src/)
 */
$moduleDir = dirname(__DIR__);
$targets = array_slice($argv, 1) ?: [$moduleDir . '/view', $moduleDir . '/src'];

$strings = [];
$paths = [];

foreach ($targets as $target) {
    if (is_file($target)) {
        $paths[] = $target;
        continue;
    }
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($target));
    foreach ($files as $file) {
        if ($file->isFile() && in_array($file->getExtension(), ['phtml', 'php'], true)) {
            $paths[] = $file->getPathname();
        }
    }
}
$paths = array_unique($paths);
sort($paths);

foreach ($paths as $path) {
    $tokens = token_get_all((string) file_get_contents($path));
    $count = count($tokens);

    for ($i = 0; $i < $count; $i++) {
        $token = $tokens[$i];
        if (!is_array($token)) {
            continue;
        }

        // Match a call to something named "translate": either $translate(…)
        // or $this->translate(…).
        $isTranslateCall = false;
        if (T_VARIABLE === $token[0] && '$translate' === $token[1]) {
            $isTranslateCall = true;
        } elseif (T_STRING === $token[0] && 'translate' === $token[1]) {
            // Only when reached through -> (a method call), not a bare word.
            for ($back = $i - 1; $back >= 0; $back--) {
                $prev = $tokens[$back];
                if (is_array($prev) && T_WHITESPACE === $prev[0]) {
                    continue;
                }
                $isTranslateCall = is_array($prev) && T_OBJECT_OPERATOR === $prev[0];
                break;
            }
        }

        if (!$isTranslateCall) {
            continue;
        }

        // Next non-whitespace token must be "(", then a single quoted string.
        $j = $i + 1;
        while ($j < $count && is_array($tokens[$j]) && T_WHITESPACE === $tokens[$j][0]) {
            $j++;
        }
        if ($j >= $count || '(' !== $tokens[$j]) {
            continue;
        }
        $j++;
        while ($j < $count && is_array($tokens[$j]) && T_WHITESPACE === $tokens[$j][0]) {
            $j++;
        }
        if ($j >= $count || !is_array($tokens[$j]) || T_CONSTANT_ENCAPSED_STRING !== $tokens[$j][0]) {
            continue;
        }

        $raw = $tokens[$j][1];
        $quote = $raw[0];
        $value = substr($raw, 1, -1);
        // Undo PHP's escaping so the .po holds the literal text.
        $value = "'" === $quote
            ? str_replace(['\\\\', "\\'"], ['\\', "'"], $value)
            : stripcslashes($value);

        if ('' === trim($value)) {
            continue;
        }

        $relative = ltrim(str_replace($moduleDir, '', $path), '/');
        $strings[$value][] = $relative . ':' . $tokens[$j][2];
    }
}

ksort($strings);

echo "#, fuzzy\n";
echo "msgid \"\"\n";
echo "msgstr \"\"\n";
echo "\"MIME-Version: 1.0\\n\"\n";
echo "\"Content-Type: text/plain; charset=UTF-8\\n\"\n";
echo "\"Content-Transfer-Encoding: 8bit\\n\"\n\n";

foreach ($strings as $value => $references) {
    foreach (array_unique($references) as $reference) {
        echo "#: $reference\n";
    }
    if (false !== strpos($value, '%')) {
        echo "#, php-format\n";
    }
    printf("msgid \"%s\"\n", addcslashes($value, "\"\\\n\t"));
    echo "msgstr \"\"\n\n";
}

fwrite(STDERR, sprintf("Extracted %d unique strings from %d view files.\n", count($strings), count($paths)));

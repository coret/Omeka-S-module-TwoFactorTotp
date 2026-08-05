<?php declare(strict_types=1);

/**
 * Build language/*.po from language/template.pot.
 *
 * Driven by the $translations map below rather than by hand-editing .po files,
 * so a string added to the code but not to the map is a hard error instead of
 * a silently untranslated label.
 *
 * Usage:
 *   php test/build-translations.php        # writes .po files, then run msgfmt
 */

$moduleDir = dirname(__DIR__);
$potFile = $moduleDir . '/language/template.pot';

if (!is_readable($potFile)) {
    fwrite(STDERR, "Missing $potFile — regenerate it first (see language/README.md).\n");
    exit(1);
}

/**
 * Dutch. Register and terminology follow Omeka S's own nl_NL catalogue
 * (application/language/nl_NL.po): informal "je", "Inloggen", "Wachtwoord".
 */
$nl = [
    '1. Install an authenticator app' => '1. Installeer een authenticator-app',
    '2. Scan this code' => '2. Scan deze code',
    '3. Confirm' => '3. Bevestig',
    'Accepted time steps either side' => 'Toegestane tijdstappen aan weerszijden',
    'Add a second step to your login using an authenticator app on your phone, so a stolen password is not enough on its own.' => 'Voeg een tweede stap toe aan je login met een authenticator-app op je telefoon, zodat een gestolen wachtwoord op zichzelf niet genoeg is.',
    'Added' => 'Toegevoegd',
    'After this many wrong codes the login is discarded and the user starts again from the password screen.' => 'Na dit aantal foute codes wordt de login weggegooid en begint de gebruiker opnieuw bij het wachtwoordscherm.',
    'An administrator has reset two-factor authentication on your account. You can log in with your password alone until you set it up again. If you did not expect this, contact your administrator immediately.' => 'Een beheerder heeft tweefactorauthenticatie op je account gereset. Je kunt met alleen je wachtwoord inloggen totdat je het opnieuw instelt. Als je dit niet verwachtte, neem dan onmiddellijk contact op met je beheerder.',
    'Any TOTP app works — for example Google Authenticator, Aegis, FreeOTP, 1Password or Bitwarden.' => 'Elke TOTP-app werkt — bijvoorbeeld Google Authenticator, Aegis, FreeOTP, 1Password of Bitwarden.',
    'Authentication code' => 'Authenticatiecode',
    'Back to the code from my app' => 'Terug naar de code uit mijn app',
    'Cancel' => 'Annuleer',
    'Can’t scan? Enter this key by hand' => 'Kun je niet scannen? Voer deze sleutel handmatig in',
    'Code from your app' => 'Code uit je app',
    'Confirm' => 'Bevestigen',
    'Confirm with your password to continue.' => 'Bevestig met je wachtwoord om door te gaan.',
    'Copied' => 'Gekopieerd',
    'Copy to clipboard' => 'Kopieer naar klembord',
    'Device' => 'Apparaat',
    'Device revoked.' => 'Apparaat ingetrokken.',
    'Disable two-factor authentication' => 'Tweefactorauthenticatie uitschakelen',
    '%d recovery codes remaining.' => 'Nog %d herstelcodes.',
    '%d trusted devices.' => '%d vertrouwde apparaten.',
    'Email or password is invalid' => 'E-mailadres of wachtwoord is ongeldig',
    'Enable two-factor authentication' => 'Tweefactorauthenticatie inschakelen',
    'Enter one of the recovery codes you saved when you set up two-factor authentication. Each code works only once.' => 'Voer een van de herstelcodes in die je hebt opgeslagen toen je tweefactorauthenticatie instelde. Elke code werkt maar één keer.',
    'Enter the 6-digit code from your authenticator app to finish logging in.' => 'Voer de 6-cijferige code uit je authenticator-app in om het inloggen af te ronden.',
    'Enter the 6-digit code your authenticator app shows now.' => 'Voer de 6-cijferige code in die je authenticator-app nu toont.',
    'Enter the code your app shows now. This proves the app was set up correctly before it becomes required to log in.' => 'Voer de code in die je app nu toont. Zo staat vast dat de app goed is ingesteld, voordat hij nodig is om in te loggen.',
    'Generate new recovery codes' => 'Nieuwe herstelcodes genereren',
    'How long a device stays trusted after the user ticks "remember this device". Set to 0 to remove the option entirely.' => 'Hoe lang een apparaat vertrouwd blijft nadat de gebruiker "dit apparaat onthouden" aanvinkt. Zet op 0 om de optie helemaal te verwijderen.',
    'How long a password-verified login may wait at the code screen before it is discarded.' => 'Hoe lang een met wachtwoord geverifieerde login bij het codescherm mag wachten voordat hij wordt weggegooid.',
    'How much clock drift between server and phone to tolerate, in 30-second steps. 1 is the usual value; raising it widens the window in which a code stays valid.' => 'Hoeveel klokverschil tussen server en telefoon wordt getolereerd, in stappen van 30 seconden. 1 is de gebruikelijke waarde; verhogen vergroot het venster waarin een code geldig blijft.',
    'I have saved my recovery codes' => 'Ik heb mijn herstelcodes opgeslagen',
    'Invalid code. %d attempts remaining.' => 'Ongeldige code. Nog %d pogingen over.',
    'Invalid or missing CSRF token' => 'Ongeldig of ontbrekend CSRF-token',
    'Issuer name' => 'Naam van de uitgever',
    'It is required for your role — you will be asked to set it up on your next request.' => 'Het is verplicht voor jouw rol — bij je volgende verzoek wordt gevraagd het in te stellen.',
    'JavaScript is required to draw the QR code. Use the setup key below instead.' => 'JavaScript is nodig om de QR-code te tekenen. Gebruik in plaats daarvan de sleutel hieronder.',
    'Last used' => 'Laatst gebruikt',
    'Manage trusted devices' => 'Vertrouwde apparaten beheren',
    'New recovery codes generated. Your previous codes no longer work.' => 'Nieuwe herstelcodes gegenereerd. Je vorige codes werken niet meer.',
    'No trusted devices.' => 'Geen vertrouwde apparaten.',
    'One of the codes you saved when you set up two-factor authentication. Each code works once.' => 'Een van de codes die je hebt opgeslagen toen je tweefactorauthenticatie instelde. Elke code werkt één keer.',
    'Only %d recovery codes left. Generate a new set so you are not locked out if you lose your phone.' => 'Nog maar %d herstelcodes over. Genereer een nieuwe set zodat je niet buitengesloten raakt als je je telefoon kwijtraakt.',
    'Only the account holder can set this up — nobody else can see or change their secret.' => 'Alleen de accounthouder kan dit instellen — niemand anders kan die sleutel zien of wijzigen.',
    'Only tick this on a device that is yours alone.' => 'Vink dit alleen aan op een apparaat dat alleen van jou is.',
    'Print' => 'Afdrukken',
    'QR code for setting up two-factor authentication' => 'QR-code om tweefactorauthenticatie in te stellen',
    'Recovery code' => 'Herstelcode',
    'Recovery code accepted. You have %d left.' => 'Herstelcode geaccepteerd. Je hebt er nog %d.',
    'Remember a device for (days)' => 'Een apparaat onthouden gedurende (dagen)',
    'Remember this device for %d days' => 'Dit apparaat %d dagen onthouden',
    'Require two-factor authentication for these roles' => 'Tweefactorauthenticatie verplichten voor deze rollen',
    'Reset two-factor authentication' => 'Tweefactorauthenticatie resetten',
    'Revoke' => 'Intrekken',
    'Revoke all devices' => 'Alle apparaten intrekken',
    'Revoked %d devices.' => '%d apparaten ingetrokken.',
    '%s does not have two-factor authentication enabled. There is nothing to reset.' => 'Bij %s is tweefactorauthenticatie niet ingeschakeld. Er is niets te resetten.',
    'Server time is %s. If this is more than about half a minute away from real time, every code will be rejected — check that NTP is running.' => 'De servertijd is %s. Wijkt dit meer dan ongeveer een halve minuut af van de echte tijd, dan wordt elke code geweigerd — controleer of NTP draait.',
    'Set up two-factor authentication' => 'Tweefactorauthenticatie instellen',
    '[%s] Two-factor authentication was reset' => '[%s] Tweefactorauthenticatie is gereset',
    'Successfully logged in' => 'Succesvol ingelogd',
    'That code was not correct. Check your app and try again.' => 'Die code was niet juist. Controleer je app en probeer het opnieuw.',
    'The 6-digit code from your authenticator app.' => 'De 6-cijferige code uit je authenticator-app.',
    'The name shown next to the account in the authenticator app. Leave empty to use the installation title.' => 'De naam die naast het account in de authenticator-app wordt getoond. Laat leeg om de titel van de installatie te gebruiken.',
    'The password entered was invalid.' => 'Het ingevoerde wachtwoord was ongeldig.',
    'These browsers skip the code screen until their trust expires. Revoke any you no longer use or recognise.' => 'Deze browsers slaan het codescherm over totdat hun vertrouwen verloopt. Trek de apparaten in die je niet meer gebruikt of herkent.',
    'These codes are shown once and cannot be retrieved again. Save them somewhere safe and away from the device running your authenticator app — they are the only way back in if you lose your phone.' => 'Deze codes worden één keer getoond en kunnen daarna niet meer worden opgehaald. Bewaar ze op een veilige plek, los van het apparaat waarop je authenticator-app draait — ze zijn de enige manier om weer binnen te komen als je je telefoon kwijtraakt.',
    'The TwoFactorAuth module is active. Both modules replace the login controller, so they cannot run together. Disable TwoFactorAuth first.' => 'De module TwoFactorAuth is actief. Beide modules vervangen de logincontroller, dus ze kunnen niet samen draaien. Schakel eerst TwoFactorAuth uit.',
    '(this browser)' => '(deze browser)',
    'This removes the second factor from another person’s account. Only do this when you are certain who you are talking to — anyone who can pass this check can take the account over with the password alone.' => 'Hiermee verwijder je de tweede factor van het account van iemand anders. Doe dit alleen als je zeker weet met wie je spreekt — wie deze controle passeert, kan het account met alleen het wachtwoord overnemen.',
    'This removes the second factor from your account, deletes your recovery codes, and signs out every device you had marked as trusted. Your account will be protected by its password alone.' => 'Hiermee verwijder je de tweede factor van je account, worden je herstelcodes gewist en worden alle apparaten die je als vertrouwd had gemarkeerd uitgelogd. Je account wordt dan alleen nog door het wachtwoord beschermd.',
    'Time allowed to enter the code (seconds)' => 'Toegestane tijd om de code in te voeren (seconden)',
    'Too many incorrect codes. Please log in again.' => 'Te veel onjuiste codes. Log opnieuw in.',
    'Trusted devices' => 'Vertrouwde apparaten',
    'Trusted until' => 'Vertrouwd tot',
    'Two-factor authentication' => 'Tweefactorauthenticatie',
    'Two-factor authentication, all recovery codes and all trusted devices will be removed for %s. They will be emailed about it, and the action is written to the log.' => 'Tweefactorauthenticatie, alle herstelcodes en alle vertrouwde apparaten worden verwijderd voor %s. Diegene krijgt hierover een e-mail en de actie wordt in het log vastgelegd.',
    'Two-factor authentication is already enabled for your account.' => 'Tweefactorauthenticatie is al ingeschakeld voor je account.',
    'Two-factor authentication is enabled.' => 'Tweefactorauthenticatie is ingeschakeld.',
    'Two-factor authentication is enabled for this user.' => 'Tweefactorauthenticatie is ingeschakeld voor deze gebruiker.',
    'Two-factor authentication is not enabled.' => 'Tweefactorauthenticatie is niet ingeschakeld.',
    'Two-factor authentication is not enabled for this user.' => 'Tweefactorauthenticatie is niet ingeschakeld voor deze gebruiker.',
    'Two-factor authentication is now disabled.' => 'Tweefactorauthenticatie is nu uitgeschakeld.',
    'Two-factor authentication is now enabled.' => 'Tweefactorauthenticatie is nu ingeschakeld.',
    'Two-factor authentication is required for your role and cannot be turned off.' => 'Tweefactorauthenticatie is verplicht voor jouw rol en kan niet worden uitgeschakeld.',
    'Two-factor authentication is required for your role. Set it up to continue.' => 'Tweefactorauthenticatie is verplicht voor jouw rol. Stel het in om door te gaan.',
    'Two-factor authentication is required for your role, so it cannot be turned off.' => 'Tweefactorauthenticatie is verplicht voor jouw rol en kan daarom niet worden uitgeschakeld.',
    'Two-factor authentication is required for your role. You cannot use the admin interface until you finish this.' => 'Tweefactorauthenticatie is verplicht voor jouw rol. Je kunt de beheeromgeving niet gebruiken totdat je dit hebt afgerond.',
    'Two-factor authentication was reset for %s.' => 'Tweefactorauthenticatie is gereset voor %s.',
    'Two-step verification' => 'Verificatie in twee stappen',
    'Type: time-based · Digits: 6 · Interval: 30 seconds · Algorithm: SHA1' => 'Type: tijdgebaseerd · Cijfers: 6 · Interval: 30 seconden · Algoritme: SHA1',
    'Unknown device' => 'Onbekend apparaat',
    'Cancelled.' => 'Geannuleerd.',
    'Passkeys are not available on this installation.' => 'Passkeys zijn niet beschikbaar op deze installatie.',
    'That did not work. Try again, or use another way in.' => 'Dat werkte niet. Probeer het opnieuw of gebruik een andere manier om in te loggen.',
    'This browser does not support passkeys.' => 'Deze browser ondersteunt geen passkeys.',
    'Touch your key, or use your device unlock.' => 'Raak je sleutel aan of gebruik de ontgrendeling van je apparaat.',
    'Use your passkey to finish logging in.' => 'Gebruik je passkey om het inloggen af te ronden.',
    'A passkey lets you finish logging in with a hardware key, a fingerprint or your device unlock, instead of typing a code.' => 'Met een passkey rond je het inloggen af met een hardwaresleutel, een vingerafdruk of de ontgrendeling van je apparaat, in plaats van een code te typen.',
    'Add a passkey' => 'Een passkey toevoegen',
    'Name (optional)' => 'Naam (optioneel)',
    'Never' => 'Nooit',
    'No passkeys registered.' => 'Geen passkeys geregistreerd.',
    'Passkey' => 'Passkey',
    'Passkey domain' => 'Passkey-domein',
    'Passkey removed.' => 'Passkey verwijderd.',
    'Passkeys' => 'Passkeys',
    'Passkeys (%d)' => 'Passkeys (%d)',
    'That passkey is already registered.' => 'Die passkey is al geregistreerd.',
    'The domain passkeys are bound to. Leave empty to use the host the site is served from, which is right unless the site answers on more than one name. Changing it invalidates every passkey already registered.' => 'Het domein waaraan passkeys gebonden zijn. Laat leeg om de host te gebruiken waarop de site draait; dat klopt tenzij de site op meerdere namen reageert. Wijzigen maakt elke al geregistreerde passkey ongeldig.',
    'Unnamed passkey' => 'Naamloze passkey',
    'Work laptop' => 'Werklaptop',
    'Use a passkey' => 'Een passkey gebruiken',
    'Use a recovery code' => 'Een herstelcode gebruiken',
    'Use a recovery code instead' => 'Gebruik in plaats daarvan een herstelcode',
    'Use recovery code' => 'Herstelcode gebruiken',
    'Users' => 'Gebruikers',
    'Users enable two-factor authentication themselves, from the "Two-factor authentication" tab on their own user page. These settings apply to everyone.' => 'Gebruikers schakelen tweefactorauthenticatie zelf in, via het tabblad "Tweefactorauthenticatie" op hun eigen gebruikerspagina. Deze instellingen gelden voor iedereen.',
    'Users with a selected role must set up two-factor authentication before they can use the admin interface. Existing sessions are not affected.' => 'Gebruikers met een geselecteerde rol moeten tweefactorauthenticatie instellen voordat ze de beheeromgeving kunnen gebruiken. Bestaande sessies worden niet beïnvloed.',
    'Use this when the person has lost their phone and their recovery codes. They will be emailed, and the reset is logged.' => 'Gebruik dit wanneer diegene zowel de telefoon als de herstelcodes kwijt is. Diegene krijgt een e-mail en de reset wordt gelogd.',
    'Verify' => 'Verifiëren',
    'Wrong codes allowed per login' => 'Toegestane foute codes per login',
    'You are asked for a code from your authenticator app when you log in.' => 'Bij het inloggen wordt om een code uit je authenticator-app gevraagd.',
    'You have %d recovery codes left. Generate a new set from your user page.' => 'Je hebt nog %d herstelcodes. Genereer een nieuwe set via je gebruikerspagina.',
    'Your login timed out. Please log in again.' => 'Je login is verlopen. Log opnieuw in.',
    'Your password' => 'Je wachtwoord',
    'Your recovery codes' => 'Je herstelcodes',
];

// -----------------------------------------------------------------------------

/**
 * Turn a .po-escaped literal back into its real string.
 */
function poUnescape(string $value): string
{
    return stripcslashes($value);
}

function poEscape(string $value): string
{
    return addcslashes($value, "\"\\\n\t");
}

/**
 * Pull the msgids out of a .pot produced with --no-wrap (one line each).
 *
 * @return string[]
 */
function readMsgids(string $file): array
{
    $msgids = [];
    foreach (file($file, FILE_IGNORE_NEW_LINES) as $line) {
        if (0 !== strncmp($line, 'msgid "', 7)) {
            continue;
        }
        $raw = substr($line, 7, -1);
        if ('' === $raw) {
            // The header entry.
            continue;
        }
        $msgids[] = poUnescape($raw);
    }
    return $msgids;
}

function writePo(string $file, string $locale, string $language, array $msgids, callable $translator): int
{
    $out = [];
    $out[] = 'msgid ""';
    $out[] = 'msgstr ""';
    $out[] = '"Project-Id-Version: TwoFactorTotp 0.1.0\n"';
    $out[] = '"Report-Msgid-Bugs-To: \n"';
    $out[] = '"PO-Revision-Date: \n"';
    $out[] = '"Last-Translator: \n"';
    $out[] = sprintf('"Language-Team: %s\n"', $language);
    $out[] = '"MIME-Version: 1.0\n"';
    $out[] = '"Content-Type: text/plain; charset=UTF-8\n"';
    $out[] = '"Content-Transfer-Encoding: 8bit\n"';
    $out[] = sprintf('"Language: %s\n"', $locale);
    $out[] = '"Plural-Forms: nplurals=2; plural=(n != 1);\n"';
    $out[] = '';

    $translated = 0;
    foreach ($msgids as $msgid) {
        $msgstr = $translator($msgid);
        if ('' !== $msgstr) {
            $translated++;
        }
        if (false !== strpos($msgid, '%')) {
            $out[] = '#, php-format';
        }
        $out[] = sprintf('msgid "%s"', poEscape($msgid));
        $out[] = sprintf('msgstr "%s"', poEscape($msgstr));
        $out[] = '';
    }

    file_put_contents($file, implode("\n", $out) . "\n");
    printf("%-34s %3d/%d translated (%s)\n", basename($file), $translated, count($msgids), $language);

    return $translated;
}

$msgids = readMsgids($potFile);
printf("Read %d strings from template.pot\n\n", count($msgids));

// Fail loudly on anything the map has not been told about.
$missing = array_values(array_filter($msgids, fn (string $m): bool => !array_key_exists($m, $nl)));
$stale = array_values(array_filter(array_keys($nl), fn (string $m): bool => !in_array($m, $msgids, true)));

if ($missing) {
    fwrite(STDERR, "Untranslated strings (add them to \$nl in " . basename(__FILE__) . "):\n");
    foreach ($missing as $m) {
        fwrite(STDERR, "  - $m\n");
    }
}
if ($stale) {
    fwrite(STDERR, "Stale entries no longer present in the code:\n");
    foreach ($stale as $m) {
        fwrite(STDERR, "  - $m\n");
    }
}
if ($missing || $stale) {
    exit(1);
}

$languageDir = $moduleDir . '/language';

// English is the source language: an identity catalogue, so that an explicit
// "en" locale resolves rather than falling through to the untranslated msgid.
writePo($languageDir . '/en.po', 'en', 'English', $msgids, fn (string $m): string => $m);

// Dutch. nl_NL matches Omeka core's own filename; nl is provided too so a
// plain "nl" locale setting resolves as well.
$toDutch = fn (string $m): string => $nl[$m];
writePo($languageDir . '/nl_NL.po', 'nl_NL', 'Dutch', $msgids, $toDutch);
writePo($languageDir . '/nl.po', 'nl', 'Dutch', $msgids, $toDutch);

echo "\nNow compile: for f in language/*.po; do msgfmt -o \"\${f%.po}.mo\" \"\$f\"; done\n";

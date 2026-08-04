<?php declare(strict_types=1);
/**
 * End-to-end walk of the whole flow against a running site:
 * enroll -> confirm -> log in with a code -> replay -> recovery codes -> pages.
 *
 * Unlike the unit tests and verify-wiring.php this actually dispatches
 * requests, which is the only way to catch controller/template and service
 * wiring faults.
 *
 * It needs a throwaway account (any role with admin access, e.g. editor) and
 * it WILL enroll, reset and log in as that account. Never point it at a real
 * user. Create and remove one with omeka-s-cli:
 *
 *   omeka-s-cli user:add e2e@example.com 'E2E' editor 'the-password'
 *   omeka-s-cli user:delete e2e@example.com
 *
 * Usage:
 *   TOTP_E2E_URL=https://example.org/omeka \
 *   TOTP_E2E_EMAIL=e2e@example.com \
 *   TOTP_E2E_PASSWORD=the-password \
 *   php test/e2e.php
 *
 * The account must start without an enrollment; the script says so if not.
 */
require dirname(__DIR__) . '/src/Service/Totp.php';

use TwoFactorTotp\Service\Totp;

$required = ['TOTP_E2E_URL', 'TOTP_E2E_EMAIL', 'TOTP_E2E_PASSWORD'];
foreach ($required as $var) {
    if (!getenv($var)) {
        fwrite(STDERR, "Set " . implode(', ', $required) . " - see the top of this file.\n");
        exit(2);
    }
}
define('BASE', rtrim((string) getenv('TOTP_E2E_URL'), '/'));
$jar = sys_get_temp_dir() . '/twofactortotp-e2e-cookies.txt';
$email = (string) getenv('TOTP_E2E_EMAIL');
$password = (string) getenv('TOTP_E2E_PASSWORD');

$pass = 0;
$fail = 0;
function check(string $label, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok    $label\n"; }
    else { $fail++; echo "  FAIL  $label" . ($detail ? " — $detail" : '') . "\n"; }
}

function http(string $url, ?array $post = null, bool $follow = true): array
{
    global $jar;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => $follow,
        CURLOPT_COOKIEJAR => $jar,
        CURLOPT_COOKIEFILE => $jar,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HEADER => true,
        CURLOPT_USERAGENT => 'TwoFactorTotp-e2e',
    ]);
    if (null !== $post) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $raw = (string) curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    $body = substr($raw, $info['header_size']);
    return ['code' => $info['http_code'], 'url' => $info['url'], 'body' => $body];
}

/** Every hidden input on the page, so CSRF tokens travel back untouched. */
function hidden(string $html): array
{
    preg_match_all(
        '/<input[^>]*type=["\']hidden["\'][^>]*>/i',
        $html,
        $inputs
    );
    $out = [];
    foreach ($inputs[0] as $tag) {
        if (preg_match('/name=["\']([^"\']+)["\']/', $tag, $n)
            && preg_match('/value=["\']([^"\']*)["\']/', $tag, $v)
        ) {
            $out[html_entity_decode($n[1])] = html_entity_decode($v[1]);
        }
    }
    return $out;
}

echo "\n== 1. log in without a second factor ==\n";
@unlink($jar);
$login = http(BASE . '/login');
check('login page loads', 200 === $login['code']);
$fields = hidden($login['body']) + ['email' => $email, 'password' => $password, 'submit' => 'Log in'];
$in = http(BASE . '/login', $fields);
check('password login reaches the admin interface', str_contains($in['url'], '/admin'), $in['url']);

echo "\n== 2. enroll ==\n";
$setup = http(BASE . '/admin/two-factor/setup');
check('setup page loads', 200 === $setup['code']);
preg_match('/<code id="totp-secret">([^<]+)<\/code>/', $setup['body'], $m);
$secret = isset($m[1]) ? preg_replace('/\s+/', '', html_entity_decode($m[1])) : '';
check('setup page shows a base32 secret', (bool) preg_match('/^[A-Z2-7]{32}$/', $secret), $secret);
check('setup page renders a QR provisioning uri', str_contains($setup['body'], 'otpauth://'));

$totp = new Totp();
/** Single-use codes: wait for the next 30s step so the counter is unspent. */
function freshCode(Totp $totp, string $secret): string
{
    $next = (intdiv(time(), 30) + 1) * 30;
    usleep(max(0, ($next - time())) * 1000000 + 1200000);
    return $totp->totpAt($secret, time());
}
$reload = http(BASE . '/admin/two-factor/setup');
preg_match('/<code id="totp-secret">([^<]+)<\/code>/', $reload['body'], $m2);
$secret2 = isset($m2[1]) ? preg_replace('/\s+/', '', html_entity_decode($m2[1])) : '';
check('secret survives a page reload (regression: was regenerated)', $secret === $secret2);

echo "\n== 3. confirm with a live code ==\n";
$code = $totp->totpAt($secret, time());
$confirm = http(BASE . '/admin/two-factor/setup', hidden($reload['body']) + ['code' => $code]);
check('confirmation accepts a valid code', str_contains($confirm['body'], 'totp-recovery-code-list'), 'no recovery-code list returned');
preg_match_all('/<li><code>([A-Z2-9]{5}-[A-Z2-9]{5})<\/code><\/li>/', $confirm['body'], $rc);
$recoveryCodes = $rc[1] ?? [];
check('ten recovery codes issued', 10 === count($recoveryCodes), count($recoveryCodes) . ' returned');

echo "\n== 4. a wrong code is refused ==\n";
http(BASE . '/logout');
$in = loginToSecondStep();
check('password alone no longer reaches admin', !str_contains($in['url'], '/admin'), $in['url']);
check('held at the two-factor step', str_contains($in['url'], 'two-factor'), $in['url']);
$wrong = http(BASE . '/two-factor', hidden($in['body']) + ['code' => '000000']);
check('wrong code rejected', !str_contains($wrong['url'], '/admin'), $wrong['url']);


/** Clear cookies, log in with the password, and stop at the second step. */
function loginToSecondStep(): array
{
    global $jar, $email, $password;
    @unlink($jar);
    $login = http(BASE . '/login');
    $r = http(BASE . '/login', hidden($login['body'])
        + ['email' => $email, 'password' => $password, 'submit' => 'Log in']);
    if (str_contains($r['url'], '/login')) {
        preg_match_all('/<li[^>]*class="[^"]*(?:error|warning|success)[^"]*"[^>]*>(.*?)<\/li>/s', $r['body'], $msg);
        echo "         [login landed on /login] messages: "
            . (implode(' | ', array_map(fn($m) => trim(strip_tags($m)), $msg[1])) ?: '(none)') . "\n";
    }
    return $r;
}

echo "\n== 5. log in with a real code ==\n";
$at = loginToSecondStep();
$spentCode = freshCode($totp, $secret);
$good = http(BASE . '/two-factor', hidden($at['body']) + ['code' => $spentCode]);
check('valid code completes the login', str_contains($good['url'], '/admin'), $good['url']);

echo "\n== 6. that same code cannot be replayed ==\n";
$at = loginToSecondStep();
check('a fresh login is held at the second step', str_contains($at['url'], 'two-factor'), $at['url']);
$replay = http(BASE . '/two-factor', hidden($at['body']) + ['code' => $spentCode]);
check('the already-spent code is refused', !str_contains($replay['url'], '/admin'), $replay['url']);

echo "\n== 7. recovery code ==\n";
$at = loginToSecondStep();
$recoveryPage = http(BASE . '/two-factor/recovery');
check('recovery page loads', 200 === $recoveryPage['code']);
$one = $recoveryCodes[0] ?? 'XXXXX-XXXXX';
$rec = http(BASE . '/two-factor/recovery', hidden($recoveryPage['body']) + ['recovery_code' => $one]);
check('a recovery code completes the login', str_contains($rec['url'], '/admin'), $rec['url']);

$at = loginToSecondStep();
$recoveryPage = http(BASE . '/two-factor/recovery');
$reuse = http(BASE . '/two-factor/recovery', hidden($recoveryPage['body']) + ['recovery_code' => $one]);
check('the same recovery code is refused the second time', !str_contains($reuse['url'], '/admin'), $reuse['url']);

$at = loginToSecondStep();
$recoveryPage = http(BASE . '/two-factor/recovery');
$second = http(BASE . '/two-factor/recovery', hidden($recoveryPage['body']) + ['recovery_code' => $recoveryCodes[1] ?? 'XXXXX-XXXXX']);
check('a different unused recovery code still works', str_contains($second['url'], '/admin'), $second['url']);

echo "\n== 8. pages behind the second factor ==\n";
$at = loginToSecondStep();
$in = http(BASE . '/two-factor', hidden($at['body']) + ['code' => freshCode($totp, $secret)]);
check('logged in for the page sweep', str_contains($in['url'], '/admin'), $in['url']);
foreach ([
    '/admin/two-factor/devices' => 'trusted devices',
    '/admin/two-factor/recovery-codes' => 'regenerate recovery codes',
    '/admin/two-factor/disable' => 'disable',
] as $path => $label) {
    $r = http(BASE . $path);
    check("$label page renders", 200 === $r['code']
        && !str_contains($r['url'], '/login')
        && !str_contains($r['body'], 'Fatal error'), $r['url']);
}
$devices = http(BASE . '/admin/two-factor/devices');
check('devices page has a working csrf element (regression)', !str_contains($devices['body'], 'InvalidElementException'));
$regen = http(BASE . '/admin/two-factor/recovery-codes');
check('recovery-codes page offers a password form (regression)', str_contains($regen['body'], 'type="password"'));

printf("\n----------------------------------------\n%d passed, %d failed\n\n", $pass, $fail);
exit($fail > 0 ? 1 : 0);

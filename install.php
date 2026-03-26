<?php
declare(strict_types=1);

$config = require __DIR__ . '/config.php';
$authFile = $config['auth_file'] ?? (__DIR__ . '/auth_data.json');
$adminAuthFile = $config['admin_auth_file'] ?? (__DIR__ . '/admin_auth_data.json');
$verifySsl = (bool)($config['verify_ssl'] ?? true);
$caBundle = trim((string)($config['ca_bundle'] ?? ''));

function respondJson(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function respondInstallHtml(bool $success, string $message): void
{
    $safeMessage = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    header('Content-Type: text/html; charset=utf-8');
    ?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Установка приложения</title>
</head>
<body style="font-family:Segoe UI,Arial,sans-serif;padding:16px;">
<div><?= $safeMessage ?></div>
<script src="https://api.bitrix24.com/api/v1/"></script>
<script>
    (function () {
        if (window.BX24 && typeof BX24.init === 'function') {
            BX24.init(function () {
                if (typeof BX24.installFinish === 'function') {
                    BX24.installFinish();
                }
            });
        }
    })();
</script>
</body>
</html>
<?php
    exit;
}

function buildCurrentBaseUrl(): string
{
    $proto = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $proto = trim((string)$_SERVER['HTTP_X_FORWARDED_PROTO']);
    } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $proto = 'https';
    }

    $host = trim((string)($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '') {
        return '';
    }

    return $proto . '://' . $host;
}

function restCallInstall(string $basePortalUrl, string $authId, string $method, array $params = []): array
{
    global $verifySsl, $caBundle;

    $url = rtrim($basePortalUrl, '/') . '/rest/' . rawurlencode($method) . '.json?auth=' . rawurlencode($authId);
    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'error' => 'curl_init failed'];
    }

    $curlOptions = [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($params),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => $verifySsl,
        CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
    ];
    if ($verifySsl && $caBundle !== '' && is_file($caBundle)) {
        $curlOptions[CURLOPT_CAINFO] = $caBundle;
    }
    curl_setopt_array($ch, $curlOptions);

    $raw = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'error' => $err];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'invalid json'];
    }
    if (isset($decoded['error'])) {
        return [
            'ok' => false,
            'error' => (string)$decoded['error'],
            'error_description' => (string)($decoded['error_description'] ?? ''),
        ];
    }

    return ['ok' => true, 'result' => $decoded['result'] ?? null];
}

$requiredFields = ['AUTH_ID'];
$missing = [];
foreach ($requiredFields as $field) {
    if (!isset($_REQUEST[$field]) || trim((string)$_REQUEST[$field]) === '') {
        $missing[] = $field;
    }
}

if ($missing !== []) {
    // If install.php is opened manually (or configured as app entry by mistake),
    // route to the main app interface instead of returning an error page.
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        header('Location: handler.php', true, 302);
        exit;
    }

    respondJson(400, [
        'success' => false,
        'message' => 'Missing required install parameters.',
        'missing_fields' => $missing,
    ]);
}

$payload = [
    'AUTH_ID' => trim((string)$_REQUEST['AUTH_ID']),
    'AUTH_SECRET' => isset($_REQUEST['AUTH_SECRET']) ? trim((string)$_REQUEST['AUTH_SECRET']) : '',
    'MEMBER_ID' => isset($_REQUEST['MEMBER_ID']) ? trim((string)$_REQUEST['MEMBER_ID']) : '',
    'DOMAIN' => isset($_REQUEST['DOMAIN']) ? trim((string)$_REQUEST['DOMAIN']) : '',
    'REFRESH_ID' => isset($_REQUEST['REFRESH_ID']) ? trim((string)$_REQUEST['REFRESH_ID']) : '',
    'APPLICATION_TOKEN' => isset($_REQUEST['APP_SID']) ? trim((string)$_REQUEST['APP_SID']) : '',
    'installed_at' => date('c'),
];

$json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if ($json === false) {
    respondJson(500, [
        'success' => false,
        'message' => 'Failed to encode auth payload.',
    ]);
}

$bytes = @file_put_contents($authFile, $json);
if ($bytes === false) {
    respondJson(500, [
        'success' => false,
        'message' => 'Failed to save auth data file.',
    ]);
}

// Save a separate copy for "admin/auth installer" mode.
// If the copy fails, we just continue with normal auth storage.
@file_put_contents($adminAuthFile, $json);

$domain = trim((string)($payload['DOMAIN'] ?? ''));
$authId = trim((string)($payload['AUTH_ID'] ?? ''));
$currentBaseUrl = buildCurrentBaseUrl();
$installMessages = [];

if ($domain !== '' && $authId !== '' && $currentBaseUrl !== '') {
    $portalBaseUrl = 'https://' . $domain;
    $handlerUrl = rtrim($currentBaseUrl, '/') . '/handler.php';
    $placements = [
        'CRM_LEAD_DETAIL_TAB' => 'ИНН поиск',
        'CRM_DEAL_DETAIL_TAB' => 'ИНН поиск',
        'CRM_COMPANY_DETAIL_TAB' => 'ИНН поиск',
        'CRM_CONTACT_DETAIL_TAB' => 'ИНН поиск',
    ];

    foreach ($placements as $placementCode => $title) {
        $bind = restCallInstall($portalBaseUrl, $authId, 'placement.bind', [
            'PLACEMENT' => $placementCode,
            'HANDLER' => $handlerUrl,
            'TITLE' => $title,
            'DESCRIPTION' => 'Поиск компаний по ИНН и добавление наблюдателя.',
        ]);

        if ($bind['ok']) {
            $installMessages[] = 'Плейсмент ' . $placementCode . ' зарегистрирован.';
            continue;
        }

        $err = mb_strtolower((string)($bind['error_description'] ?? $bind['error'] ?? ''), 'UTF-8');
        if (mb_strpos($err, 'already', 0, 'UTF-8') !== false || mb_strpos($err, 'существ', 0, 'UTF-8') !== false) {
            $installMessages[] = 'Плейсмент ' . $placementCode . ' уже зарегистрирован.';
        } else {
            $installMessages[] = 'Плейсмент ' . $placementCode . ' не зарегистрирован: ' . (string)($bind['error_description'] ?? $bind['error'] ?? 'unknown');
        }
    }
}

// For Bitrix24 installation iframe we should finish install via JS.
respondInstallHtml(true, 'Application installed successfully. ' . implode(' ', $installMessages));

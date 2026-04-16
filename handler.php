<?php
declare(strict_types=1);

$config = require __DIR__ . '/config.php';
$authFile = $config['auth_file'] ?? (__DIR__ . '/auth_data.json');
$apiTimeout = (int)($config['api_timeout'] ?? 15);
$portalUrl = rtrim((string)($config['portal_url'] ?? ''), '/');
$verifySsl = (bool)($config['verify_ssl'] ?? true);
$caBundle = trim((string)($config['ca_bundle'] ?? ''));
$useInstallAuthAsAdmin = (bool)($config['use_install_auth_as_admin'] ?? false);
$adminAuthFile = $config['admin_auth_file'] ?? (__DIR__ . '/admin_auth_data.json');
$portalMemberIdFromRequest = (int)($_REQUEST['member_id'] ?? $_REQUEST['memberId'] ?? 0);

$authData = [];
$errors = [];
$successes = [];
$currentUser = [];
$resultInfo = null;

$debugLogFile = __DIR__ . '/runtime_debug_handler.log';
$debugRequestId = substr(sha1((string)microtime(true) . '|' . ($_SERVER['REMOTE_ADDR'] ?? '') . '|' . ($_SERVER['HTTP_USER_AGENT'] ?? '')), 0, 12);

function logDebug(string $event, array $data = []): void
{
    global $debugLogFile, $debugRequestId;
    $payload = [
        'id' => $debugRequestId,
        'time' => date('c'),
        'event' => $event,
        'data' => $data,
    ];
    @file_put_contents($debugLogFile, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND);
}

logDebug('request_received', [
    'method' => $_SERVER['REQUEST_METHOD'] ?? '',
    'request_keys_sample' => array_slice(array_keys($_REQUEST), 0, 80),
    'has_placement_options' => array_key_exists('PLACEMENT_OPTIONS', $_REQUEST) || array_key_exists('placement_options', $_REQUEST),
    'placement_options_raw_len' => isset($_REQUEST['PLACEMENT_OPTIONS']) ? strlen((string)$_REQUEST['PLACEMENT_OPTIONS']) : (isset($_REQUEST['placement_options']) ? strlen((string)$_REQUEST['placement_options']) : 0),
    'portal_member_id_from_request' => $portalMemberIdFromRequest,
]);

// In admin-auth mode we try to read the installer token from admin_auth_file.
$authDataFile = $authFile;
if ($useInstallAuthAsAdmin && is_file($adminAuthFile)) {
    $authDataFile = $adminAuthFile;
}
$authDataSourceLabel = $authDataFile === $adminAuthFile ? 'admin_auth_data.json' : 'auth_data.json';

if (!is_file($authDataFile)) {
    $errors[] = 'Файл авторизации не найден. Сначала установите приложение (install.php).';
} else {
    $rawAuth = @file_get_contents($authDataFile);
    $decoded = is_string($rawAuth) ? json_decode($rawAuth, true) : null;
    if (!is_array($decoded)) {
        $errors[] = 'Файл авторизации поврежден или имеет неверный формат JSON.';
    } else {
        $authData = $decoded;
    }
}

// Bitrix24 may send fresh auth parameters on each app launch.
// We merge and persist them to avoid issues with expired/old tokens.
$requestAuthMap = [
    'AUTH_ID' => 'AUTH_ID',
    'AUTH_EXPIRES' => 'AUTH_EXPIRES',
    'REFRESH_ID' => 'REFRESH_ID',
    'DOMAIN' => 'DOMAIN',
    'PROTOCOL' => 'PROTOCOL',
    'APP_SID' => 'APPLICATION_TOKEN',
    'MEMBER_ID' => 'MEMBER_ID',
];
$userAuthData = $authData;
if ($useInstallAuthAsAdmin) {
    // Build auth data for "user.current" from the current app launch request.
    // This avoids overwriting the installer/admin token used for CRM write/search.
    foreach ($requestAuthMap as $requestKey => $authKey) {
        if (!isset($_REQUEST[$requestKey])) {
            continue;
        }
        $value = trim((string)$_REQUEST[$requestKey]);
        if ($value === '') {
            continue;
        }
        $userAuthData[$authKey] = $value;
    }
}

// IMPORTANT:
// In admin-auth mode we DO NOT resolve current user on initial GET/boot,
// because extracted "current user" can be installer/admin and then we won't
// override it on POST. We'll resolve it only on POST using request context.
if (!$useInstallAuthAsAdmin) {
    $requestUserId = extractCurrentUserIdFromRequest();
    if ($requestUserId > 0) {
        $currentUser = ['ID' => (string)$requestUserId];
    }
}

if (!$useInstallAuthAsAdmin) {
    // Default mode: keep auth in sync with current app launch user.
    $authChanged = false;
    foreach ($requestAuthMap as $requestKey => $authKey) {
        if (!isset($_REQUEST[$requestKey])) {
            continue;
        }
        $value = trim((string)$_REQUEST[$requestKey]);
        if ($value === '') {
            continue;
        }
        if (!isset($authData[$authKey]) || (string)$authData[$authKey] !== $value) {
            $authData[$authKey] = $value;
            $authChanged = true;
        }
    }

    if ($authChanged) {
        $authData['updated_at'] = date('c');
        $encodedAuth = json_encode($authData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_string($encodedAuth)) {
            @file_put_contents($authFile, $encodedAuth);
        }
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function restCall(string $method, array $params, array $authData, int $timeout, ?string $portalUrl = null): array
{
    global $verifySsl, $caBundle;

    $token = (string)($authData['AUTH_ID'] ?? '');
    $domain = trim((string)($authData['DOMAIN'] ?? ''));
    $baseUrl = '';

    if ($domain !== '') {
        $baseUrl = 'https://' . $domain;
    } elseif ($portalUrl !== '') {
        $baseUrl = $portalUrl;
    }

    if ($baseUrl === '' || $token === '') {
        return ['ok' => false, 'error' => 'Authorization data is missing.'];
    }

    $url = $baseUrl . '/rest/' . rawurlencode($method) . '.json?auth=' . rawurlencode($token);
    $payload = http_build_query($params);

    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'error' => 'Failed to initialize cURL.'];
    }

    $curlOptions = [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => $verifySsl,
        CURLOPT_SSL_VERIFYHOST => $verifySsl ? 2 : 0,
    ];
    if ($verifySsl && $caBundle !== '' && is_file($caBundle)) {
        $curlOptions[CURLOPT_CAINFO] = $caBundle;
    }
    curl_setopt_array($ch, $curlOptions);

    $raw = curl_exec($ch);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'error' => 'cURL error: ' . $curlError];
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'Invalid JSON response from Bitrix24.'];
    }

    if (isset($decoded['error'])) {
        return [
            'ok' => false,
            'error' => (string)$decoded['error'],
            'error_description' => (string)($decoded['error_description'] ?? ''),
            'raw' => $decoded,
        ];
    }

    return ['ok' => true, 'result' => $decoded['result'] ?? null, 'raw' => $decoded];
}

function normalizeInn(string $inn): string
{
    return preg_replace('/\D+/', '', $inn) ?? '';
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

function getPortalBaseUrl(array $authData, ?string $portalUrl): string
{
    $domain = trim((string)($authData['DOMAIN'] ?? ''));
    if ($domain !== '') {
        return 'https://' . $domain;
    }
    return rtrim((string)$portalUrl, '/');
}

function extractCurrentUserIdFromRequest(): int
{
    $placementOptionsRaw = (string)($_REQUEST['PLACEMENT_OPTIONS'] ?? $_REQUEST['placement_options'] ?? '');
    $placementOptions = null;
    if (is_array($_REQUEST['PLACEMENT_OPTIONS'] ?? null)) {
        $placementOptions = $_REQUEST['PLACEMENT_OPTIONS'];
    } elseif ($placementOptionsRaw !== '') {
        // Try multiple decoding strategies: raw JSON and URL-decoded JSON.
        $decoded = json_decode($placementOptionsRaw, true);
        if (!is_array($decoded)) {
            $decoded = json_decode(urldecode($placementOptionsRaw), true);
        }
        if (is_array($decoded)) {
            $placementOptions = $decoded;
        }
    }

    if (is_array($placementOptions)) {
        logDebug('extract.user_from_placement_options', [
            'placement_options_raw_len' => strlen($placementOptionsRaw),
            'placement_options_keys_top' => array_slice(array_keys($placementOptions), 0, 50),
            'direct_keys_present_in_placement' => array_values(array_intersect([
                'USER_ID',
                'userId',
                'CURRENT_USER_ID',
                'currentUserId',
                'AUTH_USER_ID',
                'auth_user_id'
            ], array_keys($placementOptions))),
        ]);
        $optionKeys = [
            'USER_ID',
            'userId',
            'CURRENT_USER_ID',
            'currentUserId',
            'AUTH_USER_ID',
            'auth_user_id',
            'authUserId',
        ];
        foreach ($optionKeys as $key) {
            if (!array_key_exists($key, $placementOptions)) {
                continue;
            }
            $id = (int)$placementOptions[$key];
            if ($id > 0) {
                return $id;
            }
        }

        // IMPORTANT:
        // We intentionally do not recursively scan arbitrary keys here.
        // Placement payload may contain IDs of responsible users, creators etc.
        // Using such IDs can incorrectly bind an unrelated employee as observer.
    }

    // Fallback to direct request parameters.
    $directKeys = [
        'USER_ID',
        'user_id',
        'AUTH_USER_ID',
        'auth_user_id',
        'userId',
    ];
    foreach ($directKeys as $key) {
        if (!isset($_REQUEST[$key])) {
            continue;
        }
        $id = (int)$_REQUEST[$key];
        if ($id > 0) {
            logDebug('extract.user_from_direct_keys', [
                'key' => $key,
                'id' => $id,
            ]);
            return $id;
        }
    }

    return 0;
}

function resolveObserverUserId(int $timeout, ?string $portalUrl, bool $useInstallAuthAsAdmin, array $userAuthData): int
{
    $requestScopedAuthData = $userAuthData;
    $requestScopedAuthMap = [
        'observer_auth_id' => 'AUTH_ID',
        'observer_refresh_id' => 'REFRESH_ID',
        'observer_domain' => 'DOMAIN',
        'observer_protocol' => 'PROTOCOL',
    ];
    foreach ($requestScopedAuthMap as $postKey => $authKey) {
        if (!isset($_POST[$postKey])) {
            continue;
        }
        $value = trim((string)$_POST[$postKey]);
        if ($value === '') {
            continue;
        }
        $requestScopedAuthData[$authKey] = $value;
    }

    if (!empty($requestScopedAuthData['AUTH_ID']) && !empty($requestScopedAuthData['DOMAIN'])) {
        $userFromPostedAuth = getCurrentUser($requestScopedAuthData, $timeout, $portalUrl, false);
        $observerUserIdFromAuth = (int)($userFromPostedAuth['ID'] ?? 0);
        if ($observerUserIdFromAuth > 0) {
            logDebug('observer.resolve.from_posted_auth', [
                'observer_user_id' => $observerUserIdFromAuth,
                'domain' => (string)$requestScopedAuthData['DOMAIN'],
            ]);
            return $observerUserIdFromAuth;
        }

        logDebug('observer.resolve.posted_auth_failed', [
            'domain' => (string)($requestScopedAuthData['DOMAIN'] ?? ''),
            'error' => (string)($userFromPostedAuth['_error'] ?? ''),
        ]);
    }

    $observerUserId = (int)($_POST['observer_user_id'] ?? 0);
    if ($observerUserId > 0) {
        logDebug('observer.resolve.from_post', [
            'observer_user_id' => $observerUserId,
        ]);
        return $observerUserId;
    }

    if (!$useInstallAuthAsAdmin) {
        $observerUserId = extractCurrentUserIdFromRequest();
        if ($observerUserId > 0) {
            logDebug('observer.resolve.from_request_context', [
                'observer_user_id' => $observerUserId,
            ]);
            return $observerUserId;
        }
    }

    if ($useInstallAuthAsAdmin) {
        $userFromRequestAuth = getCurrentUser($userAuthData, $timeout, $portalUrl, true);
        $observerUserId = (int)($userFromRequestAuth['ID'] ?? 0);
        if ($observerUserId > 0) {
            logDebug('observer.resolve.from_user_auth', [
                'observer_user_id' => $observerUserId,
            ]);
            return $observerUserId;
        }
    }

    logDebug('observer.resolve.failed', [
        'post_observer_user_id' => (int)($_POST['observer_user_id'] ?? 0),
        'request_keys_sample' => array_slice(array_keys($_REQUEST), 0, 80),
    ]);

    return 0;
}

function ensurePlacementsBound(array $authData, int $timeout, ?string $portalUrl): array
{
    $baseUrl = buildCurrentBaseUrl();
    if ($baseUrl === '') {
        return ['ok' => false, 'error' => 'Cannot build current base URL.'];
    }

    $handlerUrl = rtrim($baseUrl, '/') . '/handler.php';
    $placements = [
        'CRM_LEAD_DETAIL_TAB' => 'ИНН поиск',
        'CRM_DEAL_DETAIL_TAB' => 'ИНН поиск',
        'CRM_COMPANY_DETAIL_TAB' => 'ИНН поиск',
        'CRM_CONTACT_DETAIL_TAB' => 'ИНН поиск',
    ];

    $errors = [];
    foreach ($placements as $placementCode => $title) {
        $bind = restCall('placement.bind', [
            'PLACEMENT' => $placementCode,
            'HANDLER' => $handlerUrl,
            'TITLE' => $title,
            'DESCRIPTION' => 'Поиск компаний по ИНН и добавление наблюдателя.',
        ], $authData, $timeout, $portalUrl);

        if ($bind['ok']) {
            continue;
        }

        $errorText = mb_strtolower((string)($bind['error_description'] ?? $bind['error'] ?? ''), 'UTF-8');
        if (mb_strpos($errorText, 'already', 0, 'UTF-8') !== false || mb_strpos($errorText, 'существ', 0, 'UTF-8') !== false) {
            continue;
        }

        $errors[] = $placementCode . ': ' . (string)($bind['error_description'] ?? $bind['error'] ?? 'unknown');
    }

    if ($errors !== []) {
        return ['ok' => false, 'error' => implode('; ', $errors)];
    }

    return ['ok' => true];
}

function findCompanyIdsByInnViaRequisites(string $inn, array $authData, int $timeout, ?string $portalUrl): array
{
    $baseParams = [
        'filter' => [
            'ENTITY_TYPE_ID' => 4,
            'RQ_INN' => $inn,
        ],
        'select' => ['ID', 'ENTITY_ID', 'RQ_INN'],
        'order' => ['ID' => 'ASC'],
        'start' => -1,
    ];

    $responses = [];
    $responses[] = restCall('crm.requisite.list', $baseParams, $authData, $timeout, $portalUrl);
    $responses[] = restCall('crm.requisite.list', array_merge($baseParams, [
        'filter' => [
            'ENTITY_TYPE_ID' => 4,
            'RQ_INN' => $inn,
            'CHECK_PERMISSIONS' => 'N',
        ],
    ]), $authData, $timeout, $portalUrl);
    $responses[] = restCall('crm.requisite.list', array_merge($baseParams, [
        'params' => ['CHECK_PERMISSIONS' => 'N'],
    ]), $authData, $timeout, $portalUrl);

    $lastError = '';
    $companyIds = [];
    foreach ($responses as $response) {
        if (!$response['ok']) {
            $lastError = (string)($response['error_description'] ?? $response['error'] ?? 'unknown error');
            continue;
        }

        $requisites = $response['result'];
        if (!is_array($requisites)) {
            continue;
        }

        foreach ($requisites as $row) {
            if (!is_array($row)) {
                continue;
            }
            $entityId = (int)($row['ENTITY_ID'] ?? 0);
            if ($entityId > 0) {
                $companyIds[] = $entityId;
            }
        }
    }

    $companyIds = array_values(array_unique(array_map('intval', $companyIds)));
    if ($companyIds !== []) {
        return ['ok' => true, 'company_ids' => $companyIds];
    }

    if ($lastError !== '') {
        return [
            'ok' => false,
            'error' => $lastError,
            'company_ids' => [],
        ];
    }

    return ['ok' => true, 'company_ids' => $companyIds];
}

function getCurrentUser(array $authData, int $timeout, ?string $portalUrl, bool $useRequestFallback = true): array
{
    $response = restCall('user.current', [], $authData, $timeout, $portalUrl);
    if (!$response['ok']) {
        if ($useRequestFallback) {
            $fallbackId = extractCurrentUserIdFromRequest();
            if ($fallbackId > 0) {
                return ['ID' => (string)$fallbackId];
            }
        }
        return ['_error' => (string)($response['error_description'] ?? $response['error'] ?? 'unknown')];
    }

    $result = $response['result'];
    if (!is_array($result)) {
        return [];
    }

    if (isset($result['ID']) && (int)$result['ID'] > 0) {
        return $result;
    }

    if ($useRequestFallback) {
        $fallbackId = extractCurrentUserIdFromRequest();
        if ($fallbackId > 0) {
            $result['ID'] = (string)$fallbackId;
        }
    }

    return $result;
}

function addObserverToCompany(int $companyId, int $userId, array $authData, int $timeout, ?string $portalUrl): array
{
    $itemGet = restCall('crm.item.get', [
        'entityTypeId' => 4,
        'id' => $companyId,
    ], $authData, $timeout, $portalUrl);
    $item = $itemGet['result']['item'] ?? null;
    if (!$itemGet['ok'] || !is_array($item)) {
        return [
            'ok' => false,
            'error' => (string)($itemGet['error_description'] ?? $itemGet['error'] ?? 'Failed to get CRM item.'),
        ];
    }

    $observerIds = $item['observers'] ?? [];
    if (!is_array($observerIds)) {
        $observerIds = [];
    }

    $observerIds = array_values(array_unique(array_map('intval', $observerIds)));
    if (in_array($userId, $observerIds, true)) {
        return ['ok' => true, 'already_observer' => true];
    }

    $observerIds[] = $userId;
    $observerIds = array_values(array_unique(array_map('intval', $observerIds)));

    $update = restCall('crm.item.update', [
        'entityTypeId' => 4,
        'id' => $companyId,
        'fields' => [
            'observers' => $observerIds,
        ],
    ], $authData, $timeout, $portalUrl);

    if (!$update['ok']) {
        return ['ok' => false, 'error' => (string)($update['error_description'] ?? $update['error'] ?? 'Failed to update CRM item.')];
    }

    // Verify observer presence after update to avoid false-positive success.
    $verify = restCall('crm.item.get', [
        'entityTypeId' => 4,
        'id' => $companyId,
    ], $authData, $timeout, $portalUrl);
    $verifyItem = $verify['result']['item'] ?? null;
    $verifyObservers = is_array($verifyItem) && isset($verifyItem['observers']) && is_array($verifyItem['observers'])
        ? array_values(array_unique(array_map('intval', $verifyItem['observers'])))
        : [];
    if (!in_array($userId, $verifyObservers, true)) {
        return ['ok' => false, 'error' => 'Observer was not added (verification failed).'];
    }

    return ['ok' => true, 'already_observer' => false];
}

$inn = '';
$observerUserId = resolveObserverUserId($apiTimeout, $portalUrl, $useInstallAuthAsAdmin, $userAuthData);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $errors === []) {
    $inn = normalizeInn((string)($_POST['inn'] ?? ''));
    if (!preg_match('/^\d{10}(\d{2})?$/', $inn)) {
        $errors[] = 'ИНН должен содержать 10 или 12 цифр.';
    } else {
        $requisiteSearch = findCompanyIdsByInnViaRequisites($inn, $authData, $apiTimeout, $portalUrl);
        if (!$requisiteSearch['ok']) {
            $errors[] = 'Ошибка поиска по реквизитам (RQ_INN): ' . (string)$requisiteSearch['error'];
        } else {
            $companyIds = is_array($requisiteSearch['company_ids']) ? $requisiteSearch['company_ids'] : [];
            if ($companyIds === []) {
                $errors[] = 'Компании с указанным ИНН не найдены в реквизитах (RQ_INN).';
            } else {
                $companyList = restCall('crm.company.list', [
                    'filter' => [
                        'ID' => $companyIds,
                        'CHECK_PERMISSIONS' => 'N',
                    ],
                    'select' => ['ID', 'TITLE'],
                    'order' => ['ID' => 'ASC'],
                    'start' => -1,
                ], $authData, $apiTimeout, $portalUrl);

                $companies = [];
                if ($companyList['ok']) {
                    $companies = is_array($companyList['result']) ? $companyList['result'] : [];
                }

                if ($companies === [] && $companyIds !== []) {
                    // User can have restricted read permissions: keep IDs.
                    foreach ($companyIds as $id) {
                        $companies[] = [
                            'ID' => (int)$id,
                            'TITLE' => 'Компания #' . (int)$id,
                        ];
                    }
                    $successes[] = 'Названия компаний недоступны по правам, обработка выполнена по ID.';
                }

                $successes[] = 'Найдено компаний: ' . count($companies);

                if ($observerUserId <= 0) {
                    $errors[] = 'Не удалось определить ID текущего пользователя Bitrix24. Откройте приложение внутри портала и попробуйте снова.';
                }

                if ($observerUserId > 0) {
                    $added = 0;
                    $already = 0;
                    $failed = 0;
                    $failedItems = [];

                    foreach ($companies as $company) {
                        $companyId = (int)($company['ID'] ?? 0);
                        if ($companyId <= 0) {
                            $failed++;
                            $failedItems[] = 'Некорректный ID компании в ответе API.';
                            continue;
                        }

                        $observerResult = addObserverToCompany($companyId, $observerUserId, $authData, $apiTimeout, $portalUrl);
                        if ($observerResult['ok']) {
                            if (!empty($observerResult['already_observer'])) {
                                $already++;
                            } else {
                                $added++;
                            }
                        } else {
                            $failed++;
                            $failedItems[] = 'Компания #' . $companyId . ': ' . (string)($observerResult['error'] ?? 'unknown error');
                        }
                    }

                    $successes[] = 'ID наблюдателя: ' . $observerUserId;
                    $successes[] = 'Добавлено в наблюдатели: ' . $added;
                    $successes[] = 'Уже был наблюдателем: ' . $already;
                    if ($failed > 0) {
                        $errors[] = 'Не удалось обновить наблюдателей в ' . $failed . ' компаниях.';
                        foreach ($failedItems as $item) {
                            $errors[] = $item;
                        }
                    }
                }

                $resultInfo = [
                    'companies' => $companies,
                    'requisite_field_code' => 'RQ_INN',
                    'observer_user_id' => (string)$observerUserId,
                    'portal_base_url' => getPortalBaseUrl($authData, $portalUrl),
                ];
            }
        }
    }
}

if ($authData !== [] && isset($_GET['bind_tabs']) && (string)$_GET['bind_tabs'] === '1') {
    $placementBindResult = ensurePlacementsBound($authData, $apiTimeout, $portalUrl);
    if ($placementBindResult['ok']) {
        $successes[] = 'Вкладки CRM успешно зарегистрированы.';
    } else {
        $errors[] = 'Не удалось зарегистрировать вкладки CRM: ' . (string)$placementBindResult['error'];
    }
}
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Поиск компаний по ИНН</title>
    <style>
        :root {
            --bx-bg: #f5f7fa;
            --bx-card: #fff;
            --bx-primary: #2fc6f6;
            --bx-primary-dark: #18afe0;
            --bx-text: #1f2d3d;
            --bx-muted: #73879c;
            --bx-success: #2fcf8f;
            --bx-danger: #eb5757;
            --bx-border: #dfe6ee;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            padding: 24px;
            background: var(--bx-bg);
            color: var(--bx-text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
        }
        .container {
            max-width: 860px;
            margin: 0 auto;
        }
        .card {
            background: var(--bx-card);
            border: 1px solid var(--bx-border);
            border-radius: 10px;
            box-shadow: 0 8px 24px rgba(15, 33, 59, 0.06);
            padding: 24px;
        }
        h1 {
            margin: 0 0 8px;
            font-size: 24px;
            font-weight: 600;
        }
        .meta {
            margin-bottom: 20px;
            color: var(--bx-muted);
            font-size: 14px;
        }
        form {
            display: grid;
            gap: 12px;
            grid-template-columns: 1fr auto;
            margin-bottom: 16px;
        }
        input[type="text"] {
            width: 100%;
            border: 1px solid var(--bx-border);
            border-radius: 8px;
            font-size: 16px;
            padding: 12px 14px;
            outline: none;
        }
        input[type="text"]:focus {
            border-color: var(--bx-primary);
            box-shadow: 0 0 0 3px rgba(47, 198, 246, 0.16);
        }
        button {
            border: none;
            border-radius: 8px;
            padding: 12px 18px;
            font-size: 15px;
            font-weight: 600;
            color: #fff;
            background: var(--bx-primary);
            cursor: pointer;
            min-width: 170px;
        }
        button:hover { background: var(--bx-primary-dark); }
        button:disabled { opacity: 0.75; cursor: wait; }
        .alert {
            border-radius: 8px;
            padding: 12px 14px;
            margin: 10px 0;
            font-size: 14px;
            line-height: 1.45;
        }
        .alert-success {
            background: rgba(47, 207, 143, 0.12);
            color: #1b7d57;
            border: 1px solid rgba(47, 207, 143, 0.35);
        }
        .alert-error {
            background: rgba(235, 87, 87, 0.1);
            color: #ab2f2f;
            border: 1px solid rgba(235, 87, 87, 0.35);
        }
        .small {
            color: var(--bx-muted);
            font-size: 13px;
            margin-top: 8px;
        }
        .result {
            margin-top: 14px;
            border-top: 1px solid var(--bx-border);
            padding-top: 14px;
        }
        ul {
            margin: 8px 0 0;
            padding-left: 20px;
        }
        @media (max-width: 640px) {
            body { padding: 12px; }
            .card { padding: 16px; }
            form { grid-template-columns: 1fr; }
            button { width: 100%; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>Поиск компаний по ИНН</h1>
        <div class="meta">
            Приложение ищет компании по ИНН от имени администратора и автоматически добавляет текущего пользователя в наблюдатели.
        </div>

        <form method="post" id="inn-form">
            <input type="hidden" name="observer_user_id" id="observer_user_id_hidden" value="<?= h($observerUserId > 0 ? (string)$observerUserId : '') ?>">
            <input type="hidden" name="observer_auth_id" id="observer_auth_id_hidden" value="">
            <input type="hidden" name="observer_refresh_id" id="observer_refresh_id_hidden" value="">
            <input type="hidden" name="observer_domain" id="observer_domain_hidden" value="">
            <input type="hidden" name="observer_protocol" id="observer_protocol_hidden" value="">
            <input
                type="text"
                name="inn"
                id="inn"
                inputmode="numeric"
                autocomplete="off"
                maxlength="12"
                placeholder="Введите ИНН (10 или 12 цифр)"
                value="<?= h($inn) ?>"
                required
            >
            <button type="submit" id="submit-btn">Найти и привязать</button>
        </form>
        <div class="small">ID пользователя определяется автоматически через Bitrix24 JS API (<code>user.current</code>).</div>
        <div class="small"><a href="?bind_tabs=1">Зарегистрировать вкладки в лидах/сделках/компаниях/контактах</a></div>

        <?php foreach ($successes as $msg): ?>
            <div class="alert alert-success"><?= h($msg) ?></div>
        <?php endforeach; ?>

        <?php foreach ($errors as $msg): ?>
            <div class="alert alert-error"><?= h($msg) ?></div>
        <?php endforeach; ?>

        <?php if (is_array($resultInfo) && isset($resultInfo['companies']) && is_array($resultInfo['companies'])): ?>
            <div class="result">
                <div><strong>Поле ИНН (реквизиты):</strong> <?= h((string)$resultInfo['requisite_field_code']) ?></div>
                <div><strong>Найденные компании:</strong></div>
                <ul>
                    <?php foreach ($resultInfo['companies'] as $company): ?>
                        <?php
                            $companyId = (int)($company['ID'] ?? 0);
                            $companyTitle = (string)($company['TITLE'] ?? 'Без названия');
                            $portalBaseUrl = rtrim((string)($resultInfo['portal_base_url'] ?? ''), '/');
                            $companyUrl = $portalBaseUrl !== '' && $companyId > 0
                                ? $portalBaseUrl . '/crm/company/details/' . $companyId . '/'
                                : '';
                        ?>
                        <li>
                            #<?= h((string)$companyId) ?>
                            —
                            <?php if ($companyUrl !== ''): ?>
                                <a href="<?= h($companyUrl) ?>" target="_blank" rel="noopener noreferrer"><?= h($companyTitle) ?></a>
                            <?php else: ?>
                                <?= h($companyTitle) ?>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
</div>

<script src="https://api.bitrix24.com/api/v1/"></script>
<script>
    (function () {
        var input = document.getElementById('observer_user_id_hidden');
        var authIdInput = document.getElementById('observer_auth_id_hidden');
        var refreshIdInput = document.getElementById('observer_refresh_id_hidden');
        var domainInput = document.getElementById('observer_domain_hidden');
        var protocolInput = document.getElementById('observer_protocol_hidden');
        var form = document.getElementById('inn-form');
        var submitBtn = document.getElementById('submit-btn');
        var resolving = false;

        if (!input || !authIdInput || !refreshIdInput || !domainInput || !protocolInput || !form) {
            return;
        }

        function setSubmittingState(isBusy) {
            if (!submitBtn) {
                return;
            }
            submitBtn.disabled = isBusy;
            submitBtn.textContent = isBusy ? 'Определяем пользователя...' : 'Найти и привязать';
        }

        function fetchCurrentUserContext(callback) {
            if (!(window.BX24 && typeof BX24.init === 'function')) {
                callback({
                    id: '',
                    authId: '',
                    refreshId: '',
                    domain: '',
                    protocol: ''
                });
                return;
            }

            BX24.init(function () {
                var auth = typeof BX24.getAuth === 'function' ? BX24.getAuth() : null;
                BX24.callMethod('user.current', {}, function (result) {
                    if (!result || typeof result.error === 'function') {
                        callback({
                            id: '',
                            authId: auth && auth.access_token ? String(auth.access_token) : '',
                            refreshId: auth && auth.refresh_token ? String(auth.refresh_token) : '',
                            domain: auth && auth.domain ? String(auth.domain) : '',
                            protocol: 'https'
                        });
                        return;
                    }

                    var data = result.data && result.data();
                    callback({
                        id: data && data.ID ? String(data.ID) : '',
                        authId: auth && auth.access_token ? String(auth.access_token) : '',
                        refreshId: auth && auth.refresh_token ? String(auth.refresh_token) : '',
                        domain: auth && auth.domain ? String(auth.domain) : '',
                        protocol: 'https'
                    });
                });
            });
        }

        function applyContext(context) {
            input.value = context.id || '';
            authIdInput.value = context.authId || '';
            refreshIdInput.value = context.refreshId || '';
            domainInput.value = context.domain || '';
            protocolInput.value = context.protocol || 'https';
        }

        function hasUsableContext() {
            return Boolean(
                (input.value && Number(input.value) > 0) ||
                (authIdInput.value && domainInput.value)
            );
        }

        fetchCurrentUserContext(function (context) {
            applyContext(context);
        });

        form.addEventListener('submit', function (event) {
            if (resolving) {
                event.preventDefault();
                return;
            }

            if (hasUsableContext()) {
                return;
            }

            event.preventDefault();
            resolving = true;
            setSubmittingState(true);

            fetchCurrentUserContext(function (context) {
                resolving = false;
                setSubmittingState(false);
                applyContext(context);

                if (hasUsableContext()) {
                    form.requestSubmit();
                    return;
                }

                alert('Не удалось определить ID текущего пользователя Bitrix24. Откройте приложение внутри портала и попробуйте снова.');
            });
        });
    })();
</script>
</body>
</html>

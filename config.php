<?php
declare(strict_types=1);

return [
    // Bitrix24 portal URL without trailing slash.
    'portal_url' => 'https://devcrm.prom23.ru',

    // Local PHP built-in server port.
    'local_port' => 8000,

    // Absolute path to file where install auth data is saved.
    'auth_file' => __DIR__ . '/auth_data.json',

    // Optional: separate file for "admin/auth installer" mode.
    // If enabled, handler.php will read tokens from this file (not overwriting it).
    'admin_auth_file' => __DIR__ . '/admin_auth_data.json',

    // REST request timeout in seconds.
    'api_timeout' => 15,

    // SSL verification for cURL requests to Bitrix24 REST.
    // For local Windows dev you can temporarily set to false.
    'verify_ssl' => false,

    // Optional path to CA bundle file (cacert.pem).
    // Example: 'C:/php/cacert.pem'
    'ca_bundle' => '',

    // If true, we will not overwrite saved AUTH_* tokens from Bitrix24 with
    // tokens provided in $_REQUEST. That lets the app act with installer/admin rights,
    // while still using the current user's ID from PLACEMENT_OPTIONS / request params.
    'use_install_auth_as_admin' => true,
];

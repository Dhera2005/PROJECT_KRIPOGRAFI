<?php
session_start();
$donglePath = 'E:/CryptoAppDongle/dongle.key';
$expectedKey = 'CRYPTOAPP-DONGLE-SRI-2026-SECURE-KEY-025';
$valid = is_file($donglePath) && is_readable($donglePath)
    && hash_equals($expectedKey, trim((string) file_get_contents($donglePath)));
if (!$valid) {
    http_response_code(403);
    echo '<!doctype html><html lang="id"><meta charset="utf-8"><title>CryptoApp Terkunci</title><body style="background:#17152b;color:white;font:16px Arial;text-align:center;padding:15vh 20px"><h1>🔐 CryptoApp Terkunci</h1><p>USB Dongle tidak ditemukan atau kunci tidak valid.</p><p>Pasang USB Dongle yang benar, lalu muat ulang halaman.</p></body></html>';
    exit;
}
if (empty($_SESSION['cryptoapp_user'])) {
    header('Location: login.php');
    exit;
}
include __DIR__ . '/Index.html.html';

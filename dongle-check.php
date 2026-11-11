<?php
// Pemeriksaan USB Dongle di sisi server.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$donglePath = 'E:/CryptoAppDongle/dongle.key';
$expectedKey = 'CRYPTOAPP-DONGLE-SRI-2026-SECURE-KEY-025';

if (!is_file($donglePath) || !is_readable($donglePath)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'USB Dongle tidak ditemukan']);
    exit;
}

$actualKey = trim((string) file_get_contents($donglePath));
if (!hash_equals($expectedKey, $actualKey)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Kunci USB tidak valid']);
    exit;
}

echo json_encode(['status' => 'success', 'message' => 'USB Dongle valid']);

<?php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/db.php';

use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

function wa_json(array $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function wa_require_login(): array {
    if (empty($_SESSION['cryptoapp_user']['id'])) wa_json(['ok'=>false,'message'=>'Sesi login berakhir. Login ulang.'], 401);
    return $_SESSION['cryptoapp_user'];
}
function wa_serializer() {
    $manager = AttestationStatementSupportManager::create();
    $manager->add(NoneAttestationStatementSupport::create());
    return (new WebauthnSerializerFactory($manager))->create();
}
function wa_require_dongle(): void {
    $path = 'E:/CryptoAppDongle/dongle.key';
    $key = 'CRYPTOAPP-DONGLE-SRI-2026-SECURE-KEY-025';
    if (!is_file($path) || !is_readable($path) || !hash_equals($key, trim((string) file_get_contents($path)))) {
        wa_json(['ok'=>false,'message'=>'USB Dongle tidak ditemukan atau tidak valid.'], 403);
    }
}
wa_require_dongle();

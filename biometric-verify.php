<?php
declare(strict_types=1);
require __DIR__ . '/webauthn-common.php';
$user = wa_require_login();

use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\CredentialRecord;

try {
    $optionsSerialized = $_SESSION['wa_registration_options'] ?? null;
    unset($_SESSION['wa_registration_options']); // challenge hanya boleh dipakai sekali
    if (!$optionsSerialized) wa_json(['ok'=>false,'message'=>'Challenge tidak ditemukan. Muat ulang dan coba lagi.'], 400);
    $payload = file_get_contents('php://input');
    $credential = wa_serializer()->deserialize($payload, PublicKeyCredential::class, 'json');
    if (!$credential->response instanceof AuthenticatorAttestationResponse) {
        wa_json(['ok'=>false,'message'=>'Respons biometrik tidak valid.'], 400);
    }
    /** @var \Webauthn\PublicKeyCredentialCreationOptions $options */
    $options = unserialize($optionsSerialized, ['allowed_classes'=>true]);
    $factory = new CeremonyStepManagerFactory();
    // KHUSUS PENGEMBANGAN LOKAL
    $factory->setAllowedOrigins(['http://localhost']);
    $record = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
        ->check($credential->response, $options, 'localhost');
    $credentialId = rtrim(
        strtr(base64_encode($record->publicKeyCredentialId), '+/', '-_'),
        '='
    );
    $recordJson = wa_serializer()->serialize($record, 'json');
    $counter = (int) $record->counter;

    $stmt = $db->prepare('INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)');
    $stmt->bind_param('issi', $user['id'], $credentialId, $recordJson, $counter);
    $stmt->execute();
    wa_json(['ok'=>true,'message'=>'Biometrik Windows Hello berhasil didaftarkan.']);
} catch (Throwable $e) {
    wa_json(['ok'=>false,'message'=>'Verifikasi biometrik gagal: '.$e->getMessage()], 400);
}

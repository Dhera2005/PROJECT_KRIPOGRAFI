<?php
declare(strict_types=1);
require __DIR__ . '/webauthn-common.php';

use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredential;

try {
    wa_require_dongle();

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        wa_json(['ok' => false, 'message' => 'Metode tidak diizinkan.'], 405);
    }

    // Ambil challenge yang sebelumnya dibuat
    $optionsSerialized = $_SESSION['wa_login_options'] ?? null;
    $userId = $_SESSION['wa_login_user_id'] ?? null;

    unset($_SESSION['wa_login_options'], $_SESSION['wa_login_user_id']);

    if (!$optionsSerialized || !$userId) {
        wa_json(['ok' => false, 'message' => 'Sesi login berakhir. Silakan ulangi.'], 400);
    }

    $options = unserialize($optionsSerialized, ['allowed_classes' => true]);

    if (!$options instanceof \Webauthn\PublicKeyCredentialRequestOptions) {
        wa_json(['ok' => false, 'message' => 'Data challenge tidak valid.'], 400);
    }

    // Baca respons dari Windows Hello
    $payload = file_get_contents('php://input');

    $credential = wa_serializer()->deserialize(
        $payload,
        PublicKeyCredential::class,
        'json'
    );

    if (!$credential->response instanceof AuthenticatorAssertionResponse) {
        wa_json(['ok' => false, 'message' => 'Respons Windows Hello tidak valid.'], 400);
    }

    // Cari data kredensial milik pengguna
    $stmt = $db->prepare(
        'SELECT id, username FROM users WHERE id = ? LIMIT 1'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if (!$user) {
        wa_json(['ok' => false, 'message' => 'Pengguna tidak ditemukan.'], 404);
    }

    $stmt = $db->prepare(
        'SELECT id, public_key FROM webauthn_credentials WHERE user_id = ?'
    );
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    $credentialRow = null;
    $record = null;

    while ($row = $result->fetch_assoc()) {
        $storedRecord = wa_serializer()->deserialize(
            $row['public_key'],
            CredentialRecord::class,
            'json'
        );

        if (hash_equals(
            $storedRecord->publicKeyCredentialId,
            $credential->rawId
        )) {
            $credentialRow = $row;
            $record = $storedRecord;
            break;
        }
    }

    if (!$record || !$credentialRow) {
        wa_json(['ok' => false, 'message' => 'Kredensial Windows Hello tidak cocok.'], 401);
    }

    // Periksa tanda tangan dan challenge WebAuthn
    $factory = new CeremonyStepManagerFactory();
    $factory->setAllowedOrigins(['http://localhost']);

    $updatedRecord = AuthenticatorAssertionResponseValidator::create(
        $factory->requestCeremony()
    )->check(
        $record,
        $credential->response,
        $options,
        'localhost',
        $record->userHandle
    );

    // Simpan counter terbaru
    $recordJson = wa_serializer()->serialize($updatedRecord, 'json');
    $counter = (int) $updatedRecord->counter;
    $rowId = (int) $credentialRow['id'];

    $stmt = $db->prepare(
        'UPDATE webauthn_credentials
         SET public_key = ?, sign_count = ?
         WHERE id = ? AND user_id = ?'
    );
    $stmt->bind_param('siii', $recordJson, $counter, $rowId, $userId);
    $stmt->execute();

    // Buat sesi login
    session_regenerate_id(true);

    $_SESSION['cryptoapp_user'] = [
        'id' => (int) $user['id'],
        'username' => $user['username']
    ];

    wa_json([
        'ok' => true,
        'message' => 'Login Windows Hello berhasil.',
        'redirect' => 'index.php'
    ]);

} catch (Throwable $e) {
    wa_json([
        'ok' => false,
        'message' => 'Verifikasi gagal: ' . $e->getMessage()
    ], 400);
}

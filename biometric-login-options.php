<?php
declare(strict_types=1);
require __DIR__ . '/webauthn-common.php';

use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

try {
    // Periksa USB dongle seperti pada proses login biasa
    wa_require_dongle();

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        wa_json(['ok' => false, 'message' => 'Metode tidak diizinkan.'], 405);
    }

    $input = json_decode(file_get_contents('php://input'), true);
    $username = trim($input['username'] ?? '');

    if ($username === '') {
        wa_json(['ok' => false, 'message' => 'Username wajib diisi.'], 400);
    }

    // Cari pengguna
    $stmt = $db->prepare(
        'SELECT id FROM users WHERE username = ? LIMIT 1'
    );
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if (!$user) {
        wa_json(['ok' => false, 'message' => 'Akun tidak ditemukan.'], 404);
    }

    // Ambil kredensial Windows Hello
    $stmt = $db->prepare(
        'SELECT credential_id FROM webauthn_credentials WHERE user_id = ?'
    );
    $stmt->bind_param('i', $user['id']);
    $stmt->execute();
    $result = $stmt->get_result();

    $allowCredentials = [];

    while ($row = $result->fetch_assoc()) {
        $id = $row['credential_id'];
        $id .= str_repeat('=', (4 - strlen($id) % 4) % 4);

        $rawId = base64_decode(strtr($id, '-_', '+/'), true);

        if ($rawId === false) {
            continue;
        }

        $allowCredentials[] = PublicKeyCredentialDescriptor::create(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $rawId
        );
    }

    if (count($allowCredentials) === 0) {
        wa_json([
            'ok' => false,
            'message' => 'Windows Hello belum terdaftar untuk akun ini.'
        ], 404);
    }

    // Buat challenge baru
    $options = PublicKeyCredentialRequestOptions::create(
        random_bytes(32),
        'localhost',
        $allowCredentials,
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
    );

    $_SESSION['wa_login_options'] = serialize($options);
    $_SESSION['wa_login_user_id'] = (int) $user['id'];

    header('Content-Type: application/json; charset=utf-8');
    echo wa_serializer()->serialize($options, 'json');

} catch (Throwable $e) {
    wa_json([
        'ok' => false,
        'message' => 'Gagal menyiapkan login Windows Hello: ' . $e->getMessage()
    ], 500);
}

<?php
session_start();
if (empty($_SESSION['cryptoapp_user']['id'])) {
    http_response_code(401);
    exit('Silakan login terlebih dahulu melalui CryptoApp.');
}
require __DIR__ . '/db.php';
require __DIR__ . '/crypto_config.php';

$userId = (int) $_SESSION['cryptoapp_user']['id'];
$key = hex2bin(CRYPTOAPP_MESSAGE_KEY_HEX);
if ($key === false || strlen($key) !== 32) {
    http_response_code(500);
    exit('Kunci enkripsi harus berupa 64 karakter hex (32 byte).');
}

$notice = '';
$decrypted = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'save') {
        $plain = trim($_POST['message'] ?? '');
        if ($plain === '') {
            $notice = 'Pesan tidak boleh kosong.';
        } else {
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            if ($cipher === false) {
                $notice = 'Enkripsi gagal.';
            } else {
                $cipherB64 = base64_encode($cipher);
                $ivB64 = base64_encode($iv);
                $tagB64 = base64_encode($tag);
                $alg = 'AES-256-GCM';
                $stmt = $db->prepare('INSERT INTO important_messages (user_id, encrypted_message, encryption_algorithm, iv, auth_tag) VALUES (?, ?, ?, ?, ?)');
                $stmt->bind_param('issss', $userId, $cipherB64, $alg, $ivB64, $tagB64);
                $stmt->execute();
                $notice = 'Pesan berhasil dienkripsi dan disimpan ke database.';
            }
        }
    } elseif ($action === 'decrypt') {
        $messageId = (int) ($_POST['message_id'] ?? 0);
        $stmt = $db->prepare('SELECT encrypted_message, iv, auth_tag FROM important_messages WHERE id = ? AND user_id = ?');
        $stmt->bind_param('ii', $messageId, $userId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        if ($row) {
            $cipher = base64_decode($row['encrypted_message'], true);
            $iv = base64_decode($row['iv'], true);
            $tag = base64_decode($row['auth_tag'], true);
            $plain = ($cipher !== false && $iv !== false && $tag !== false)
                ? openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag)
                : false;
            $decrypted = ($plain === false) ? 'Gagal dekripsi: kunci atau data tidak valid.' : $plain;
        } else {
            $decrypted = 'Pesan tidak ditemukan.';
        }
    }
}

$stmt = $db->prepare('SELECT id, encryption_algorithm, created_at FROM important_messages WHERE user_id = ? ORDER BY id DESC');
$stmt->bind_param('i', $userId);
$stmt->execute();
$messages = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
function h($value) { return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pesan Penting - CryptoApp</title>
<style>body{font-family:Arial,sans-serif;background:#f4f1fb;color:#28233d;margin:0;padding:24px}.wrap{max-width:850px;margin:auto;background:white;padding:25px;border-radius:16px;box-shadow:0 8px 30px #21134a18}h1{color:#49318c}textarea{width:100%;min-height:110px;padding:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:8px}button{background:#6746c3;color:#fff;border:0;border-radius:8px;padding:10px 16px;cursor:pointer;margin-top:10px}.notice{background:#eee9ff;padding:12px;border-radius:8px;margin:14px 0}.item{border:1px solid #e4def2;border-radius:9px;padding:13px;margin:10px 0;display:flex;justify-content:space-between;gap:12px;align-items:center}.muted{color:#777;font-size:13px}a{color:#5b3ba5}</style></head><body><main class="wrap">
<h1>🔐 Pesan Penting Terenkripsi</h1><p>Pesan dienkripsi dengan AES-256-GCM sebelum disimpan ke MySQL.</p>
<?php if ($notice): ?><div class="notice"><?=h($notice)?></div><?php endif; ?>
<form method="post"><input type="hidden" name="action" value="save"><label for="message"><b>Tulis pesan penting</b></label><p><textarea id="message" name="message" required placeholder="Masukkan pesan penting..."></textarea></p><button type="submit">Enkripsi & Simpan</button></form>
<?php if ($decrypted !== null): ?><div class="notice"><b>Hasil dekripsi:</b><p><?=nl2br(h($decrypted))?></p></div><?php endif; ?>
<h2>Daftar pesan tersimpan</h2>
<?php if (!$messages): ?><p class="muted">Belum ada pesan penting.</p><?php endif; ?>
<?php foreach ($messages as $m): ?><div class="item"><div><b>Pesan #<?=h($m['id'])?></b><div class="muted"><?=h($m['encryption_algorithm'])?> • <?=h($m['created_at'])?></div></div><form method="post"><input type="hidden" name="action" value="decrypt"><input type="hidden" name="message_id" value="<?=h($m['id'])?>"><button type="submit">Dekripsi</button></form></div><?php endforeach; ?>
<p><a href="index.php">← Kembali ke CryptoApp</a></p>
</main></body></html>

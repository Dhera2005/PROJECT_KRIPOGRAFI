<?php
session_start();
if (empty($_SESSION['cryptoapp_user']['id'])) {
    http_response_code(401);
    exit('Silakan login terlebih dahulu melalui CryptoApp.');
}
require __DIR__ . '/db.php';
$userId = (int) $_SESSION['cryptoapp_user']['id'];
$storageDir = __DIR__ . '/protected_assets';
if (!is_dir($storageDir)) { mkdir($storageDir, 0755, true); }
// Cegah akses langsung ke file aset melalui URL (Apache).
$denyFile = $storageDir . '/.htaccess';
if (!file_exists($denyFile)) { file_put_contents($denyFile, "Require all denied\n"); }
function h($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
$notice = '';
$verification = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'add') {
    if (!isset($_FILES['asset']) || $_FILES['asset']['error'] !== UPLOAD_ERR_OK) {
        $notice = 'Pilih file aset terlebih dahulu.';
    } elseif ($_FILES['asset']['size'] > 10 * 1024 * 1024) {
        $notice = 'Ukuran file maksimal 10 MB.';
    } else {
        $originalName = basename($_FILES['asset']['name']);
        $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', $originalName);
        $storedName = bin2hex(random_bytes(12)) . '_' . $safeName;
        $destination = $storageDir . '/' . $storedName;
        if (!move_uploaded_file($_FILES['asset']['tmp_name'], $destination)) {
            $notice = 'File gagal disimpan.';
        } else {
            $assetHash = hash_file('sha256', $destination);
            $prevStmt = $db->prepare('SELECT block_hash FROM blockchain_assets WHERE user_id = ? ORDER BY id DESC LIMIT 1');
            $prevStmt->bind_param('i', $userId);
            $prevStmt->execute();
            $prevRow = $prevStmt->get_result()->fetch_assoc();
            $previousHash = $prevRow ? $prevRow['block_hash'] : str_repeat('0', 64);
            $createdAt = date('Y-m-d H:i:s');
            $blockPayload = $userId . '|' . $safeName . '|' . $assetHash . '|' . $previousHash . '|' . $createdAt;
            $blockHash = hash('sha256', $blockPayload);
            $relativePath = 'protected_assets/' . $storedName;
            $stmt = $db->prepare('INSERT INTO blockchain_assets (user_id, asset_name, stored_path, asset_hash, previous_hash, block_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
            $stmt->bind_param('issssss', $userId, $safeName, $relativePath, $assetHash, $previousHash, $blockHash, $createdAt);
            if ($stmt->execute()) {
                $notice = 'Aset berhasil disimpan dan dicatat ke dalam blok blockchain sederhana.';
            } else {
                @unlink($destination);
                $notice = 'Gagal mencatat aset ke database.';
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'verify') {
    $assetId = (int)($_POST['asset_id'] ?? 0);
    $stmt = $db->prepare('SELECT id, asset_name, stored_path, asset_hash, previous_hash, block_hash, created_at FROM blockchain_assets WHERE id = ? AND user_id = ?');
    $stmt->bind_param('ii', $assetId, $userId);
    $stmt->execute();
    $record = $stmt->get_result()->fetch_assoc();
    if (!$record) {
        $verification = 'Catatan aset tidak ditemukan.';
    } else {
        $fullPath = __DIR__ . '/' . $record['stored_path'];
        if (!is_file($fullPath)) {
            $verification = 'GAGAL: file aset tidak ditemukan.';
        } else {
            $currentAssetHash = hash_file('sha256', $fullPath);
            $payload = $userId . '|' . $record['asset_name'] . '|' . $record['asset_hash'] . '|' . $record['previous_hash'] . '|' . $record['created_at'];
            $recalculatedBlockHash = hash('sha256', $payload);
            $chainOK = hash_equals($record['block_hash'], $recalculatedBlockHash);
            $fileOK = hash_equals($record['asset_hash'], $currentAssetHash);
            $verification = ($chainOK && $fileOK)
                ? 'VALID: file masih sama dan hash blok cocok.'
                : 'PERINGATAN: file atau catatan blok telah berubah.';
        }
    }
}

$stmt = $db->prepare('SELECT id, asset_name, asset_hash, previous_hash, block_hash, created_at FROM blockchain_assets WHERE user_id = ? ORDER BY id DESC');
$stmt->bind_param('i', $userId);
$stmt->execute();
$assets = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
?>
<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Blockchain Aset - CryptoApp</title>
<style>
body{font-family:Arial,sans-serif;background:#f4f1fb;color:#28233d;margin:0;padding:24px}.wrap{max-width:900px;margin:auto;background:#fff;padding:25px;border-radius:16px;box-shadow:0 8px 30px #21134a18}h1{color:#49318c}button{background:#6746c3;color:#fff;border:0;border-radius:8px;padding:10px 16px;cursor:pointer}.notice{background:#eee9ff;padding:12px;border-radius:8px;margin:14px 0}.item{border:1px solid #e4def2;border-radius:9px;padding:14px;margin:12px 0;overflow-wrap:anywhere}.muted{color:#777;font-size:13px}.hash{font-family:monospace;font-size:12px;overflow-wrap:anywhere}input[type=file]{margin:12px 0}a{color:#5b3ba5}
</style></head><body><main class="wrap">
<h1>⛓️ Blockchain Aset CryptoApp</h1>
<p>Setiap aset dicatat menggunakan hash SHA-256. Hash blok menyimpan hash blok sebelumnya sehingga perubahan data dapat terdeteksi.</p>
<?php if($notice): ?><div class="notice"><?=h($notice)?></div><?php endif; ?>
<?php if($verification !== null): ?><div class="notice"><b>Hasil verifikasi:</b> <?=h($verification)?></div><?php endif; ?>
<h2>Tambahkan aset penting</h2>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="add"><p><input type="file" name="asset" required></p><p class="muted">Maksimal 10 MB. File disimpan di folder terlindungi dan hash SHA-256 dicatat ke blockchain sederhana.</p><button type="submit">Simpan Aset ke Blockchain</button></form>
<h2>Riwayat blok aset</h2>
<?php if(!$assets): ?><p class="muted">Belum ada aset yang dicatat.</p><?php endif; ?>
<?php foreach($assets as $a): ?><section class="item"><b>Blok #<?=h($a['id'])?> — <?=h($a['asset_name'])?></b><p class="muted">Waktu: <?=h($a['created_at'])?></p><p class="hash"><b>Asset SHA-256:</b><br><?=h($a['asset_hash'])?></p><p class="hash"><b>Previous hash:</b><br><?=h($a['previous_hash'])?></p><p class="hash"><b>Block hash:</b><br><?=h($a['block_hash'])?></p><form method="post"><input type="hidden" name="action" value="verify"><input type="hidden" name="asset_id" value="<?=h($a['id'])?>"><button type="submit">Verifikasi Integritas</button></form></section><?php endforeach; ?>
<p><a href="index.php">← Kembali ke CryptoApp</a></p>
</main></body></html>

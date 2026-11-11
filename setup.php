<?php
// Jalankan sekali melalui http://localhost/CryptoApp/setup.php untuk membuat database dan akun awal.
$donglePath = 'E:/CryptoAppDongle/dongle.key';
$expectedKey = 'CRYPTOAPP-DONGLE-SRI-2026-SECURE-KEY-025';
if (!is_file($donglePath) || !is_readable($donglePath) || !hash_equals($expectedKey, trim((string)file_get_contents($donglePath)))) {
    http_response_code(403); exit('USB Dongle tidak valid.');
}
$notice = '';
try {
    $conn = new mysqli('localhost', 'root', '');
    $conn->set_charset('utf8mb4');
    $conn->query("CREATE DATABASE IF NOT EXISTS cryptoapp_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $conn->select_db('cryptoapp_db');
    $conn->query("CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(80) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        if (!preg_match('/^[a-zA-Z0-9_.-]{3,80}$/', $username) || strlen($password) < 8) {
            $notice = 'Username minimal 3 karakter (huruf/angka/._-) dan password minimal 8 karakter.';
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare('INSERT INTO users (username,password_hash) VALUES (?,?)');
            $stmt->bind_param('ss', $username, $hash);
            $stmt->execute();
            $notice = 'Akun berhasil dibuat. Hapus atau ubah nama file setup.php demi keamanan, lalu login.';
        }
    } else { $notice = 'Database dan tabel users siap. Buat akun pertama di bawah.'; }
} catch (Throwable $e) { $notice = 'Proses gagal: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Setup CryptoApp</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#17152b,#30245b);font:15px Arial;color:#292443}.panel{width:min(420px,92vw);background:#fff;padding:32px;border-radius:18px;box-shadow:0 20px 60px #0005}h1{margin-top:0;color:#30245b}label{display:block;margin:14px 0 6px;font-weight:bold}input{width:100%;padding:12px;border:1px solid #d9d5e8;border-radius:9px}button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:9px;background:#6c4bd2;color:white;font-weight:bold;cursor:pointer}.notice{padding:12px;background:#f1edff;border-radius:9px;line-height:1.5}</style></head><body><main class="panel"><h1>🔐 Setup CryptoApp</h1><p class="notice"><?= htmlspecialchars($notice, ENT_QUOTES, 'UTF-8') ?></p><form method="post"><label>Username</label><input name="username" required minlength="3" autocomplete="username"><label>Password (minimal 8 karakter)</label><input type="password" name="password" required minlength="8" autocomplete="new-password"><button type="submit">Buat Akun</button></form><p><a href="login.php">Ke halaman login</a></p></main></body></html>

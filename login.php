<?php
session_start();
$donglePath = 'E:/CryptoAppDongle/dongle.key';
$expectedKey = 'CRYPTOAPP-DONGLE-SRI-2026-SECURE-KEY-025';
if (!is_file($donglePath) || !is_readable($donglePath) || !hash_equals($expectedKey, trim((string)file_get_contents($donglePath)))) {
    http_response_code(403); exit('🔐 CryptoApp terkunci. Pasang USB Dongle yang valid.');
}
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        require __DIR__ . '/db.php';
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $stmt = $db->prepare('SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1');
        $stmt->bind_param('s', $username); $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        if ($user && password_verify($password, $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['cryptoapp_user'] = ['id' => (int)$user['id'], 'username' => $user['username']];
            header('Location: index.php'); exit;
        }
        $error = 'Username atau password salah.';
    } catch (Throwable $e) { $error = 'Database belum disiapkan. Buka setup.php terlebih dahulu.'; }
}
?>
<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login CryptoApp</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#17152b,#30245b);font:15px Arial;color:#292443}.panel{width:min(420px,92vw);background:#fff;padding:36px;border-radius:20px;box-shadow:0 20px 60px #0005}.logo{text-align:center;font-size:38px}h1{text-align:center;color:#30245b;margin:8px 0}p.sub{text-align:center;color:#777;margin-bottom:26px}label{display:block;margin:14px 0 6px;font-weight:bold}input{width:100%;padding:13px;border:1px solid #d9d5e8;border-radius:9px;font-size:15px}button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:9px;background:#6c4bd2;color:white;font-weight:bold;font-size:15px;cursor:pointer}.error{background:#ffe9ed;color:#a51f40;padding:11px;border-radius:8px}.foot{text-align:center;color:#888;font-size:12px;margin-top:20px}</style></head><body><main class="panel"><div class="logo">🔐</div><h1>CryptoApp</h1><p class="sub">Login aman dengan verifikasi password kriptografis</p><?php if($error): ?><p class="error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?><form method="post"><label>Username</label><input id="username" name="username" required autocomplete="username"<label>Password</label><input type="password" name="password" required autocomplete="current-password"><button type="submit">Masuk ke CryptoApp</button><button type="button" id="biometricBtn">
    Login dengan Windows Hello
</button></form><div class="foot">Akses dilindungi USB Dongle • Password disimpan menggunakan password_hash()</div></main>

<script>
const biometricBtn = document.getElementById('biometricBtn');

function base64urlToBuffer(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

biometricBtn.addEventListener('click', async () => {
    try {
        const username = document.getElementById('username').value.trim();

        if (!username) {
            alert('Masukkan username terlebih dahulu.');
            return;
        }

        biometricBtn.disabled = true;
        biometricBtn.textContent = 'Memproses Windows Hello...';

        const optionsResponse = await fetch('biometric-login-options.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });

        const options = await optionsResponse.json();

        if (!optionsResponse.ok || !options.challenge) {
            throw new Error(options.message || 'Gagal mengambil data autentikasi.');
        }

        options.challenge = base64urlToBuffer(options.challenge);

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(item => ({
                ...item,
                id: base64urlToBuffer(item.id)
            }));
        }

        const assertion = await navigator.credentials.get({
            publicKey: options
        });

        const payload = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null
            }
        };

        const verifyResponse = await fetch('biometric-login-verify.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        const result = await verifyResponse.json();

        if (!verifyResponse.ok || !result.ok) {
            throw new Error(result.message || 'Verifikasi Windows Hello gagal.');
        }

        window.location.href = result.redirect || 'index.php';

    } catch (error) {
        alert(error.message || 'Login Windows Hello gagal.');
    } finally {
        biometricBtn.disabled = false;
        biometricBtn.textContent = 'Login dengan Windows Hello';
    }
});
</script>
</body>
</html>

</body></html>

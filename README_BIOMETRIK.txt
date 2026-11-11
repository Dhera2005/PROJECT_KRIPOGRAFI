CRYPTOAPP - PENDAFTARAN WINDOWS HELLO (TAHAP BIOMETRIK)

Prasyarat:
- File vendor/ sudah ada di folder CryptoApp (hasil composer require web-auth/webauthn-lib).
- Login CryptoApp dan pemeriksaan USB dongle sudah berfungsi.
- Apache dan MySQL aktif.
- Akses aplikasi melalui http://localhost/CryptoApp/ (jangan buka file HTML langsung).

Pemasangan:
1. Salin 4 file berikut ke C:\xampp\htdocs\CryptoApp: biometric.php, webauthn-common.php, biometric-options.php, biometric-verify.php.
2. Di phpMyAdmin, pilih database cryptoapp_db lalu jalankan SQL:

ALTER TABLE webauthn_credentials
  MODIFY credential_id VARCHAR(512) NOT NULL,
  MODIFY public_key LONGTEXT NOT NULL;

3. Login ke CryptoApp.
4. Buka http://localhost/CryptoApp/biometric.php
5. Klik Daftarkan Windows Hello dan ikuti dialog Windows.

Catatan:
- Tahap ini mendaftarkan dan memverifikasi credential biometrik di server PHP menggunakan web-auth/webauthn-lib.
- Ini belum mengubah alur login agar passkey menjadi faktor wajib. Login passkey akan disambungkan pada tahap berikutnya setelah pendaftaran berhasil.
- WebAuthn tidak mengirim atau menyimpan data sidik jari/wajah ke aplikasi. Windows Hello menyimpan kunci privat pada perangkat; server menyimpan credential/public key.
- Untuk demo localhost, RP ID adalah localhost dan origin yang dipakai browser harus http://localhost.

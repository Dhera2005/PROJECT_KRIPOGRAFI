<?php
// Konfigurasi standar XAMPP. Ubah jika MySQL Anda memakai password.
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli('localhost', 'root', '', 'cryptoapp_db');
$db->set_charset('utf8mb4');

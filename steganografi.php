<?php
session_start();
if (empty($_SESSION['cryptoapp_user']['id'])) { http_response_code(401); exit('Silakan login terlebih dahulu melalui CryptoApp.'); }
require __DIR__ . '/db.php';
$userId = (int)$_SESSION['cryptoapp_user']['id'];
$uploadDir = __DIR__ . '/uploads_stego';
if (!is_dir($uploadDir)) { mkdir($uploadDir, 0755, true); }
$notice = '';
$decoded = null;
$originalImage = null;
$stegoImage = null;

function h($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function hideMessageInPng($im, string $message): bool {
    $payload = pack('N', strlen($message)) . $message;
    $bits = '';
    foreach (str_split($payload) as $byte) $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
    $w = imagesx($im); $h = imagesy($im);
    if (strlen($bits) > $w * $h * 3) return false;
    $i = 0;
    for ($y=0; $y<$h && $i<strlen($bits); $y++) {
        for ($x=0; $x<$w && $i<strlen($bits); $x++) {
            $c = imagecolorat($im, $x, $y);
            $r = ($c >> 16) & 255; $g = ($c >> 8) & 255; $b = $c & 255;
            foreach (['r','g','b'] as $ch) {
                if ($i >= strlen($bits)) break;
                $$ch = ($$ch & 254) | (int)$bits[$i++];
            }
            imagesetpixel($im, $x, $y, imagecolorallocate($im, $r, $g, $b));
        }
    }
    return true;
}
function extractMessageFromPng($im) {
    $w=imagesx($im); $h=imagesy($im); $bits=''; $bytes=''; $length=null; $i=0;
    for ($y=0; $y<$h; $y++) for ($x=0; $x<$w; $x++) {
        $c=imagecolorat($im,$x,$y);
        foreach ([($c>>16)&255,($c>>8)&255,$c&255] as $v) {
            $bits .= (string)($v & 1);
            if (strlen($bits)===8) {
                $bytes .= chr(bindec($bits)); $bits='';
                if (strlen($bytes)===4 && $length===null) {
                    $u=unpack('Nlen',$bytes); $length=$u['len']; $bytes='';
                    if ($length > 10000000) return false;
                    if ($length===0) return '';
                } elseif ($length!==null && strlen($bytes)===$length) return $bytes;
            }
        }
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='hide') {
    $message=trim($_POST['message']??'');
    if ($message==='') $notice='Masukkan pesan yang ingin disembunyikan.';
    elseif (!isset($_FILES['image']) || $_FILES['image']['error']!==UPLOAD_ERR_OK) $notice='Pilih gambar PNG terlebih dahulu.';
    else {
        $info=@getimagesize($_FILES['image']['tmp_name']);
        if (!$info || $info[2]!==IMAGETYPE_PNG) $notice='Format yang didukung hanya PNG.';
        elseif ($_FILES['image']['size']>8*1024*1024) $notice='Ukuran gambar maksimal 8 MB.';
        else {
            $im=@imagecreatefrompng($_FILES['image']['tmp_name']);
            if (!$im) $notice='Gambar PNG tidak dapat dibaca.';
            elseif (!hideMessageInPng($im,$message)) { $notice='Pesan terlalu panjang untuk ukuran gambar. Gunakan gambar PNG yang lebih besar atau pesan lebih pendek.'; imagedestroy($im); }
            else {
                $filename='stego_'.$userId.'_'.bin2hex(random_bytes(8)).'.png';
                $full=$uploadDir.'/'.$filename;
                if (imagepng($im, $full)) {
                    $relative = 'uploads_stego/' . $filename;

                    $originalImage = 'uploads_stego/original_' . $filename;
                    copy($_FILES['image']['tmp_name'], __DIR__ . '/' . $originalImage);

                    $stegoImage = $relative;

                    $stmt = $db->prepare('INSERT INTO image_messages (user_id,image_path,created_at) VALUES (?, ?, NOW())');
                    $stmt->bind_param('is', $userId, $relative);
                    $stmt->execute();

                    $notice = 'Pesan berhasil disembunyikan ke dalam gambar dan disimpan.';
                } else {
                    $notice = 'Gagal menyimpan gambar hasil steganografi.';
                }
                imagedestroy($im);
            }
        }
    }
}
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['action']??'')==='extract') {
    $id=(int)($_POST['image_id']??0);
    $stmt=$db->prepare('SELECT image_path FROM image_messages WHERE id=? AND user_id=?');
    $stmt->bind_param('ii',$id,$userId); $stmt->execute(); $row=$stmt->get_result()->fetch_assoc();
    if (!$row) $decoded='Gambar tidak ditemukan.';
    else {
        $path=__DIR__.'/'.$row['image_path']; $im=is_file($path)?@imagecreatefrompng($path):false;
        if (!$im) $decoded='File gambar tidak ditemukan atau tidak dapat dibaca.';
        else { $result=extractMessageFromPng($im); imagedestroy($im); $decoded=($result===false)?'Pesan tidak ditemukan atau gambar tidak valid.':$result; }
    }
}
$stmt=$db->prepare('SELECT id,image_path,created_at FROM image_messages WHERE user_id=? ORDER BY id DESC');
$stmt->bind_param('i',$userId); $stmt->execute(); $images=$stmt->get_result()->fetch_all(MYSQLI_ASSOC);
?>
<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Steganografi - CryptoApp</title>
<style>body{font-family:Arial,sans-serif;background:#f4f1fb;color:#28233d;margin:0;padding:24px}.wrap{max-width:850px;margin:auto;background:#fff;padding:25px;border-radius:16px;box-shadow:0 8px 30px #21134a18}h1{color:#49318c}textarea{width:100%;min-height:100px;padding:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:8px}input[type=file]{margin:12px 0}button{background:#6746c3;color:white;border:0;border-radius:8px;padding:10px 16px;cursor:pointer}.notice{background:#eee9ff;padding:12px;border-radius:8px;margin:14px 0}.item{border:1px solid #e4def2;border-radius:9px;padding:13px;margin:10px 0;display:flex;justify-content:space-between;gap:12px;align-items:center}.muted{color:#777;font-size:13px}a{color:#5b3ba5}</style></head><body><main class="wrap">
<h1>🖼️ Steganografi Pesan Gambar</h1><p>Pesan disisipkan ke dalam bit paling rendah (LSB) warna RGB pada gambar PNG. Gambar hasil tetap berupa PNG.</p>
<?php if($notice): ?><div class="notice"><?=h($notice)?></div><?php endif; ?>
<form method="post" enctype="multipart/form-data"><input type="hidden" name="action" value="hide"><p><b>Pilih gambar PNG</b></p><input type="file" name="image" accept="image/png" required><p><b>Pesan yang akan disembunyikan</b></p><textarea name="message" required placeholder="Tulis pesan rahasia..."></textarea><p><button type="submit">Sembunyikan Pesan</button></p></form>
<?php if ($stegoImage): ?>
<div class="notice">
    <h2>Hasil Steganografi</h2>

    <h3>1. Gambar Asli</h3>
    <img src="<?=h($originalImage)?>" style="max-width:300px;width:100%;border-radius:10px">

    <h3>2. Gambar Setelah Pesan Disisipkan</h3>
    <img src="<?=h($stegoImage)?>" style="max-width:300px;width:100%;border-radius:10px">

    <p>
        <a href="<?=h($stegoImage)?>" download>
            Unduh Gambar Hasil
        </a>
    </p>
</div>
<?php endif; ?>
<?php if($decoded!==null): ?><div class="notice"><b>Hasil ekstraksi:</b><p><?=nl2br(h($decoded))?></p></div><?php endif; ?>
<h2>Gambar tersimpan</h2><?php if(!$images): ?><p class="muted">Belum ada gambar.</p><?php endif; ?>
<?php foreach($images as $im): ?><div class="item"><div><b>Gambar #<?=h($im['id'])?></b><div class="muted"><?=h($im['created_at'])?></div><a href="<?=h($im['image_path'])?>" target="_blank">Lihat gambar hasil</a></div><form method="post"><input type="hidden" name="action" value="extract"><input type="hidden" name="image_id" value="<?=h($im['id'])?>"><button type="submit">Ekstrak Pesan</button></form></div><?php endforeach; ?>
<p><a href="index.php">← Kembali ke CryptoApp</a></p></main></body></html>

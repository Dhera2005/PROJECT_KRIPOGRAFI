/* CRYPTOGRAPHY WEB APP: Caesar - Vigenere - AES - RSA - Super Encryption */

/* ================= HELPERS ================= */

const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const EMPTY = `<p class="empty-process">Jalankan enkripsi atau dekripsi untuk melihat proses.</p>`;
const esc = t => t.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
const line = html => `<div class="process-line">${html}</div>`;
const proc = (title, lines) => `<div class="process-title">${title}</div>` + lines.map(line).join("");

const pageInfo = {
    caesar:   ["Caesar Cipher", "Algoritma kriptografi klasik berbasis pergeseran karakter.", "KRIPTOGRAFI KLASIK"],
    vigenere: ["Vigenère Cipher", "Algoritma kriptografi klasik menggunakan kata kunci.", "KRIPTOGRAFI KLASIK"],
    aes:      ["AES-256-GCM", "Algoritma kriptografi modern menggunakan kunci 256-bit.", "KRIPTOGRAFI MODERN"],
    rsa:      ["RSA-OAEP", "Algoritma kriptografi modern menggunakan public dan private key.", "KRIPTOGRAFI MODERN"],
    super:    ["Super Enkripsi", "Gabungan Caesar → Vigenère → AES → RSA.", "SUPER ENKRIPSI"],
    filecrypto: ["Enkripsi File", "Pengamanan file menggunakan AES-256-CTR dan HMAC-SHA256.", "KRIPTOGRAFI FILE"]
};

function showPage(id, btn) {
    document.querySelectorAll(".page").forEach(p => p.classList.toggle("active-page", p.id === id));
    document.querySelectorAll(".menu-btn").forEach(b => b.classList.toggle("active", b === btn));
    ["page-title", "page-description", "type-badge"].forEach((el, i) => $(el).textContent = pageInfo[id][i]);
}

function showToast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2500);
}

function copyText(id) {
    const v = $(id).value;
    if (!v) return showToast("Tidak ada hasil untuk disalin.");
    navigator.clipboard.writeText(v);
    showToast("Hasil berhasil disalin.");
}

const clearFields = (prefix, empty = EMPTY) => {
    $(prefix + "-input").value = "";
    if ($(prefix + "-output")) $(prefix + "-output").value = "";
    $(prefix + "-process").innerHTML = empty;
};

/* ================= ENCODING ================= */

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(bin);
}

const base64ToArrayBuffer = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
const arrayBufferToHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");

/* ================= CLASSIC CIPHERS ================= */

const shiftChar = (c, shift, base) => String.fromCharCode((((c.charCodeAt(0) - base + shift) % 26) + 26) % 26 + base);

function caesarTransform(text, shift, decrypt = false) {
    if (decrypt) shift = -shift;
    return [...text].map(c =>
        /[A-Z]/.test(c) ? shiftChar(c, shift, 65) :
        /[a-z]/.test(c) ? shiftChar(c, shift, 97) : c
    ).join("");
}

const cleanVigenereKey = key => key.toUpperCase().replace(/[^A-Z]/g, "");

function vigenereTransform(text, key, decrypt = false) {
    key = cleanVigenereKey(key);
    if (!key) throw new Error("Key Vigenère harus berisi huruf.");
    let n = 0;
    return [...text].map(c => {
        if (!/[A-Za-z]/.test(c)) return c;
        const shift = (key.charCodeAt(n++ % key.length) - 65) * (decrypt ? -1 : 1);
        return shiftChar(c, shift, c === c.toUpperCase() ? 65 : 97);
    }).join("");
}

/* Proses langkah-per-huruf (maks. 30 baris), dipakai Caesar & Vigenere */
function letterProcess(text, result, decrypt, info, describe, moreMsg) {
    let html = `<div class="process-title">${decrypt ? "Proses Dekripsi" : "Proses Enkripsi"}</div>`
        + line("Input: " + esc(text)) + line(info);
    let n = 0;
    for (let i = 0; i < text.length; i++) {
        if (!/[a-zA-Z]/.test(text[i])) continue;
        html += line(describe(text[i], result[i], n));
        if (++n >= 30) { html += line(moreMsg); break; }
    }
    return html + line(`<strong>Hasil:</strong> ${esc(result)}`);
}

/* ---- Caesar ---- */
const caesarRun = decrypt => () => {
    const input = $("caesar-input").value;
    const shift = parseInt($("caesar-key").value) || 0;
    if (!input) return showToast(decrypt ? "Masukkan ciphertext terlebih dahulu." : "Masukkan teks terlebih dahulu.");
    const result = caesarTransform(input, shift, decrypt);
    $("caesar-output").value = result;
    $("caesar-process").innerHTML = letterProcess(input, result, decrypt, "Shift: " + shift,
        (a, b) => `${esc(a)} → ${esc(b)}`, "... proses lainnya ditampilkan pada hasil akhir");
    showToast(`Caesar berhasil ${decrypt ? "didekripsi" : "dienkripsi"}.`);
};
const caesarEncrypt = caesarRun(false);
const caesarDecrypt = caesarRun(true);
const clearCaesar = () => clearFields("caesar");

/* ---- Vigenere ---- */
const vigenereRun = decrypt => () => {
    const input = $("vigenere-input").value;
    const key = $("vigenere-key").value;
    if (!input || !key) return showToast(decrypt ? "Ciphertext dan key harus diisi." : "Teks dan key harus diisi.");
    try {
        const result = vigenereTransform(input, key, decrypt);
        const clean = cleanVigenereKey(key);
        $("vigenere-output").value = result;
        $("vigenere-process").innerHTML = letterProcess(input, result, decrypt, "Key: " + esc(clean),
            (a, b, n) => `${esc(a)} menggunakan key ${esc(clean[n % clean.length])} → ${esc(b)}`,
            "... proses karakter berikutnya disederhanakan.");
        showToast(`Vigenère berhasil ${decrypt ? "didekripsi" : "dienkripsi"}.`);
    } catch (e) {
        showToast(e.message);
    }
};
const vigenereEncrypt = vigenereRun(false);
const vigenereDecrypt = vigenereRun(true);
const clearVigenere = () => clearFields("vigenere");

/* ================= AES-256-GCM ================= */

async function deriveAESKey(password, salt) {
    const base = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function aesEncryptRaw(text, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveAESKey(password, salt);
    const enc = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text)));
    const combined = new Uint8Array(28 + enc.length);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(enc, 28);
    return { base64: arrayBufferToBase64(combined.buffer), salt, iv };
}

async function aesDecryptRaw(base64, password) {
    const data = new Uint8Array(base64ToArrayBuffer(base64));
    const key = await deriveAESKey(password, data.slice(0, 16));
    return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(16, 28) }, key, data.slice(28)));
}

async function aesEncrypt() {
    const input = $("aes-input").value;
    const password = $("aes-key").value;
    if (!input || !password) return showToast("Teks dan password harus diisi.");
    try {
        const r = await aesEncryptRaw(input, password);
        $("aes-output").value = r.base64;
        $("aes-process").innerHTML = proc("Proses AES-256-GCM", [
            "1. Password digunakan sebagai bahan pembentukan key.",
            "2. PBKDF2 + SHA-256 menghasilkan AES Key 256-bit.",
            "3. Salt random: " + arrayBufferToHex(r.salt),
            "4. IV random: " + arrayBufferToHex(r.iv),
            "5. Plaintext diproses menggunakan AES-256-GCM.",
            "6. Hasil ciphertext dikonversi ke Base64.",
            `<strong>Ciphertext:</strong> ${esc(r.base64)}`
        ]);
        showToast("AES berhasil dienkripsi.");
    } catch (e) {
        console.error(e);
        showToast("Enkripsi AES gagal.");
    }
}

async function aesDecrypt() {
    const input = $("aes-input").value.trim();
    const password = $("aes-key").value;
    if (!input || !password) return showToast("Ciphertext dan password harus diisi.");
    try {
        const data = new Uint8Array(base64ToArrayBuffer(input));
        const result = await aesDecryptRaw(input, password);
        $("aes-output").value = result;
        $("aes-process").innerHTML = proc("Proses Dekripsi AES-256-GCM", [
            "1. Ciphertext Base64 dikonversi kembali menjadi bytes.",
            "2. Salt: " + arrayBufferToHex(data.slice(0, 16)),
            "3. IV: " + arrayBufferToHex(data.slice(16, 28)),
            "4. Password digunakan untuk menghasilkan kembali AES Key.",
            "5. AES-256-GCM mendekripsi ciphertext.",
            `<strong>Plaintext:</strong> ${esc(result)}`
        ]);
        showToast("AES berhasil didekripsi.");
    } catch (e) {
        console.error(e);
        showToast("Dekripsi gagal. Pastikan ciphertext dan password benar.");
    }
}

const clearAES = () => clearFields("aes");

/* ================= RSA-OAEP ================= */

let rsaPublicKey = null;
let rsaPrivateKey = null;

const generateRSAPair = () => crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]
);

async function generateRSAKeys() {
    try {
        ({ publicKey: rsaPublicKey, privateKey: rsaPrivateKey } = await generateRSAPair());
        const dump = async k => JSON.stringify(await crypto.subtle.exportKey("jwk", k), null, 2);
        $("rsa-public").value = await dump(rsaPublicKey);
        $("rsa-private").value = await dump(rsaPrivateKey);

        const status = $("rsa-status");
        status.textContent = "RSA Key siap digunakan";
        status.classList.add("ready");

        $("rsa-process").innerHTML = proc("RSA Key Generation", [
            "1. Membuat pasangan Public Key dan Private Key.",
            "2. Algoritma: RSA-OAEP.",
            "3. Panjang modulus: 2048 bit.",
            "4. Hash: SHA-256.",
            "5. Public Key digunakan untuk enkripsi.",
            "6. Private Key digunakan untuk dekripsi."
        ]);
        showToast("RSA key berhasil dibuat.");
    } catch (e) {
        console.error(e);
        showToast("Gagal membuat RSA key.");
    }
}

async function rsaEncrypt() {
    if (!rsaPublicKey) return showToast("Generate RSA Key terlebih dahulu.");
    const input = $("rsa-input").value;
    if (!input) return showToast("Masukkan plaintext.");
    try {
        const result = arrayBufferToBase64(
            await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPublicKey, encoder.encode(input))
        );
        $("rsa-input").value = result;
        $("rsa-process").innerHTML = proc("Proses Enkripsi RSA-OAEP", [
            "1. Plaintext dikonversi menjadi bytes.",
            "2. Public Key RSA digunakan.",
            "3. RSA-OAEP + SHA-256 memproses plaintext.",
            "4. Ciphertext dikonversi ke Base64.",
            `<strong>Ciphertext:</strong> ${esc(result)}`
        ]);
        showToast("RSA berhasil dienkripsi.");
    } catch (e) {
        console.error(e);
        showToast("RSA gagal. Teks mungkin terlalu panjang.");
    }
}

async function rsaDecrypt() {
    if (!rsaPrivateKey) return showToast("Generate RSA Key terlebih dahulu.");
    const input = $("rsa-input").value.trim();
    if (!input) return showToast("Masukkan ciphertext.");
    try {
        const result = decoder.decode(
            await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaPrivateKey, base64ToArrayBuffer(input))
        );
        $("rsa-input").value = result;
        $("rsa-process").innerHTML = proc("Proses Dekripsi RSA-OAEP", [
            "1. Ciphertext Base64 dikonversi menjadi bytes.",
            "2. Private Key RSA digunakan.",
            "3. RSA-OAEP mendekripsi ciphertext.",
            "4. Bytes dikonversi kembali menjadi plaintext.",
            `<strong>Plaintext:</strong> ${esc(result)}`
        ]);
        showToast("RSA berhasil didekripsi.");
    } catch (e) {
        console.error(e);
        showToast("Dekripsi RSA gagal. Pastikan key dan ciphertext sesuai.");
    }
}

const clearRSA = () => {
    $("rsa-input").value = "";
    $("rsa-process").innerHTML = `<p class="empty-process">Generate key kemudian jalankan enkripsi/dekripsi.</p>`;
};

/* ================= SUPER ENCRYPTION =================
   Plaintext → Caesar → Vigenere → AES-256-GCM → RSA-OAEP
   RSA mengenkripsi hash password AES (paket: RSA_HASH::AES_CIPHERTEXT) */

let superRSAKeyPair = null;
const ensureSuperRSAKey = async () => superRSAKeyPair ||= await generateRSAPair();

const setStep = (n, text) => $("super-step-" + n).textContent = text;
const sha256 = text => crypto.subtle.digest("SHA-256", encoder.encode(text));
const superInputs = () => ({
    caesarKey: parseInt($("super-caesar-key").value) || 0,
    vigenereKey: $("super-vigenere-key").value,
    aesPassword: $("super-aes-key").value
});

async function superEncrypt() {
    const plaintext = $("super-input").value;
    const { caesarKey, vigenereKey, aesPassword } = superInputs();
    if (!plaintext) return showToast("Masukkan plaintext.");
    if (!vigenereKey || !aesPassword) return showToast("Key Vigenère dan password AES harus diisi.");

    try {
        const caesar = caesarTransform(plaintext, caesarKey);
        setStep(1, caesar);

        const vigenere = vigenereTransform(caesar, vigenereKey);
        setStep(2, vigenere);

        const aes = await aesEncryptRaw(vigenere, aesPassword);
        setStep(3, aes.base64);

        const { publicKey } = await ensureSuperRSAKey();
        const rsa = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, await sha256(aesPassword));

        $("super-output").value = arrayBufferToBase64(rsa) + "::" + aes.base64;
        setStep(4, "RSA berhasil memproses key AES.");
        showToast("Super Enkripsi berhasil.");
    } catch (e) {
        console.error(e);
        showToast("Super Enkripsi gagal.");
    }
}

async function superDecrypt() {
    const pkg = $("super-input").value.trim();
    const { caesarKey, vigenereKey, aesPassword } = superInputs();
    if (!pkg) return showToast("Masukkan hasil super enkripsi.");

    try {
        const parts = pkg.split("::");
        if (parts.length !== 2) throw new Error("Format super ciphertext tidak valid.");

        const { privateKey } = await ensureSuperRSAKey();
        const storedHash = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, base64ToArrayBuffer(parts[0]));
        if (arrayBufferToHex(storedHash) !== arrayBufferToHex(await sha256(aesPassword)))
            throw new Error("Password AES tidak sesuai.");
        setStep(4, "RSA berhasil didekripsi dan password terverifikasi.");

        const aes = await aesDecryptRaw(parts[1], aesPassword);
        setStep(3, aes);

        const vigenere = vigenereTransform(aes, vigenereKey, true);
        setStep(2, vigenere);

        const plaintext = caesarTransform(vigenere, caesarKey, true);
        setStep(1, plaintext);

        $("super-output").value = plaintext;
        showToast("Super Dekripsi berhasil.");
    } catch (e) {
        console.error(e);
        showToast("Super Dekripsi gagal. Pastikan key benar dan ciphertext sesuai.");
    }
}

function clearSuper() {
    $("super-input").value = "";
    $("super-output").value = "";
    [1, 2, 3, 4].forEach(n => setStep(n, "Menunggu..."));
}

/* ================= ENKRIPSI FILE: AES-256-CTR + HMAC-SHA256 =================
   Format .capp: magic(16) | salt(16) | iv(16) | nameLength(2) | filename | ciphertext | HMAC(32)
   PBKDF2-SHA256 menghasilkan 512 bit: 256 bit AES + 256 bit HMAC.
*/
const FILE_MAGIC = new TextEncoder().encode("CRYPTOAPP-FILE1"); // 15 bytes
const FILE_ITERATIONS = 250000;

async function deriveFileKeys(password, salt) {
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt, iterations:FILE_ITERATIONS, hash:"SHA-256"}, material, 512);
    const all = new Uint8Array(bits);
    const aes = await crypto.subtle.importKey("raw", all.slice(0,32), {name:"AES-CTR"}, false, ["encrypt","decrypt"]);
    const mac = await crypto.subtle.importKey("raw", all.slice(32,64), {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
    all.fill(0);
    return {aes, mac};
}

function downloadBytes(bytes, filename, type="application/octet-stream") {
    const blob = new Blob([bytes], {type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function setFileStatus(message, isError=false) {
    const el = $("file-crypto-status");
    if (el) { el.textContent = message; el.style.color = isError ? "#dc2626" : "#059669"; }
}

async function encryptSelectedFile() {
    try {
        const file = $("file-encrypt-input").files[0];
        const password = $("file-encrypt-password").value;
        if (!file) throw new Error("Pilih file terlebih dahulu.");
        if (password.length < 8) throw new Error("Password minimal 8 karakter.");
        if (!crypto.subtle) throw new Error("Web Crypto tidak tersedia. Buka aplikasi melalui localhost.");
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const keys = await deriveFileKeys(password, salt);
        const name = encoder.encode(file.name);
        if (name.length > 65535) throw new Error("Nama file terlalu panjang.");
        const plain = await file.arrayBuffer();
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({name:"AES-CTR", counter:iv, length:64}, keys.aes, plain));
        const nameLen = new Uint8Array([name.length >> 8, name.length & 255]);
        const prefix = new Uint8Array(FILE_MAGIC.length + salt.length + iv.length + 2 + name.length + encrypted.length);
        let offset = 0;
        for (const part of [FILE_MAGIC, salt, iv, nameLen, name, encrypted]) { prefix.set(part, offset); offset += part.length; }
        const tag = new Uint8Array(await crypto.subtle.sign("HMAC", keys.mac, prefix));
        const output = new Uint8Array(prefix.length + tag.length); output.set(prefix); output.set(tag, prefix.length);
        const safeName = file.name.replace(/[\\/:*?"<>|]/g, "_");
        downloadBytes(output, safeName + ".capp");
        setFileStatus(`Berhasil mengenkripsi ${file.name}. File .capp sudah diunduh.`);
        showToast("File berhasil dienkripsi.");
    } catch (e) { console.error(e); setFileStatus(e.message || "Enkripsi file gagal.", true); showToast("Enkripsi file gagal."); }
}

async function decryptSelectedFile() {
    try {
        const file = $("file-decrypt-input").files[0];
        const password = $("file-decrypt-password").value;
        if (!file) throw new Error("Pilih file .capp terlebih dahulu.");
        if (!password) throw new Error("Masukkan password dekripsi.");
        const data = new Uint8Array(await file.arrayBuffer());
        const min = FILE_MAGIC.length + 16 + 16 + 2 + 32;
        if (data.length < min) throw new Error("Format file tidak valid atau file rusak.");
        let offset = 0;
        const magic = data.slice(offset, offset + FILE_MAGIC.length); offset += FILE_MAGIC.length;
        if (magic.length !== FILE_MAGIC.length || !magic.every((v,i)=>v===FILE_MAGIC[i])) throw new Error("File bukan format CryptoApp (.capp).");
        const salt = data.slice(offset, offset+16); offset += 16;
        const iv = data.slice(offset, offset+16); offset += 16;
        const nameLen = (data[offset] << 8) | data[offset+1]; offset += 2;
        if (offset + nameLen + 32 > data.length) throw new Error("Struktur file tidak lengkap.");
        const originalName = decoder.decode(data.slice(offset, offset+nameLen)); offset += nameLen;
        const tagStart = data.length - 32;
        if (tagStart < offset) throw new Error("Data file tidak valid.");
        const prefix = data.slice(0, tagStart);
        const ciphertext = data.slice(offset, tagStart);
        const tag = data.slice(tagStart);
        const keys = await deriveFileKeys(password, salt);
        const valid = await crypto.subtle.verify("HMAC", keys.mac, tag, prefix);
        if (!valid) throw new Error("Password salah atau file telah diubah/rusak.");
        const plain = await crypto.subtle.decrypt({name:"AES-CTR", counter:iv, length:64}, keys.aes, ciphertext);
        const cleanName = (originalName || "hasil-dekripsi.bin").replace(/[\\/:*?"<>|]/g, "_");
        downloadBytes(new Uint8Array(plain), cleanName);
        setFileStatus(`Berhasil memverifikasi dan mendekripsi ${cleanName}.`);
        showToast("File berhasil didekripsi.");
    } catch (e) { console.error(e); setFileStatus(e.message || "Dekripsi file gagal.", true); showToast("Dekripsi file gagal."); }
}

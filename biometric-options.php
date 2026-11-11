<?php
declare(strict_types=1);
require __DIR__ . '/webauthn-common.php';
$user = wa_require_login();

use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

try {
    $rp = PublicKeyCredentialRpEntity::create('CryptoApp', 'localhost');
    // User handle harus berupa byte string stabil dan unik untuk setiap akun.
    $userHandle = 'cryptoapp-user-' . (string) $user['id'];
    $userEntity = PublicKeyCredentialUserEntity::create($user['username'], $userHandle, $user['username']);
    $selection = AuthenticatorSelectionCriteria::create(
        authenticatorAttachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
        userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED
    );
    $options = PublicKeyCredentialCreationOptions::create(
        $rp,
        $userEntity,
        random_bytes(32),
        [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
        authenticatorSelection: $selection,
        attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE
    );
    $_SESSION['wa_registration_options'] = serialize($options);
    $json = wa_serializer()->serialize($options, 'json');
    header('Content-Type: application/json; charset=utf-8');
    echo $json;
} catch (Throwable $e) {
    wa_json(['ok'=>false, 'message'=>'Gagal menyiapkan registrasi biometrik: '.$e->getMessage()], 500);
}

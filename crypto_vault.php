<?php
/**
 * crypto_vault.php - Patient Medical Records Symmetric Protection
 * * DESIGN PRINCIPLES:
 * 1. Authenticated Encryption with Associated Data (AEAD) via AES-256-GCM.
 * 2. Strict IV Randomization: Employs cryptographically secure pseudo-random numbers.
 * 3. Cryptographic Key Isolation: Extracts keys exclusively from external runtime configurations.
 */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medical_payload = $_POST['payload'] ?? '';

    if (empty($medical_payload)) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Empty cryptographic payload."]);
        exit;
    }

    // 1. ISOLATED KEY RETRIEVAL
    // Keys are stored outside the codebase to prevent key exposure via repository leaks.
    // The key is expected to be a 256-bit cryptographically secure, base64-encoded key.
    $raw_key = getenv('CRYPTO_VAULT_KEY');

    if (!$raw_key) {
        error_log("Critical Configuration Error: CRYPTO_VAULT_KEY is undefined.");
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Cryptographic vault currently unavailable."]);
        exit;
    }

    $secret_key = base64_decode($raw_key);

    // 2. RANDOMIZATION INITIALIZATION (IV Generation)
    // GCM requires a unique, non-repeating Initialization Vector (IV) for every record transaction.
    // The industry standard for GCM is a 12-byte (96-bit) IV, which offers optimal performance and safety.
    $iv_length = 12;
    $iv = openssl_random_pseudo_bytes($iv_length, $was_secure);

    if (!$was_secure || $iv === false) {
        error_log("Cryptographic Error: Insufficient entropy pool for IV generation.");
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Entropy depletion event."]);
        exit;
    }

    // 3. SECURE ENCRYPTION PIPELINE (AES-256-GCM + Authentication Tag Binding)
    // Encrypts the payload using AES-256-GCM.
    // The variable $tag is passed by reference; the engine populates it with a 16-byte authentication check.
    $cipher_mode = 'aes-256-gcm';
    $tag = ''; // Populated at runtime by OpenSSL
    $tag_length = 16;

    $encrypted = openssl_encrypt(
        $medical_payload,
        $cipher_mode,
        $secret_key,
        0, // No padding flags (standard)
        $iv,
        $tag,
        '', // Optional Associated Data (AAD) left blank
        $tag_length
    );

    if ($encrypted === false) {
        error_log("Cryptographic Error: Symmetric encryption operation failed.");
        http_response_code(500);
        echo json_encode(["status" => "error", "message" => "Symmetric operation failed."]);
        exit;
    }

    // 4. STRUCTURED RESPONSE ASSEMBLY
    // Output the ciphertext, randomized IV, and Authentication Tag.
    // Standardizing on Base64 ensures binary-safe transport over web APIs.
    echo json_encode([
        "status" => "vaulted",
        "data" => base64_encode($encrypted),
        "iv" => base64_encode($iv),
        "tag" => base64_encode($tag)
    ]);
}
?>
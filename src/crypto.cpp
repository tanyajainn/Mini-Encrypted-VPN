#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

bool encrypt_data(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& iv,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& tag
) {
    if (key.size() != 32) return false;

    iv.resize(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool success = false;

    ciphertext.resize(plaintext.size() + 16);
    tag.resize(16);

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(
            ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(
            ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        goto cleanup;

    if (EVP_EncryptUpdate(
            ctx,
            ciphertext.data(),
            &len,
            plaintext.data(),
            static_cast<int>(plaintext.size())) != 1)
        goto cleanup;

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(
            ctx, ciphertext.data() + ciphertext_len, &len) != 1)
        goto cleanup;

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            16,
            tag.data()) != 1)
        goto cleanup;

    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool decrypt_data(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    std::vector<uint8_t>& plaintext
) {
    if (key.size() != 32 || iv.size() != 12 || tag.size() != 16)
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    plaintext.resize(ciphertext.size());

    int len = 0;
    int plaintext_len = 0;
    bool success = false;

    if (EVP_DecryptInit_ex(
            ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(
            ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        goto cleanup;

    if (EVP_DecryptUpdate(
            ctx,
            plaintext.data(),
            &len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size())) != 1)
        goto cleanup;

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            16,
            const_cast<uint8_t*>(tag.data())) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext.data() + plaintext_len,
            &len) != 1)
        goto cleanup;

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

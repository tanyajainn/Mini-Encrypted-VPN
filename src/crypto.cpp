#include "crypto.h"
#include <openssl/evp.h>
#include <climits>

bool encrypt_data(const std::vector<uint8_t>& plaintext, const Key256& key,
                  const Nonce96& nonce, const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& ciphertext, Tag128& tag) {
    if (plaintext.size() > INT_MAX || aad_len > INT_MAX) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int n = 0, total = 0;
    ciphertext.resize(plaintext.size() + 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        goto done;
    if (aad_len && EVP_EncryptUpdate(ctx, nullptr, &n, aad, static_cast<int>(aad_len)) != 1)
        goto done;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &n, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) goto done;
    total = n;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &n) != 1) goto done;
    total += n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) goto done;
    ciphertext.resize(static_cast<size_t>(total));
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { ciphertext.clear(); tag.fill(0); }
    return ok;
}

bool decrypt_data(const uint8_t* ciphertext, size_t ciphertext_len,
                  const Key256& key, const Nonce96& nonce,
                  const uint8_t* aad, size_t aad_len, const Tag128& tag,
                  std::vector<uint8_t>& plaintext) {
    plaintext.clear();
    if (ciphertext_len > INT_MAX || aad_len > INT_MAX) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int n = 0, total = 0;
    std::vector<uint8_t> tmp(ciphertext_len + 16);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        goto done;
    if (aad_len && EVP_DecryptUpdate(ctx, nullptr, &n, aad, static_cast<int>(aad_len)) != 1)
        goto done;
    if (EVP_DecryptUpdate(ctx, tmp.data(), &n, ciphertext,
                          static_cast<int>(ciphertext_len)) != 1) goto done;
    total = n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag.data())) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, tmp.data() + total, &n) != 1) goto done;
    total += n;
    tmp.resize(static_cast<size_t>(total));
    plaintext.swap(tmp);
    ok = true;
done:
    EVP_CIPHER_CTX_free(ctx);
    // Never expose unauthenticated plaintext to callers.
    return ok;
}

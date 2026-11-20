#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

using Key256 = std::array<uint8_t, 32>;
using Nonce96 = std::array<uint8_t, 12>;
using Tag128 = std::array<uint8_t, 16>;

bool encrypt_data(const std::vector<uint8_t>& plaintext, const Key256& key,
                  const Nonce96& nonce, const uint8_t* aad, size_t aad_len,
                  std::vector<uint8_t>& ciphertext, Tag128& tag);
bool decrypt_data(const uint8_t* ciphertext, size_t ciphertext_len,
                  const Key256& key, const Nonce96& nonce,
                  const uint8_t* aad, size_t aad_len, const Tag128& tag,
                  std::vector<uint8_t>& plaintext);

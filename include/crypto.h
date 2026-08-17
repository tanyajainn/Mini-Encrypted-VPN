#pragma once

#include <cstdint>
#include <vector>

bool encrypt_data(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& iv,
    std::vector<uint8_t>& ciphertext,
    std::vector<uint8_t>& tag
);

bool decrypt_data(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    std::vector<uint8_t>& plaintext
);

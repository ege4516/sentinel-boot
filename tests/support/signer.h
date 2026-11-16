// SPDX-License-Identifier: MIT
// Test-side package builder. Mirrors tools/sentinel_sign.py using the PSA API
// directly, so tests do not depend on Python.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sbtest {

using Bytes = std::vector<uint8_t>;

struct KeyPair {
    std::array<uint8_t, 32> priv{};
    std::array<uint8_t, 65> pub{};
};

struct PackageSpec {
    uint32_t fw_version = 0x01000000;
    uint32_t security_counter = 1;
    Bytes image;
};

KeyPair generate_p256();
// Rebuild a key pair from a raw 32-byte private scalar (deterministic keys for fuzzing).
KeyPair keypair_from_private(const std::array<uint8_t, 32> &priv);
std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len);
Bytes random_bytes(size_t n);

// Deterministic pseudo-random image contents, distinct per seed.
Bytes make_image(size_t size, uint32_t seed);

// Build manifest || ciphertext for the given device.
Bytes make_package(const PackageSpec &spec, const KeyPair &root,
                   const std::array<uint8_t, 65> &device_pub);

// Recompute the signature over a (possibly modified) manifest.
void resign(Bytes &pkg, const KeyPair &root);

void put_le32(Bytes &buf, size_t off, uint32_t v);

Bytes from_hex(const char *hex);

}  // namespace sbtest

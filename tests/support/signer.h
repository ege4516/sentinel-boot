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

// ECDSA P-256 over SHA-256(msg), raw r || s (64 bytes).
Bytes sign_p256(const KeyPair &key, const Bytes &msg);

// Test-side transparency log. Deliberately written straight from the recursive
// definitions in RFC 9162 2.1 (MTH, PATH), not from the iterative verifier the
// bootloader uses, so the two act as independent implementations.
class TestLog {
public:
    explicit TestLog(const KeyPair &log_key) : key_(log_key) {}

    // Record a leaf (the signed manifest region); returns the 364-byte proof
    // block against the new tree head.
    Bytes append(const Bytes &leaf_data);
    // Proof block for an existing entry against the current tree.
    Bytes proof_for(size_t index) const;
    Bytes root() const;
    size_t size() const { return entries_.size(); }
    const KeyPair &key() const { return key_; }

private:
    KeyPair key_;
    std::vector<Bytes> entries_;
};

// Build manifest || proof block || ciphertext for the given device. With a log
// the release is recorded and carries a valid proof; with nullptr the proof
// block is all zeros (a release that was never logged).
Bytes make_package(const PackageSpec &spec, const KeyPair &root,
                   const std::array<uint8_t, 65> &device_pub, TestLog *log = nullptr);

// Recompute the root signature over a (possibly modified) manifest.
void resign(Bytes &pkg, const KeyPair &root);

// Replace the package's proof block with a fresh proof for its (current) manifest.
void relog(Bytes &pkg, TestLog &log);

void put_le32(Bytes &buf, size_t off, uint32_t v);

Bytes from_hex(const char *hex);

}  // namespace sbtest

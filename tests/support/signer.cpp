// SPDX-License-Identifier: MIT
#include "signer.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include <psa/crypto.h>

extern "C" {
#include "boot/crypto_port.h"
#include "boot/manifest.h"
#include "boot/merkle.h"
}

namespace sbtest {

namespace {

void check(psa_status_t st, const char *what)
{
    if (st != PSA_SUCCESS) {
        throw std::runtime_error(std::string("PSA failure in ") + what + ": " +
                                 std::to_string(st));
    }
}

void ensure_init()
{
    check(psa_crypto_init(), "psa_crypto_init");
}

const uint8_t kKdfLabel[] = "sentinel-boot/v1/image-key";
const char kTreeHeadLabel[] = "sentinel-boot/v1/tree-head";

}  // namespace

KeyPair generate_p256()
{
    ensure_init();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    check(psa_generate_key(&attr, &key), "psa_generate_key");

    KeyPair kp;
    size_t len = 0;
    check(psa_export_key(key, kp.priv.data(), kp.priv.size(), &len), "psa_export_key");
    if (len != kp.priv.size()) {
        throw std::runtime_error("unexpected private key length");
    }
    check(psa_export_public_key(key, kp.pub.data(), kp.pub.size(), &len),
          "psa_export_public_key");
    if (len != kp.pub.size()) {
        throw std::runtime_error("unexpected public key length");
    }
    psa_destroy_key(key);
    return kp;
}

KeyPair keypair_from_private(const std::array<uint8_t, 32> &priv)
{
    ensure_init();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    check(psa_import_key(&attr, priv.data(), priv.size(), &key), "import private scalar");
    KeyPair kp;
    kp.priv = priv;
    size_t len = 0;
    psa_status_t st = psa_export_public_key(key, kp.pub.data(), kp.pub.size(), &len);
    psa_destroy_key(key);
    check(st, "psa_export_public_key");
    return kp;
}

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len)
{
    ensure_init();
    std::array<uint8_t, 32> out{};
    size_t n = 0;
    check(psa_hash_compute(PSA_ALG_SHA_256, data, len, out.data(), out.size(), &n),
          "psa_hash_compute");
    return out;
}

Bytes random_bytes(size_t n)
{
    ensure_init();
    Bytes out(n);
    if (n != 0) {
        check(psa_generate_random(out.data(), n), "psa_generate_random");
    }
    return out;
}

Bytes make_image(size_t size, uint32_t seed)
{
    Bytes img(size);
    uint32_t x = seed * 2654435761u + 1u;
    for (size_t i = 0; i < size; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        img[i] = static_cast<uint8_t>(x);
    }
    return img;
}

void put_le32(Bytes &buf, size_t off, uint32_t v)
{
    buf.at(off + 3) = static_cast<uint8_t>(v >> 24);
    buf[off + 0] = static_cast<uint8_t>(v);
    buf[off + 1] = static_cast<uint8_t>(v >> 8);
    buf[off + 2] = static_cast<uint8_t>(v >> 16);
}

Bytes sign_p256(const KeyPair &key, const Bytes &msg)
{
    ensure_init();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
    check(psa_import_key(&attr, key.priv.data(), key.priv.size(), &id), "import signing key");
    auto digest = sha256(msg.data(), msg.size());
    Bytes sig(SB_P256_SIG_LEN);
    size_t sig_len = 0;
    psa_status_t st = psa_sign_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest.data(),
                                    digest.size(), sig.data(), sig.size(), &sig_len);
    psa_destroy_key(id);
    check(st, "psa_sign_hash");
    if (sig_len != SB_P256_SIG_LEN) {
        throw std::runtime_error("unexpected signature length");
    }
    return sig;
}

namespace {

Bytes concat(std::initializer_list<const Bytes *> parts)
{
    Bytes out;
    for (const Bytes *p : parts) {
        out.insert(out.end(), p->begin(), p->end());
    }
    return out;
}

Bytes hash_bytes(const Bytes &in)
{
    auto h = sha256(in.data(), in.size());
    return Bytes(h.begin(), h.end());
}

// RFC 9162 2.1.1: MTH over entries[lo, hi).
Bytes mth(const std::vector<Bytes> &e, size_t lo, size_t hi)
{
    size_t n = hi - lo;
    if (n == 0) {
        return hash_bytes({});
    }
    if (n == 1) {
        Bytes leaf{0x00};
        leaf.insert(leaf.end(), e[lo].begin(), e[lo].end());
        return hash_bytes(leaf);
    }
    size_t k = 1;
    while (k * 2 < n) {
        k *= 2;
    }
    Bytes prefix{0x01}, left = mth(e, lo, lo + k), right = mth(e, lo + k, hi);
    return hash_bytes(concat({&prefix, &left, &right}));
}

// RFC 9162 2.1.3.1: PATH(m, entries[lo, hi)).
void path(const std::vector<Bytes> &e, size_t m, size_t lo, size_t hi, std::vector<Bytes> &out)
{
    size_t n = hi - lo;
    if (n == 1) {
        return;
    }
    size_t k = 1;
    while (k * 2 < n) {
        k *= 2;
    }
    if (m < k) {
        path(e, m, lo, lo + k, out);
        out.push_back(mth(e, lo + k, hi));
    } else {
        path(e, m - k, lo + k, hi, out);
        out.push_back(mth(e, lo, lo + k));
    }
}

}  // namespace

Bytes TestLog::root() const
{
    return mth(entries_, 0, entries_.size());
}

Bytes TestLog::proof_for(size_t index) const
{
    std::vector<Bytes> p;
    path(entries_, index, 0, entries_.size(), p);
    if (p.size() > SB_PROOF_MAX_DEPTH) {
        throw std::runtime_error("test log outgrew the proof depth limit");
    }
    Bytes root_hash = root();

    Bytes head(kTreeHeadLabel, kTreeHeadLabel + sizeof(kTreeHeadLabel) - 1);
    uint32_t size = static_cast<uint32_t>(entries_.size());
    for (int i = 0; i < 4; i++) {
        head.push_back(static_cast<uint8_t>(size >> (8 * i)));
    }
    head.insert(head.end(), root_hash.begin(), root_hash.end());
    Bytes sig = sign_p256(key_, head);

    Bytes block(SB_PROOF_LEN, 0);
    put_le32(block, SB_PF_OFF_INDEX, static_cast<uint32_t>(index));
    put_le32(block, SB_PF_OFF_TREE_SIZE, size);
    block[SB_PF_OFF_PATH_LEN] = static_cast<uint8_t>(p.size());
    std::memcpy(&block[SB_PF_OFF_ROOT], root_hash.data(), root_hash.size());
    std::memcpy(&block[SB_PF_OFF_SIGNATURE], sig.data(), sig.size());
    for (size_t i = 0; i < p.size(); i++) {
        std::memcpy(&block[SB_PF_OFF_PATH + 32 * i], p[i].data(), 32);
    }
    return block;
}

Bytes TestLog::append(const Bytes &leaf_data)
{
    entries_.push_back(leaf_data);
    return proof_for(entries_.size() - 1);
}

void relog(Bytes &pkg, TestLog &log)
{
    Bytes leaf(pkg.begin(), pkg.begin() + SB_MANIFEST_SIGNED_LEN);
    Bytes block = log.append(leaf);
    std::memcpy(&pkg[SB_MANIFEST_LEN], block.data(), block.size());
}

void resign(Bytes &pkg, const KeyPair &root)
{
    ensure_init();
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    check(psa_import_key(&attr, root.priv.data(), root.priv.size(), &key), "import root key");

    auto digest = sha256(pkg.data(), SB_MANIFEST_SIGNED_LEN);
    size_t sig_len = 0;
    psa_status_t st = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest.data(),
                                    digest.size(), pkg.data() + SB_MF_OFF_SIGNATURE,
                                    SB_P256_SIG_LEN, &sig_len);
    psa_destroy_key(key);
    check(st, "psa_sign_hash");
    if (sig_len != SB_P256_SIG_LEN) {
        throw std::runtime_error("unexpected signature length");
    }
}

Bytes make_package(const PackageSpec &spec, const KeyPair &root,
                   const std::array<uint8_t, 65> &device_pub, TestLog *log)
{
    ensure_init();
    const Bytes &img = spec.image;
    Bytes pkg(SB_HEADER_LEN + img.size(), 0);

    // Header fields.
    put_le32(pkg, SB_MF_OFF_MAGIC, SB_MANIFEST_MAGIC);
    pkg[SB_MF_OFF_FORMAT] = SB_MANIFEST_FORMAT;
    put_le32(pkg, SB_MF_OFF_FW_VERSION, spec.fw_version);
    put_le32(pkg, SB_MF_OFF_SEC_COUNTER, spec.security_counter);
    put_le32(pkg, SB_MF_OFF_IMAGE_SIZE, static_cast<uint32_t>(img.size()));
    auto root_hash = sha256(root.pub.data(), root.pub.size());
    std::memcpy(&pkg[SB_MF_OFF_KEY_ID], root_hash.data(), SB_KEY_ID_LEN);

    // Fresh ephemeral key per package -> fresh AES key per package.
    KeyPair eph = generate_p256();
    std::memcpy(&pkg[SB_MF_OFF_EPH_PUB], eph.pub.data(), eph.pub.size());

    uint8_t shared[SB_P256_SHARED_LEN];
    if (sb_ecdh_p256(eph.priv.data(), device_pub.data(), shared) != SB_OK) {
        throw std::runtime_error("ECDH failed");
    }
    Bytes info(kKdfLabel, kKdfLabel + sizeof(kKdfLabel) - 1);
    info.insert(info.end(), eph.pub.begin(), eph.pub.end());
    uint8_t aes_key[SB_AES256_KEY_LEN];
    if (sb_hkdf_sha256(nullptr, 0, shared, sizeof(shared), info.data(), info.size(), aes_key,
                       sizeof(aes_key)) != SB_OK) {
        throw std::runtime_error("HKDF failed");
    }

    Bytes nonce = random_bytes(SB_GCM_NONCE_LEN);
    std::memcpy(&pkg[SB_MF_OFF_NONCE], nonce.data(), nonce.size());

    // AES-256-GCM, AAD = manifest[0..24).
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    check(psa_import_key(&attr, aes_key, sizeof(aes_key), &key), "import aes key");

    Bytes ct_tag(img.size() + SB_GCM_TAG_LEN);
    size_t out_len = 0;
    psa_status_t st =
        psa_aead_encrypt(key, PSA_ALG_GCM, nonce.data(), nonce.size(), pkg.data(),
                         SB_MANIFEST_AAD_LEN, img.data(), img.size(), ct_tag.data(),
                         ct_tag.size(), &out_len);
    psa_destroy_key(key);
    check(st, "psa_aead_encrypt");
    if (out_len != ct_tag.size()) {
        throw std::runtime_error("unexpected ciphertext length");
    }

    std::memcpy(&pkg[SB_HEADER_LEN], ct_tag.data(), img.size());
    std::memcpy(&pkg[SB_MF_OFF_TAG], ct_tag.data() + img.size(), SB_GCM_TAG_LEN);

    auto ct_digest = sha256(ct_tag.data(), img.size());
    auto pt_digest = sha256(img.data(), img.size());
    std::memcpy(&pkg[SB_MF_OFF_CT_DIGEST], ct_digest.data(), ct_digest.size());
    std::memcpy(&pkg[SB_MF_OFF_PT_DIGEST], pt_digest.data(), pt_digest.size());

    resign(pkg, root);
    if (log != nullptr) {
        relog(pkg, *log);
    }
    return pkg;
}

Bytes from_hex(const char *hex)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("bad hex digit");
    };
    size_t n = std::strlen(hex);
    if (n % 2 != 0) {
        throw std::runtime_error("odd hex length");
    }
    Bytes out(n / 2);
    for (size_t i = 0; i < out.size(); i++) {
        out[i] = static_cast<uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    }
    return out;
}

}  // namespace sbtest

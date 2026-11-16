// SPDX-License-Identifier: MIT
// Known-answer and adversarial tests for boot/crypto_port.c.
#include <gtest/gtest.h>

#include <cstring>

#include "support/signer.h"

extern "C" {
#include "boot/crypto_port.h"
}

using sbtest::Bytes;
using sbtest::from_hex;

namespace {

class Crypto : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_EQ(sb_crypto_init(), SB_OK); }
};

Bytes sha(const Bytes &in)
{
    Bytes out(SB_SHA256_LEN);
    EXPECT_EQ(sb_sha256(in.data(), in.size(), out.data()), SB_OK);
    return out;
}

// ---- SHA-256 (FIPS 180-4 examples) ----------------------------------------

TEST_F(Crypto, Sha256KnownAnswers)
{
    EXPECT_EQ(sha({}),
              from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    EXPECT_EQ(sha({'a', 'b', 'c'}),
              from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    EXPECT_EQ(sha(Bytes(two_block, two_block + std::strlen(two_block))),
              from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

TEST_F(Crypto, Sha256StreamingMatchesOneShot)
{
    Bytes msg = sbtest::make_image(10000, 7);
    Bytes expect = sha(msg);
    for (size_t chunk : {1u, 3u, 63u, 64u, 65u, 4096u}) {
        sb_sha256_ctx_t ctx;
        ASSERT_EQ(sb_sha256_init(&ctx), SB_OK);
        for (size_t off = 0; off < msg.size(); off += chunk) {
            size_t n = std::min(chunk, msg.size() - off);
            ASSERT_EQ(sb_sha256_update(&ctx, msg.data() + off, n), SB_OK);
        }
        Bytes out(SB_SHA256_LEN);
        ASSERT_EQ(sb_sha256_finish(&ctx, out.data()), SB_OK);
        EXPECT_EQ(out, expect) << "chunk=" << chunk;
    }
}

// ---- ECDSA P-256 (Wycheproof, P1363 encoding) ----------------------------

struct EcdsaVec {
    int id;
    const char *pub, *msg, *sig;
    char result;
};
const EcdsaVec kEcdsa[] = {
#include "vectors/wycheproof_ecdsa_p256.inc"
};

TEST_F(Crypto, WycheproofEcdsaP256)
{
    int valid = 0, invalid = 0;
    for (const auto &v : kEcdsa) {
        Bytes pub = from_hex(v.pub), msg = from_hex(v.msg), sig = from_hex(v.sig);
        ASSERT_EQ(pub.size(), SB_P256_PUB_LEN);
        ASSERT_NE(v.result, 'a') << "unexpected 'acceptable' vector " << v.id;

        // The API takes exactly 64 bytes; any other length is rejected by
        // construction, as the manifest format has no room for it.
        sb_err_t err = SB_ERR_SIGNATURE;
        if (sig.size() == SB_P256_SIG_LEN) {
            Bytes digest = sha(msg);
            err = sb_ecdsa_p256_verify(pub.data(), digest.data(), sig.data());
        }
        if (v.result == 'v') {
            EXPECT_EQ(err, SB_OK) << "tcId " << v.id;
            valid++;
        } else {
            EXPECT_EQ(err, SB_ERR_SIGNATURE) << "tcId " << v.id;
            invalid++;
        }
    }
    EXPECT_GT(valid, 100);
    EXPECT_GT(invalid, 50);
}

TEST_F(Crypto, EcdsaRejectsPointNotOnCurve)
{
    Bytes pub = from_hex(kEcdsa[0].pub);
    Bytes digest = sha(from_hex(kEcdsa[0].msg));
    Bytes sig(SB_P256_SIG_LEN, 1);
    pub[64] ^= 1; // knock the point off the curve
    EXPECT_EQ(sb_ecdsa_p256_verify(pub.data(), digest.data(), sig.data()), SB_ERR_KEY);
}

// ---- ECDH P-256 (Wycheproof, raw point encoding) -------------------------

struct EcdhVec {
    int id;
    const char *pub, *priv, *shared;
    char result;
};
const EcdhVec kEcdh[] = {
#include "vectors/wycheproof_ecdh_p256.inc"
};

// Wycheproof encodes private keys as integers: strip or add leading zeros.
Bytes normalize_scalar(Bytes k)
{
    while (k.size() > SB_P256_PRIV_LEN && k.front() == 0) {
        k.erase(k.begin());
    }
    while (k.size() < SB_P256_PRIV_LEN) {
        k.insert(k.begin(), 0);
    }
    return k;
}

TEST_F(Crypto, WycheproofEcdhP256)
{
    int valid = 0, invalid = 0, unsupported = 0;
    for (const auto &v : kEcdh) {
        Bytes pub = from_hex(v.pub), priv = normalize_scalar(from_hex(v.priv));
        Bytes expect = from_hex(v.shared);
        ASSERT_EQ(priv.size(), SB_P256_PRIV_LEN) << "tcId " << v.id;

        // Only uncompressed points exist in the manifest format. Compressed
        // or otherwise re-encoded points are unrepresentable, so they are
        // counted but cannot be fed to the API.
        if (pub.size() != SB_P256_PUB_LEN || pub[0] != 0x04) {
            unsupported++;
            continue;
        }
        Bytes shared(SB_P256_SHARED_LEN);
        sb_err_t err = sb_ecdh_p256(priv.data(), pub.data(), shared.data());
        if (v.result == 'v') {
            EXPECT_EQ(err, SB_OK) << "tcId " << v.id;
            EXPECT_EQ(shared, expect) << "tcId " << v.id;
            valid++;
        } else if (v.result == 'i') {
            EXPECT_NE(err, SB_OK) << "tcId " << v.id;
            invalid++;
        } else if (err == SB_OK) {
            EXPECT_EQ(shared, expect) << "tcId " << v.id;
        }
    }
    EXPECT_GT(valid, 200);
    EXPECT_GT(invalid, 5);
    RecordProperty("unsupported_encodings", unsupported);
}

// ---- HKDF-SHA256 (Wycheproof) --------------------------------------------

struct HkdfVec {
    int id;
    const char *ikm, *salt, *info;
    int size;
    const char *okm;
    char result;
};
const HkdfVec kHkdf[] = {
#include "vectors/wycheproof_hkdf_sha256.inc"
};

TEST_F(Crypto, WycheproofHkdfSha256)
{
    int valid = 0, skipped = 0;
    for (const auto &v : kHkdf) {
        Bytes ikm = from_hex(v.ikm), salt = from_hex(v.salt), info = from_hex(v.info);
        Bytes expect = from_hex(v.okm);
        if (ikm.empty()) {
            // The bootloader always feeds a 32-byte ECDH secret; an empty IKM
            // is rejected by the wrapper as a parameter error.
            EXPECT_EQ(sb_hkdf_sha256(nullptr, 0, ikm.data(), 0, nullptr, 0, expect.data(), 1),
                      SB_ERR_PARAM);
            skipped++;
            continue;
        }
        Bytes out(static_cast<size_t>(v.size));
        sb_err_t err = sb_hkdf_sha256(salt.empty() ? nullptr : salt.data(), salt.size(),
                                      ikm.data(), ikm.size(),
                                      info.empty() ? nullptr : info.data(), info.size(),
                                      out.data(), out.size());
        if (v.result == 'v') {
            EXPECT_EQ(err, SB_OK) << "tcId " << v.id;
            EXPECT_EQ(out, expect) << "tcId " << v.id;
            valid++;
        } else {
            EXPECT_NE(err, SB_OK) << "tcId " << v.id; // output longer than 255 blocks
        }
    }
    EXPECT_GT(valid, 50);
    RecordProperty("skipped_empty_ikm", skipped);
}

// ---- AES-256-GCM (Wycheproof, 96-bit nonce, 128-bit tag) ------------------

struct GcmVec {
    int id;
    const char *key, *iv, *aad, *msg, *ct, *tag;
    char result;
};
const GcmVec kGcm[] = {
#include "vectors/wycheproof_aes256_gcm.inc"
};

sb_err_t gcm_decrypt(const Bytes &key, const Bytes &iv, const Bytes &aad, const Bytes &ct,
                     const Bytes &tag, size_t chunk, Bytes &pt)
{
    sb_gcm_ctx_t ctx;
    pt.assign(ct.size(), 0);
    sb_err_t err = sb_gcm_decrypt_begin(&ctx, key.data(), iv.data(),
                                        aad.empty() ? nullptr : aad.data(), aad.size());
    for (size_t off = 0; err == SB_OK && off < ct.size(); off += chunk) {
        size_t n = std::min(chunk, ct.size() - off);
        err = sb_gcm_decrypt_update(&ctx, ct.data() + off, n, pt.data() + off);
    }
    if (err != SB_OK) {
        sb_gcm_decrypt_abort(&ctx);
        return err;
    }
    return sb_gcm_decrypt_finish(&ctx, tag.data());
}

TEST_F(Crypto, WycheproofAes256Gcm)
{
    int valid = 0, invalid = 0;
    for (const auto &v : kGcm) {
        Bytes key = from_hex(v.key), iv = from_hex(v.iv), aad = from_hex(v.aad);
        Bytes msg = from_hex(v.msg), ct = from_hex(v.ct), tag = from_hex(v.tag);
        ASSERT_EQ(key.size(), SB_AES256_KEY_LEN);
        ASSERT_EQ(iv.size(), SB_GCM_NONCE_LEN);
        ASSERT_EQ(tag.size(), SB_GCM_TAG_LEN);

        // Decrypt both in one piece and in 16-byte chunks: the bootloader
        // streams sector by sector, so chunking must not change the result.
        for (size_t chunk : {size_t{1} << 20, size_t{16}}) {
            Bytes pt;
            sb_err_t err = gcm_decrypt(key, iv, aad, ct, tag, chunk, pt);
            if (v.result == 'v') {
                EXPECT_EQ(err, SB_OK) << "tcId " << v.id;
                EXPECT_EQ(pt, msg) << "tcId " << v.id;
            } else {
                EXPECT_EQ(err, SB_ERR_AUTH) << "tcId " << v.id;
            }
        }
        (v.result == 'v' ? valid : invalid)++;
    }
    EXPECT_GT(valid, 30);
    EXPECT_GT(invalid, 10);
}

TEST_F(Crypto, GcmRejectsModifiedAad)
{
    const GcmVec *pick = nullptr;
    for (const auto &v : kGcm) {
        if (v.result == 'v' && std::strlen(v.aad) > 0 && std::strlen(v.ct) > 0) {
            pick = &v;
            break;
        }
    }
    ASSERT_NE(pick, nullptr);
    Bytes aad = from_hex(pick->aad), pt;
    aad[0] ^= 0x80;
    EXPECT_EQ(gcm_decrypt(from_hex(pick->key), from_hex(pick->iv), aad, from_hex(pick->ct),
                          from_hex(pick->tag), 16, pt),
              SB_ERR_AUTH);
}

// ---- Helpers --------------------------------------------------------------

TEST_F(Crypto, ConstantTimeCompareSemantics)
{
    Bytes a = sbtest::make_image(64, 1), b = a;
    EXPECT_EQ(sb_ct_memeq(a.data(), b.data(), a.size()), 1);
    EXPECT_EQ(sb_ct_memeq(a.data(), b.data(), 0), 1);
    for (size_t i = 0; i < a.size(); i++) {
        for (int bit = 0; bit < 8; bit++) {
            b = a;
            b[i] = static_cast<uint8_t>(b[i] ^ (1u << bit));
            ASSERT_EQ(sb_ct_memeq(a.data(), b.data(), a.size()), 0) << i << ":" << bit;
        }
    }
}

TEST_F(Crypto, NullArgumentsAreRejected)
{
    uint8_t buf[65] = {0};
    EXPECT_EQ(sb_sha256_init(nullptr), SB_ERR_PARAM);
    EXPECT_EQ(sb_sha256(nullptr, 4, buf), SB_ERR_PARAM);
    EXPECT_EQ(sb_ecdsa_p256_verify(nullptr, buf, buf), SB_ERR_PARAM);
    EXPECT_EQ(sb_ecdh_p256(buf, nullptr, buf), SB_ERR_PARAM);
    EXPECT_EQ(sb_hkdf_sha256(nullptr, 0, nullptr, 32, nullptr, 0, buf, 32), SB_ERR_PARAM);
    EXPECT_EQ(sb_gcm_decrypt_begin(nullptr, buf, buf, nullptr, 0), SB_ERR_PARAM);
    EXPECT_STREQ(sb_strerror(SB_OK), "ok");
    EXPECT_STRNE(sb_strerror(static_cast<sb_err_t>(-999)), "");
}

}  // namespace

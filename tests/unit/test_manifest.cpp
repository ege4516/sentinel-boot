// SPDX-License-Identifier: MIT
// Parser and signature checks for the update manifest.
#include <gtest/gtest.h>

#include <algorithm>

#include "support/signer.h"

extern "C" {
#include "boot/manifest.h"
}

using namespace sbtest;

namespace {

constexpr uint32_t kMaxImage = 28672;

class Manifest : public ::testing::Test {
protected:
    static void SetUpTestSuite()
    {
        root_ = new KeyPair(generate_p256());
        device_ = new KeyPair(generate_p256());
    }
    static void TearDownTestSuite()
    {
        delete root_;
        delete device_;
    }

    void SetUp() override
    {
        PackageSpec spec;
        spec.fw_version = 0x01020003;
        spec.security_counter = 7;
        spec.image = make_image(1000, 1);
        pkg_ = make_package(spec, *root_, device_->pub);
        anchor_ = sha256(root_->pub.data(), root_->pub.size());
    }

    sb_err_t parse(const Bytes &raw, sb_manifest_t *mf = nullptr)
    {
        sb_manifest_t local;
        return sb_manifest_parse(raw.data(), raw.size(), kMaxImage, mf ? mf : &local);
    }

    // Parse then verify, as the bootloader does.
    sb_err_t check(const Bytes &raw)
    {
        sb_manifest_t mf;
        sb_err_t err = parse(raw, &mf);
        if (err != SB_OK) {
            return err;
        }
        return sb_manifest_verify(raw.data(), &mf, root_->pub.data(), anchor_.data());
    }

    static KeyPair *root_;
    static KeyPair *device_;
    Bytes pkg_;
    std::array<uint8_t, 32> anchor_{};
};
KeyPair *Manifest::root_ = nullptr;
KeyPair *Manifest::device_ = nullptr;

TEST_F(Manifest, ParsesAllFields)
{
    sb_manifest_t mf;
    ASSERT_EQ(parse(pkg_, &mf), SB_OK);
    EXPECT_EQ(mf.format, SB_MANIFEST_FORMAT);
    EXPECT_EQ(mf.flags, 0);
    EXPECT_EQ(mf.fw_version, 0x01020003u);
    EXPECT_EQ(mf.security_counter, 7u);
    EXPECT_EQ(mf.image_size, 1000u);
    EXPECT_TRUE(std::equal(anchor_.begin(), anchor_.begin() + SB_KEY_ID_LEN, mf.key_id));
    EXPECT_EQ(mf.eph_pub[0], 0x04);
    auto pt = make_image(1000, 1);
    auto digest = sha256(pt.data(), pt.size());
    EXPECT_TRUE(std::equal(digest.begin(), digest.end(), mf.pt_digest));
}

TEST_F(Manifest, ValidManifestVerifies)
{
    EXPECT_EQ(check(pkg_), SB_OK);
}

TEST_F(Manifest, RejectsEveryTruncation)
{
    for (size_t len = 0; len < SB_MANIFEST_LEN; len++) {
        Bytes cut(pkg_.begin(), pkg_.begin() + static_cast<long>(len));
        cut.reserve(1); // keep data() non-null for len == 0
        sb_manifest_t mf;
        EXPECT_EQ(sb_manifest_parse(cut.data(), len, kMaxImage, &mf), SB_ERR_FORMAT)
            << "len=" << len;
    }
}

TEST_F(Manifest, RejectsBadHeaderFields)
{
    Bytes m = pkg_;
    m[SB_MF_OFF_MAGIC] ^= 1;
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    m = pkg_;
    m[SB_MF_OFF_FORMAT] = 2;
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    m = pkg_;
    m[SB_MF_OFF_FLAGS] = 1;
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    m = pkg_;
    m[SB_MF_OFF_RESERVED + 1] = 0xAA;
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    m = pkg_;
    m[SB_MF_OFF_EPH_PUB] = 0x02; // compressed point marker
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);
}

TEST_F(Manifest, EnforcesImageSizeBounds)
{
    Bytes m = pkg_;
    put_le32(m, SB_MF_OFF_IMAGE_SIZE, 0);
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    put_le32(m, SB_MF_OFF_IMAGE_SIZE, kMaxImage);
    EXPECT_EQ(parse(m), SB_OK);

    put_le32(m, SB_MF_OFF_IMAGE_SIZE, kMaxImage + 1);
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);

    put_le32(m, SB_MF_OFF_IMAGE_SIZE, 0xFFFFFFFFu);
    EXPECT_EQ(parse(m), SB_ERR_FORMAT);
}

TEST_F(Manifest, AnyBitFlipInSignedRegionIsRejected)
{
    // Exhaustive: every single-bit corruption of the signed region must fail
    // either the structural checks or the signature. None may pass.
    for (size_t byte = 0; byte < SB_MANIFEST_SIGNED_LEN; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            Bytes m = pkg_;
            m[byte] = static_cast<uint8_t>(m[byte] ^ (1u << bit));
            ASSERT_NE(check(m), SB_OK) << "byte " << byte << " bit " << bit;
        }
    }
}

TEST_F(Manifest, AnyBitFlipInSignatureIsRejected)
{
    for (size_t byte = SB_MF_OFF_SIGNATURE; byte < SB_MANIFEST_LEN; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            Bytes m = pkg_;
            m[byte] = static_cast<uint8_t>(m[byte] ^ (1u << bit));
            ASSERT_EQ(check(m), SB_ERR_SIGNATURE) << "byte " << byte << " bit " << bit;
        }
    }
}

TEST_F(Manifest, RejectsManifestSignedByAnotherKey)
{
    // Attacker signs with their own key but cannot change the OTP anchor.
    KeyPair attacker = generate_p256();
    Bytes m = pkg_;
    resign(m, attacker);
    EXPECT_EQ(check(m), SB_ERR_SIGNATURE);
}

TEST_F(Manifest, RejectsSubstitutedRootKey)
{
    // Attacker also replaces the root public key stored in flash and fixes
    // up the key id. The OTP anchor still catches it.
    KeyPair attacker = generate_p256();
    Bytes m = pkg_;
    auto attacker_hash = sha256(attacker.pub.data(), attacker.pub.size());
    std::copy(attacker_hash.begin(), attacker_hash.begin() + SB_KEY_ID_LEN,
              m.begin() + SB_MF_OFF_KEY_ID);
    resign(m, attacker);

    sb_manifest_t mf;
    ASSERT_EQ(parse(m, &mf), SB_OK);
    EXPECT_EQ(sb_manifest_verify(m.data(), &mf, attacker.pub.data(), anchor_.data()),
              SB_ERR_KEY);
}

TEST_F(Manifest, RejectsWrongKeyId)
{
    Bytes m = pkg_;
    m[SB_MF_OFF_KEY_ID] ^= 0xFF;
    resign(m, *root_); // validly signed, but claims a different key
    EXPECT_EQ(check(m), SB_ERR_KEY);
}

TEST_F(Manifest, NullArgumentsAreRejected)
{
    sb_manifest_t mf;
    EXPECT_EQ(sb_manifest_parse(nullptr, SB_MANIFEST_LEN, kMaxImage, &mf), SB_ERR_PARAM);
    EXPECT_EQ(sb_manifest_parse(pkg_.data(), SB_MANIFEST_LEN, kMaxImage, nullptr),
              SB_ERR_PARAM);
    EXPECT_EQ(sb_manifest_verify(nullptr, &mf, root_->pub.data(), anchor_.data()),
              SB_ERR_PARAM);
}

}  // namespace

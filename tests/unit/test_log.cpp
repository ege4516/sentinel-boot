// SPDX-License-Identifier: MIT
// What the transparency log adds: a stolen firmware root key is not enough.
#include <gtest/gtest.h>

#include <cstring>

#include "support/device.h"

using namespace sbtest;

namespace {

constexpr uint32_t kV1 = 0x01000000, kV2 = 0x02000000, kV3 = 0x03000000;

class LogReject : public ::testing::Test {
protected:
    static void SetUpTestSuite() { keys_ = new Keys(Keys::generate()); }
    static void TearDownTestSuite() { delete keys_; }

    void SetUp() override
    {
        dev = std::make_unique<Device>(*keys_);
        img1 = make_image(6000, 1);
        img2 = make_image(7000, 2);
        dev->install_confirmed(dev->package(kV1, 1, img1));
    }

    PackageSpec spec(uint32_t version, uint32_t counter) const
    {
        PackageSpec s;
        s.fw_version = version;
        s.security_counter = counter;
        s.image = img2;
        return s;
    }

    // Stage a package that must be refused for `reason`; v1 keeps running.
    void expect_rejected(const Bytes &pkg, sb_err_t reason)
    {
        ASSERT_EQ(dev->stage(pkg), SB_OK);
        sb_boot_result_t res{};
        ASSERT_EQ(dev->boot(&res), SB_OK);
        EXPECT_TRUE(res.events & SB_EVT_UPDATE_REJECTED);
        EXPECT_FALSE(res.events & SB_EVT_INSTALLED);
        EXPECT_EQ(res.reject_reason, reason) << sb_strerror(res.reject_reason);
        EXPECT_EQ(dev->read_image(res), img1);
        EXPECT_EQ(dev->otp_counter(), 1u);
    }

    static Keys *keys_;
    std::unique_ptr<Device> dev;
    Bytes img1, img2;
};
Keys *LogReject::keys_ = nullptr;

TEST_F(LogReject, ReleaseThatWasNeverLogged)
{
    // The attacker holds the firmware root key and signs a release, but cannot
    // get it into the log: the proof block is empty.
    Bytes pkg = make_package(spec(kV2, 2), dev->keys().root, dev->keys().device.pub, nullptr);
    expect_rejected(pkg, SB_ERR_LOG);
}

TEST_F(LogReject, ProofCopiedFromAnotherRelease)
{
    // Same attacker, now replaying the proof block of a genuine, logged release.
    Bytes genuine = dev->package(kV2, 2, img2);
    Bytes pkg = make_package(spec(kV3, 3), dev->keys().root, dev->keys().device.pub, nullptr);
    std::memcpy(&pkg[SB_MANIFEST_LEN], &genuine[SB_MANIFEST_LEN], SB_PROOF_LEN);
    expect_rejected(pkg, SB_ERR_LOG);
}

TEST_F(LogReject, TreeHeadSignedByTheRootKey)
{
    // The attacker runs a fake log signed with the firmware root key (the only
    // key they have). The device checks tree heads against the *log* key.
    TestLog fake(dev->keys().root);
    Bytes pkg = make_package(spec(kV2, 2), dev->keys().root, dev->keys().device.pub, &fake);
    expect_rejected(pkg, SB_ERR_LOG_SIGNATURE);
}

TEST_F(LogReject, SubstitutedLogKeyInFlash)
{
    // The attacker also swaps the log public key kept in ordinary flash for
    // their own. The OTP log anchor no longer matches its hash.
    KeyPair evil_log = generate_p256();
    TestLog fake(evil_log);
    Bytes pkg = make_package(spec(kV2, 2), dev->keys().root, dev->keys().device.pub, &fake);

    // The reason code, checked directly against the real OTP anchor.
    const auto anchor = sha256(dev->keys().log.pub.data(), dev->keys().log.pub.size());
    sb_proof_t proof;
    ASSERT_EQ(sb_proof_parse(&pkg[SB_MANIFEST_LEN], SB_PROOF_LEN, &proof), SB_OK);
    EXPECT_EQ(sb_proof_verify(pkg.data(), &proof, evil_log.pub.data(), anchor.data()),
              SB_ERR_LOG_KEY);

    // On the device the swap fails closed: not even the running v1 can be
    // authenticated any more, so nothing is booted.
    ASSERT_EQ(dev->stage(pkg), SB_OK);
    dev->ctx->log_pub = evil_log.pub.data();
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
    EXPECT_EQ(dev->otp_counter(), 1u);
}

TEST_F(LogReject, PreviousFormatWithoutProofIsRefused)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    pkg[SB_MF_OFF_FORMAT] = 1;
    dev->resign(pkg);
    expect_rejected(pkg, SB_ERR_FORMAT);
}

TEST_F(LogReject, LeafIndexOutsideTheTree)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    put_le32(pkg, SB_MANIFEST_LEN + SB_PF_OFF_INDEX, 99);
    expect_rejected(pkg, SB_ERR_LOG);
}

TEST_F(LogReject, ProofForAModifiedManifest)
{
    // A genuine log entry exists for the original manifest; the attacker edits
    // a field and re-signs with the root key but cannot add a new log entry.
    Bytes pkg = dev->package(kV2, 2, img2);
    put_le32(pkg, SB_MF_OFF_SEC_COUNTER, 50);
    sbtest::resign(pkg, dev->keys().root);
    expect_rejected(pkg, SB_ERR_LOG);
}

TEST_F(LogReject, EveryBitOfTheProofBlockMatters)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    const Bytes manifest(pkg.begin(), pkg.begin() + SB_MANIFEST_LEN);
    const Bytes proof(pkg.begin() + SB_MANIFEST_LEN, pkg.begin() + SB_HEADER_LEN);
    const auto anchor = sha256(dev->keys().log.pub.data(), dev->keys().log.pub.size());

    auto check = [&](const Bytes &m, const Bytes &p) {
        sb_proof_t parsed;
        sb_err_t err = sb_proof_parse(p.data(), p.size(), &parsed);
        if (err == SB_OK) {
            err = sb_proof_verify(m.data(), &parsed, dev->keys().log.pub.data(), anchor.data());
        }
        return err;
    };
    ASSERT_EQ(check(manifest, proof), SB_OK);

    for (size_t byte = 0; byte < proof.size(); byte++) {
        for (int bit = 0; bit < 8; bit++) {
            Bytes p = proof;
            p[byte] = static_cast<uint8_t>(p[byte] ^ (1u << bit));
            ASSERT_NE(check(manifest, p), SB_OK) << "proof byte " << byte << " bit " << bit;
        }
    }
    // The leaf is the signed manifest region, so every bit of it matters too.
    for (size_t byte = 0; byte < SB_MANIFEST_SIGNED_LEN; byte++) {
        Bytes m = manifest;
        m[byte] ^= 0x01;
        ASSERT_EQ(check(m, proof), SB_ERR_LOG) << "manifest byte " << byte;
    }
}

TEST(LogAccept, ReleasesFromDifferentTreeHeadsAreBothAccepted)
{
    // Documented limitation: the device keeps no log state and checks no
    // consistency between tree heads, so proofs against older or newer heads
    // are all fine as long as each is signed by the log key.
    Keys keys = Keys::generate();
    Device dev(keys);
    Bytes img1 = make_image(3000, 1), img2 = make_image(3500, 2);
    Bytes old_head = dev.package(kV1, 1, img1);   // logged at tree size 1
    Bytes new_head = dev.package(kV2, 2, img2);   // logged at tree size 2
    dev.install_confirmed(new_head);
    sb_boot_result_t res{};
    ASSERT_EQ(dev.stage(old_head), SB_OK);
    ASSERT_EQ(dev.boot(&res), SB_OK);
    // v1's proof is valid, but its counter is behind: the rollback check, not
    // the log, is what refuses it.
    EXPECT_EQ(res.reject_reason, SB_ERR_ROLLBACK);
}

}  // namespace

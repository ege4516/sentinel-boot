// SPDX-License-Identifier: MIT
// End-to-end behaviour of the boot / update state machine on a simulated device.
#include <gtest/gtest.h>

#include <algorithm>

#include "support/device.h"

using namespace sbtest;

namespace {

constexpr uint32_t kV1 = 0x01000000, kV2 = 0x02000000, kV3 = 0x03000000;

class Boot : public ::testing::Test {
protected:
    static void SetUpTestSuite() { keys_ = new Keys(Keys::generate()); }
    static void TearDownTestSuite() { delete keys_; }

    void SetUp() override
    {
        dev = std::make_unique<Device>(*keys_);
        img1 = make_image(20000, 1);
        img2 = make_image(23456, 2);
        img3 = make_image(9000, 3);
    }

    void TearDown() override
    {
        // The core must always erase before programming.
        EXPECT_EQ(dev->fsim.violations, 0u) << "flash was programmed without erase";
    }

    // Boot and expect a specific image to be selected.
    sb_boot_result_t boot_expect(const Bytes &image)
    {
        sb_boot_result_t res{};
        EXPECT_EQ(dev->boot(&res), SB_OK);
        EXPECT_EQ(dev->read_image(res), image);
        return res;
    }

    static Keys *keys_;
    std::unique_ptr<Device> dev;
    Bytes img1, img2, img3;
};
Keys *Boot::keys_ = nullptr;

// ---- Happy path -----------------------------------------------------------

TEST_F(Boot, BlankDeviceHasNothingToBoot)
{
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE); // and stays that way
}

TEST_F(Boot, FirstInstallBootsAsTrialThenConfirms)
{
    ASSERT_EQ(dev->stage(dev->package(kV1, 1, img1)), SB_OK);
    EXPECT_EQ(dev->state().slot[1], SB_SLOT_DOWNLOADED);

    sb_boot_result_t res = boot_expect(img1);
    EXPECT_TRUE(res.events & SB_EVT_INSTALLED);
    EXPECT_TRUE(res.events & SB_EVT_TRIAL_BOOT);
    EXPECT_EQ(res.manifest.fw_version, kV1);
    EXPECT_EQ(dev->state().slot[res.slot], SB_SLOT_TRIAL);
    EXPECT_EQ(dev->otp_counter(), 0u) << "counter must not move before confirm";

    ASSERT_EQ(dev->confirm(), SB_OK);
    EXPECT_EQ(dev->state().slot[res.slot], SB_SLOT_CONFIRMED);
    EXPECT_EQ(dev->otp_counter(), 1u);

    res = boot_expect(img1);
    EXPECT_EQ(res.events, 0u) << "a confirmed image boots with no side effects";
    EXPECT_EQ(dev->confirm(), SB_OK) << "confirm is idempotent";
}

TEST_F(Boot, UpdateSwitchesSlotsAndKeepsOldImageAsFallback)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    uint8_t old_slot = dev->state().active;

    ASSERT_EQ(dev->stage(dev->package(kV2, 2, img2)), SB_OK);
    sb_boot_result_t res = boot_expect(img2);
    EXPECT_NE(res.slot, old_slot);
    EXPECT_EQ(dev->state().slot[old_slot], SB_SLOT_CONFIRMED);

    ASSERT_EQ(dev->confirm(), SB_OK);
    EXPECT_EQ(dev->otp_counter(), 2u);
    boot_expect(img2);
}

TEST_F(Boot, StagedPackageIsEncryptedAtRest)
{
    ASSERT_EQ(dev->stage(dev->package(kV1, 1, img1)), SB_OK);
    const uint8_t *flash = dev->raw();
    // No 32-byte window of the plaintext may appear anywhere in flash.
    for (size_t off = 0; off + 32 <= img1.size(); off += 32) {
        auto it = std::search(flash, flash + Device::kFlashSize, img1.begin() + static_cast<long>(off),
                              img1.begin() + static_cast<long>(off) + 32);
        ASSERT_EQ(it, flash + Device::kFlashSize) << "plaintext leaked at image offset " << off;
    }
}

TEST_F(Boot, StagingWithoutFinishIsIgnored)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    Bytes pkg = dev->package(kV2, 2, img2);
    ASSERT_EQ(sb_update_begin(dev->ctx.get()), SB_OK);
    ASSERT_EQ(sb_update_write(dev->ctx.get(), 0, pkg.data(), pkg.size()), SB_OK);
    // no sb_update_finish(): e.g. the download was interrupted
    sb_boot_result_t res = boot_expect(img1);
    EXPECT_EQ(res.events, 0u);
}

class BootSizes : public Boot, public ::testing::WithParamInterface<uint32_t> {};

TEST_P(BootSizes, InstallsImageOfSize)
{
    Bytes img = make_image(GetParam(), GetParam());
    ASSERT_EQ(dev->stage(dev->package(kV1, 1, img), 777), SB_OK);
    sb_boot_result_t res = boot_expect(img);
    EXPECT_TRUE(res.events & SB_EVT_INSTALLED);
    EXPECT_EQ(res.manifest.image_size, GetParam());
}

INSTANTIATE_TEST_SUITE_P(Boundaries, BootSizes,
                         ::testing::Values(1u, 15u, 16u, 17u, 4095u, 4096u, 4097u, 8192u,
                                           Device::kSlotSize - Device::kSector - 1,
                                           Device::kSlotSize - Device::kSector));

// ---- Rejected updates -----------------------------------------------------

class BootReject : public Boot {
protected:
    void SetUp() override
    {
        Boot::SetUp();
        dev->install_confirmed(dev->package(kV1, 1, img1));
    }

    // Stage a bad package; the device must reject it for the given reason
    // and keep running v1.
    void expect_rejected(const Bytes &pkg, sb_err_t reason)
    {
        ASSERT_EQ(dev->stage(pkg), SB_OK);
        uint8_t target = static_cast<uint8_t>(dev->state().active ^ 1u);
        sb_boot_result_t res = boot_expect(img1);
        EXPECT_TRUE(res.events & SB_EVT_UPDATE_REJECTED);
        EXPECT_FALSE(res.events & SB_EVT_INSTALLED);
        EXPECT_EQ(res.reject_reason, reason) << sb_strerror(res.reject_reason);
        EXPECT_EQ(dev->state().slot[target], SB_SLOT_INVALID);
        EXPECT_EQ(dev->otp_counter(), 1u);
        // And it stays rejected: no retry loop on the next boot.
        res = boot_expect(img1);
        EXPECT_EQ(res.events, 0u);
    }
};

TEST_F(BootReject, TamperedCiphertext)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    pkg[SB_HEADER_LEN + 5000] ^= 0x01;
    expect_rejected(pkg, SB_ERR_DIGEST);
}

TEST_F(BootReject, TruncatedPackage)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    pkg.resize(pkg.size() - 100); // tail stays erased (0xFF)
    expect_rejected(pkg, SB_ERR_DIGEST);
}

TEST_F(BootReject, TamperedManifestField)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    put_le32(pkg, SB_MF_OFF_SEC_COUNTER, 100);
    expect_rejected(pkg, SB_ERR_SIGNATURE);
}

TEST_F(BootReject, SignedByAttackerKey)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    sbtest::resign(pkg, generate_p256());
    relog(pkg, dev->log()); // the log accepts anything; the root signature must still fail
    expect_rejected(pkg, SB_ERR_SIGNATURE);
}

TEST_F(BootReject, GarbageInsteadOfPackage)
{
    expect_rejected(random_bytes(5000), SB_ERR_FORMAT);
}

TEST_F(BootReject, OversizedImageSizeField)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    put_le32(pkg, SB_MF_OFF_IMAGE_SIZE, 0x7FFFFFFF);
    dev->resign(pkg); // even a validly signed and logged manifest is bounded
    expect_rejected(pkg, SB_ERR_FORMAT);
}

TEST_F(BootReject, RollbackToOlderSecurityCounter)
{
    // Bring the device to counter 5, then replay a genuine, validly signed
    // older release.
    dev->install_confirmed(dev->package(kV2, 5, img2));
    ASSERT_EQ(dev->otp_counter(), 5u);

    Bytes old_release = dev->package(kV1, 4, img1);
    ASSERT_EQ(dev->stage(old_release), SB_OK);
    sb_boot_result_t res = boot_expect(img2);
    EXPECT_TRUE(res.events & SB_EVT_UPDATE_REJECTED);
    EXPECT_EQ(res.reject_reason, SB_ERR_ROLLBACK);
    EXPECT_EQ(dev->otp_counter(), 5u);
}

TEST_F(BootReject, PackageEncryptedForAnotherDevice)
{
    // Correctly signed by the vendor but wrapped for a different device key:
    // the signature and ciphertext digest pass, the AEAD tag does not.
    PackageSpec spec;
    spec.fw_version = kV2;
    spec.security_counter = 2;
    spec.image = img2;
    Bytes pkg = make_package(spec, dev->keys().root, generate_p256().pub, &dev->log());
    expect_rejected(pkg, SB_ERR_AUTH);
}

TEST_F(BootReject, HeaderIsBoundToCiphertextAsAad)
{
    // A signer-level mistake (or a malicious insider with signing access but
    // not the plaintext) re-labels an existing ciphertext with a new version.
    Bytes pkg = dev->package(kV2, 2, img2);
    put_le32(pkg, SB_MF_OFF_FW_VERSION, kV3);
    dev->resign(pkg);
    expect_rejected(pkg, SB_ERR_AUTH);
}

TEST_F(BootReject, WrongPlaintextDigest)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    pkg[SB_MF_OFF_PT_DIGEST] ^= 0x01;
    dev->resign(pkg);
    expect_rejected(pkg, SB_ERR_DIGEST);
}

TEST_F(BootReject, EphemeralKeyNotOnCurve)
{
    Bytes pkg = dev->package(kV2, 2, img2);
    pkg[SB_MF_OFF_EPH_PUB + 64] ^= 0x01;
    dev->resign(pkg);
    ASSERT_EQ(dev->stage(pkg), SB_OK);
    sb_boot_result_t res = boot_expect(img1);
    EXPECT_TRUE(res.events & SB_EVT_UPDATE_REJECTED);
    EXPECT_NE(res.reject_reason, SB_OK);
}

TEST_F(BootReject, EqualSecurityCounterIsAccepted)
{
    // The counter gates security-relevant downgrades only; a release that
    // does not bump it stays installable (and revertible).
    ASSERT_EQ(dev->stage(dev->package(kV2, 1, img2)), SB_OK);
    sb_boot_result_t res = boot_expect(img2);
    EXPECT_TRUE(res.events & SB_EVT_INSTALLED);
}

// ---- Trial / revert -------------------------------------------------------

TEST_F(Boot, UnconfirmedUpdateRevertsAfterTrialsExpire)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    ASSERT_EQ(dev->stage(dev->package(kV2, 2, img2)), SB_OK);

    for (unsigned i = 0; i < SB_DEFAULT_TRIALS; i++) {
        sb_boot_result_t res = boot_expect(img2);
        EXPECT_TRUE(res.events & SB_EVT_TRIAL_BOOT) << "boot " << i;
    }
    sb_boot_result_t res = boot_expect(img1);
    EXPECT_TRUE(res.events & SB_EVT_REVERTED);
    EXPECT_EQ(dev->otp_counter(), 1u) << "an unconfirmed image must not burn the counter";

    res = boot_expect(img1);
    EXPECT_EQ(res.events, 0u);

    // The device is still updatable afterwards.
    ASSERT_EQ(dev->stage(dev->package(kV3, 2, img3)), SB_OK);
    boot_expect(img3);
}

TEST_F(Boot, UpdateIsRefusedWhileRunningImageIsOnTrial)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    ASSERT_EQ(dev->stage(dev->package(kV2, 2, img2)), SB_OK);
    boot_expect(img2); // v2 on trial, v1 is the only fallback

    EXPECT_EQ(sb_update_begin(dev->ctx.get()), SB_ERR_STATE);
    // v1 must still be intact: let the trial expire and check.
    for (unsigned i = 1; i < SB_DEFAULT_TRIALS; i++) {
        boot_expect(img2);
    }
    boot_expect(img1);
}

// ---- Verified on every boot ----------------------------------------------

TEST_F(Boot, CorruptedActiveImageFallsBackToConfirmedSlot)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->install_confirmed(dev->package(kV2, 1, img2)); // same counter: v1 stays valid
    sb_state_t st = dev->state();

    dev->raw()[dev->image_off(st.active) + 1234] ^= 0x10; // bit rot / tampering
    sb_boot_result_t res = boot_expect(img1);
    EXPECT_TRUE(res.events & SB_EVT_REVERTED);
    EXPECT_EQ(dev->state().slot[st.active], SB_SLOT_INVALID);
}

TEST_F(Boot, CorruptedOnlyImageRefusesToBoot)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->raw()[dev->image_off(dev->state().active)] ^= 0x01;
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
}

TEST_F(Boot, NeverFallsBackToAnUnconfirmedSlot)
{
    // v2 never confirms and is reverted: its slot is INVALID but still holds
    // a perfectly valid signed image. If the confirmed v1 is then damaged,
    // the bootloader must not "rescue" itself by switching to that slot.
    dev->install_confirmed(dev->package(kV1, 1, img1));
    ASSERT_EQ(dev->stage(dev->package(kV2, 1, img2)), SB_OK);
    for (unsigned i = 0; i <= SB_DEFAULT_TRIALS; i++) {
        sb_boot_result_t res{};
        ASSERT_EQ(dev->boot(&res), SB_OK);
    }
    sb_state_t st = dev->state();
    ASSERT_EQ(st.slot[st.active ^ 1], SB_SLOT_INVALID);

    dev->raw()[dev->image_off(st.active) + 99] ^= 0x01;
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
    EXPECT_EQ(dev->state().active, st.active) << "switched to a slot that was never confirmed";
}

TEST_F(Boot, StateRecordWithBadCrcIsIgnored)
{
    // Corrupt a field of the newest record so that it still looks plausible
    // (trials_left 0 -> 1). Only the CRC can tell; the loader must discard
    // the record and fall back to the previous one.
    dev->install_confirmed(dev->package(kV1, 1, img1));
    sb_state_t before = dev->state();
    dev->raw()[dev->layout.state_off[before.copy] + 11] ^= 0x01;

    sb_state_t after = dev->state();
    EXPECT_LT(after.seq, before.seq);
}

TEST_F(Boot, TamperedManifestOfInstalledImageRefusesToBoot)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->raw()[dev->slot_off(dev->state().active) + SB_MF_OFF_FW_VERSION] ^= 0x01;
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
}

TEST_F(Boot, ConfirmedCounterBumpRetiresOlderFallback)
{
    // Documented consequence of anti-rollback: once v2 (counter 2) is
    // confirmed, v1 (counter 1) is no longer an acceptable fallback.
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->install_confirmed(dev->package(kV2, 2, img2));
    dev->raw()[dev->image_off(dev->state().active) + 7] ^= 0x01;
    sb_boot_result_t res{};
    EXPECT_EQ(dev->boot(&res), SB_ERR_NO_IMAGE);
}

// ---- Recovery paths -------------------------------------------------------

TEST_F(Boot, RebuildsStateWhenBothCopiesAreLost)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->install_confirmed(dev->package(kV2, 1, img2));
    std::fill(dev->raw(), dev->raw() + 2 * Device::kSector, 0xFF);

    sb_boot_result_t res = boot_expect(img2); // highest version wins
    EXPECT_TRUE(res.events & SB_EVT_STATE_RECOVERED);
    res = boot_expect(img2);
    EXPECT_EQ(res.events, 0u);
}

TEST_F(Boot, SurvivesOneCorruptedStateCopy)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    sb_state_t st = dev->state();
    dev->raw()[dev->layout.state_off[st.copy] + 9] ^= 0xFF; // newest copy destroyed
    // Falls back to the previous record; whatever it says, a verified image boots.
    sb_boot_result_t res{};
    ASSERT_EQ(dev->boot(&res), SB_OK);
    EXPECT_EQ(dev->read_image(res), img1);
}

TEST_F(Boot, FinishesCounterAdvanceInterruptedAfterConfirm)
{
    dev->install_confirmed(dev->package(kV1, 1, img1));
    dev->install_confirmed(dev->package(kV2, 2, img2));
    // Model power loss between the CONFIRMED state write and the fuse write.
    dev->osim.counter = 1;

    sb_boot_result_t res = boot_expect(img2);
    EXPECT_TRUE(res.events & SB_EVT_COUNTER_ADVANCED);
    EXPECT_EQ(dev->otp_counter(), 2u);
}

// ---- API misuse -----------------------------------------------------------

TEST_F(Boot, UpdateWriteEnforcesBounds)
{
    Bytes buf(64, 0xAB);
    uint32_t max_pkg = SB_HEADER_LEN + dev->max_image();
    ASSERT_EQ(sb_update_begin(dev->ctx.get()), SB_OK);
    EXPECT_EQ(sb_update_write(dev->ctx.get(), max_pkg - 63, buf.data(), 64), SB_ERR_RANGE);
    EXPECT_EQ(sb_update_write(dev->ctx.get(), 0xFFFFFFF0u, buf.data(), 64), SB_ERR_RANGE);
    EXPECT_EQ(sb_update_write(dev->ctx.get(), max_pkg, buf.data(), 1), SB_ERR_RANGE);
    EXPECT_EQ(sb_update_write(dev->ctx.get(), max_pkg - 64, buf.data(), 64), SB_OK);
    EXPECT_EQ(sb_update_write(dev->ctx.get(), 0, nullptr, 4), SB_ERR_PARAM);
}

TEST_F(Boot, WriteAndFinishRequireBegin)
{
    Bytes pkg = dev->package(kV1, 1, img1);
    ASSERT_EQ(dev->stage(pkg), SB_OK); // slot is now DOWNLOADED
    EXPECT_EQ(sb_update_write(dev->ctx.get(), 0, pkg.data(), 16), SB_ERR_STATE);
    EXPECT_EQ(sb_update_finish(dev->ctx.get()), SB_ERR_STATE);
}

TEST_F(Boot, ConfirmWithoutImageFails)
{
    EXPECT_EQ(dev->confirm(), SB_ERR_STATE);
}

TEST_F(Boot, ContextInitValidatesLayout)
{
    sb_flash_t flash{};
    sb_otp_t otp{};
    sb_flash_sim_bind(&dev->fsim, &flash);
    sb_otp_sim_bind(&dev->osim, &otp);
    auto ctx = std::make_unique<sb_ctx_t>();
    const uint8_t *pub = dev->keys().root.pub.data();

    const uint8_t *log_pub = dev->keys().log.pub.data();
    sb_layout_t ok = dev->layout;
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &ok, pub, log_pub), SB_OK);

    sb_layout_t bad = ok;
    bad.slot_off[1] = bad.slot_off[0] + Device::kSector; // overlapping slots
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &bad, pub, log_pub), SB_ERR_PARAM);

    bad = ok;
    bad.slot_off[1] += Device::kSector; // runs past the end of flash
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &bad, pub, log_pub), SB_ERR_PARAM);

    bad = ok;
    bad.state_off[1] = bad.state_off[0]; // both state copies in one sector
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &bad, pub, log_pub), SB_ERR_PARAM);

    bad = ok;
    bad.slot_off[0] += 16; // not sector aligned
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &bad, pub, log_pub), SB_ERR_PARAM);

    bad = ok;
    bad.slot_size = Device::kSector; // no room for an image
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &bad, pub, log_pub), SB_ERR_PARAM);

    EXPECT_EQ(sb_ctx_init(nullptr, &flash, &otp, &ok, pub, log_pub), SB_ERR_PARAM);
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &ok, nullptr, log_pub), SB_ERR_PARAM);
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &otp, &ok, pub, nullptr), SB_ERR_PARAM);

    // One key must not hold both roles: equal anchors are refused.
    sb_otp_sim_t same = dev->osim;
    std::memcpy(same.log_key_hash, same.root_key_hash, 32);
    sb_otp_t same_otp{};
    sb_otp_sim_bind(&same, &same_otp);
    EXPECT_EQ(sb_ctx_init(ctx.get(), &flash, &same_otp, &ok, pub, log_pub), SB_ERR_KEY);
}

}  // namespace

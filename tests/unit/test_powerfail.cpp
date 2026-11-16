// SPDX-License-Identifier: MIT
// Exhaustive power-loss injection.
//
// For a given scenario the test first counts how many flash write/erase
// operations it performs, then replays it once per operation with power cut
// at exactly that point (the interrupted operation is applied partially).
// After every cut the device is "rebooted" and must satisfy the invariants:
//
//   1. it boots a correctly signed image whose bytes match a known release;
//   2. the OTP counter never exceeds the booted image's security counter;
//   3. it can still complete a further update.
#include <gtest/gtest.h>

#include <functional>

#include "support/device.h"

using namespace sbtest;

namespace {

constexpr uint32_t kV1 = 0x01000000, kV2 = 0x02000000, kV3 = 0x03000000;

class PowerFail : public ::testing::Test {
protected:
    static void SetUpTestSuite() { keys_ = new Keys(Keys::generate()); }
    static void TearDownTestSuite() { delete keys_; }

    void SetUp() override
    {
        dev = std::make_unique<Device>(*keys_);
        img1 = make_image(9000, 1);
        img2 = make_image(13000, 2);
        img3 = make_image(5000, 3);
        pkg1 = dev->package(kV1, 1, img1);
        pkg2 = dev->package(kV2, 2, img2);
        pkg3 = dev->package(kV3, 2, img3);
    }

    // Number of mutating flash operations a scenario performs when nothing fails.
    uint32_t count_ops(const Device::Snapshot &base, const std::function<void(Device &)> &scenario)
    {
        dev->restore(base);
        dev->fsim.op_count = 0;
        scenario(*dev);
        EXPECT_FALSE(dev->fsim.powered_off);
        return dev->fsim.op_count;
    }

    // Invariant 3: whatever happened, the device accepts and runs a new release.
    void expect_still_updatable()
    {
        sb_boot_result_t res{};
        // An image left on trial must be confirmed (or expire) before the
        // other slot may be overwritten.
        ASSERT_EQ(dev->confirm(), SB_OK);
        ASSERT_EQ(dev->stage(pkg3), SB_OK);
        ASSERT_EQ(dev->boot(&res), SB_OK);
        ASSERT_TRUE(res.events & SB_EVT_INSTALLED) << sb_strerror(res.reject_reason);
        ASSERT_EQ(dev->read_image(res), img3);
        ASSERT_EQ(dev->confirm(), SB_OK);
    }

    static Keys *keys_;
    std::unique_ptr<Device> dev;
    Bytes img1, img2, img3, pkg1, pkg2, pkg3;
};
Keys *PowerFail::keys_ = nullptr;

TEST_F(PowerFail, AnyCutDuringUpdateLeavesBootableDevice)
{
    dev->install_confirmed(pkg1);
    const Device::Snapshot base = dev->snapshot();

    // Full life cycle of an update: download, install, confirm, reboot.
    auto scenario = [&](Device &d) {
        sb_boot_result_t res{};
        if (d.stage(pkg2) != SB_OK) return;
        if (d.boot(&res) != SB_OK) return;
        if (d.confirm() != SB_OK) return;
        (void)d.boot(&res);
    };

    const uint32_t total = count_ops(base, scenario);
    ASSERT_GT(total, 20u);

    int kept_old = 0, got_new = 0, resumed = 0;
    for (uint32_t cut = 0; cut < total; cut++) {
        SCOPED_TRACE("power cut at flash operation " + std::to_string(cut));
        dev->restore(base);
        sb_flash_sim_fail_at(&dev->fsim, cut);
        scenario(*dev);
        ASSERT_TRUE(dev->fsim.powered_off);

        sb_flash_sim_power_cycle(&dev->fsim); // reboot
        sb_boot_result_t res{};
        ASSERT_EQ(dev->boot(&res), SB_OK);

        Bytes running = dev->read_image(res);
        ASSERT_TRUE(running == img1 || running == img2);
        ASSERT_EQ(res.manifest.fw_version, running == img1 ? kV1 : kV2);
        ASSERT_GE(res.manifest.security_counter, dev->otp_counter());
        ASSERT_GE(dev->otp_counter(), 1u);
        (running == img1 ? kept_old : got_new)++;
        if (res.events & SB_EVT_INSTALL_RESUMED) {
            resumed++;
        }

        expect_still_updatable();
        ASSERT_EQ(dev->fsim.violations, 0u);
    }

    // Sanity: the sweep really exercised both outcomes and the resume path.
    EXPECT_GT(kept_old, 0);
    EXPECT_GT(got_new, 0);
    EXPECT_GT(resumed, 0);
    RecordProperty("cut_points", static_cast<int>(total));
    RecordProperty("kept_old", kept_old);
    RecordProperty("got_new", got_new);
}

TEST_F(PowerFail, AnyCutDuringTrialExpiryLeavesBootableDevice)
{
    dev->install_confirmed(pkg1);
    ASSERT_EQ(dev->stage(pkg2), SB_OK);
    const Device::Snapshot base = dev->snapshot();

    // The new image never confirms: install, burn all trials, revert.
    auto scenario = [&](Device &d) {
        sb_boot_result_t res{};
        for (unsigned i = 0; i < SB_DEFAULT_TRIALS + 2; i++) {
            if (d.boot(&res) != SB_OK) return;
        }
    };

    const uint32_t total = count_ops(base, scenario);
    ASSERT_GT(total, 5u);

    for (uint32_t cut = 0; cut < total; cut++) {
        SCOPED_TRACE("power cut at flash operation " + std::to_string(cut));
        dev->restore(base);
        sb_flash_sim_fail_at(&dev->fsim, cut);
        scenario(*dev);
        ASSERT_TRUE(dev->fsim.powered_off);
        sb_flash_sim_power_cycle(&dev->fsim);

        // Keep rebooting without ever confirming: every boot must succeed and
        // the device must settle back on the confirmed v1.
        Bytes running;
        for (unsigned i = 0; i < SB_DEFAULT_TRIALS + 3; i++) {
            sb_boot_result_t res{};
            ASSERT_EQ(dev->boot(&res), SB_OK) << "reboot " << i;
            running = dev->read_image(res);
            ASSERT_TRUE(running == img1 || running == img2);
        }
        ASSERT_EQ(running, img1);
        ASSERT_EQ(dev->otp_counter(), 1u);
        ASSERT_EQ(dev->fsim.violations, 0u);
    }
}

TEST_F(PowerFail, AnyCutDuringFirstInstallIsRecoverable)
{
    const Device::Snapshot base = dev->snapshot(); // blank, provisioned device

    auto scenario = [&](Device &d) {
        sb_boot_result_t res{};
        if (d.stage(pkg1) != SB_OK) return;
        if (d.boot(&res) != SB_OK) return;
        (void)d.confirm();
    };

    const uint32_t total = count_ops(base, scenario);
    for (uint32_t cut = 0; cut < total; cut++) {
        SCOPED_TRACE("power cut at flash operation " + std::to_string(cut));
        dev->restore(base);
        sb_flash_sim_fail_at(&dev->fsim, cut);
        scenario(*dev);
        ASSERT_TRUE(dev->fsim.powered_off);
        sb_flash_sim_power_cycle(&dev->fsim);

        // With no previous image there is nothing to fall back to, so "no
        // image" is a legitimate outcome. What must never happen is booting
        // something that is not exactly the signed release.
        sb_boot_result_t res{};
        sb_err_t err = dev->boot(&res);
        if (err == SB_OK) {
            ASSERT_EQ(dev->read_image(res), img1);
        } else {
            ASSERT_EQ(err, SB_ERR_NO_IMAGE);
            // Factory flow simply retries.
            ASSERT_EQ(dev->stage(pkg1), SB_OK);
            ASSERT_EQ(dev->boot(&res), SB_OK);
            ASSERT_EQ(dev->read_image(res), img1);
        }
        ASSERT_EQ(dev->fsim.violations, 0u);
    }
}

}  // namespace

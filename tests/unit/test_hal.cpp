// SPDX-License-Identifier: MIT
// The simulators must be trustworthy before tests built on them mean anything.
#include <gtest/gtest.h>

#include <vector>

extern "C" {
#include "hal/flash_sim.h"
#include "hal/otp_sim.h"
}

namespace {

class FlashSim : public ::testing::Test {
protected:
    void SetUp() override
    {
        mem.resize(4 * 256);
        sb_flash_sim_init(&sim, mem.data(), static_cast<uint32_t>(mem.size()), 256);
        sb_flash_sim_bind(&sim, &flash);
    }
    std::vector<uint8_t> mem;
    sb_flash_sim_t sim{};
    sb_flash_t flash{};
};

TEST_F(FlashSim, StartsErased)
{
    for (uint8_t b : mem) {
        ASSERT_EQ(b, 0xFF);
    }
}

TEST_F(FlashSim, WriteOnlyClearsBits)
{
    const uint8_t a[] = {0xF0, 0x0F};
    const uint8_t b[] = {0x3C, 0xFF};
    ASSERT_EQ(flash.write(flash.dev, 10, a, 2), 0);
    EXPECT_EQ(sim.violations, 0u);
    ASSERT_EQ(flash.write(flash.dev, 10, b, 2), 0);
    EXPECT_EQ(mem[10], 0x30); // AND of both writes
    EXPECT_EQ(mem[11], 0x0F); // 0xFF over 0x0F cannot set bits
    EXPECT_GT(sim.violations, 0u);
}

TEST_F(FlashSim, EraseRestoresSectorOnly)
{
    std::vector<uint8_t> zeros(512, 0);
    ASSERT_EQ(flash.write(flash.dev, 0, zeros.data(), zeros.size()), 0);
    ASSERT_EQ(flash.erase(flash.dev, 256), 0);
    EXPECT_EQ(mem[255], 0x00);
    EXPECT_EQ(mem[256], 0xFF);
    EXPECT_EQ(mem[511], 0xFF);
}

TEST_F(FlashSim, RejectsOutOfRangeAndMisaligned)
{
    uint8_t buf[8] = {0};
    EXPECT_NE(flash.read(flash.dev, 1020, buf, 8), 0);
    EXPECT_NE(flash.write(flash.dev, 0xFFFFFFFFu, buf, 8), 0);
    EXPECT_NE(flash.erase(flash.dev, 100), 0);
    EXPECT_NE(flash.erase(flash.dev, 1024), 0);
    EXPECT_EQ(flash.read(flash.dev, 1016, buf, 8), 0);
}

TEST_F(FlashSim, PowerLossAppliesPartialWriteThenFailsEverything)
{
    std::vector<uint8_t> data(100, 0x00);
    uint8_t probe = 0;
    sb_flash_sim_fail_at(&sim, 1);
    ASSERT_EQ(flash.write(flash.dev, 0, data.data(), 100), 0);    // op 0: fine
    EXPECT_NE(flash.write(flash.dev, 256, data.data(), 100), 0);  // op 1: cut
    EXPECT_EQ(mem[256 + 49], 0x00);
    EXPECT_EQ(mem[256 + 50], 0xFF); // second half never written
    EXPECT_NE(flash.read(flash.dev, 0, &probe, 1), 0);
    EXPECT_NE(flash.erase(flash.dev, 0), 0);

    sb_flash_sim_power_cycle(&sim);
    EXPECT_EQ(flash.read(flash.dev, 0, &probe, 1), 0);
    EXPECT_EQ(probe, 0x00); // contents survive the reboot
}

TEST_F(FlashSim, PowerLossDuringEraseLeavesHalfSector)
{
    std::vector<uint8_t> zeros(256, 0);
    ASSERT_EQ(flash.write(flash.dev, 0, zeros.data(), 256), 0);
    sb_flash_sim_fail_at(&sim, 0);
    EXPECT_NE(flash.erase(flash.dev, 0), 0);
    EXPECT_EQ(mem[0], 0xFF);
    EXPECT_EQ(mem[255], 0x00);
}

TEST(OtpSim, ProvisionIsOneTimeAndCounterIsMonotonic)
{
    sb_otp_sim_t sim{};
    sb_otp_t otp{};
    uint8_t hash[32], log_hash[32], key[32], out[32];
    uint32_t counter = 99;
    for (int i = 0; i < 32; i++) {
        hash[i] = static_cast<uint8_t>(i);
        log_hash[i] = static_cast<uint8_t>(0x50 + i);
        key[i] = static_cast<uint8_t>(0xA0 + i);
    }
    sb_otp_sim_bind(&sim, &otp);

    EXPECT_NE(otp.read_counter(otp.dev, &counter), 0); // unprovisioned
    EXPECT_NE(sb_otp_sim_provision(&sim, hash, hash, key), 0); // root and log anchors must differ
    ASSERT_EQ(sb_otp_sim_provision(&sim, hash, log_hash, key), 0);
    EXPECT_NE(sb_otp_sim_provision(&sim, key, hash, hash), 0); // cannot re-provision
    ASSERT_EQ(otp.read_log_key_hash(otp.dev, out), 0);
    EXPECT_EQ(out[5], 0x55);

    ASSERT_EQ(otp.read_root_key_hash(otp.dev, out), 0);
    EXPECT_EQ(out[5], 5);
    ASSERT_EQ(otp.read_counter(otp.dev, &counter), 0);
    EXPECT_EQ(counter, 0u);

    EXPECT_EQ(otp.advance_counter(otp.dev, 5), 0);
    EXPECT_EQ(otp.advance_counter(otp.dev, 5), 0);
    EXPECT_NE(otp.advance_counter(otp.dev, 4), 0); // fuses do not un-burn
    ASSERT_EQ(otp.read_counter(otp.dev, &counter), 0);
    EXPECT_EQ(counter, 5u);
}

}  // namespace

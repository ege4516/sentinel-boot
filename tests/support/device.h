// SPDX-License-Identifier: MIT
// A complete simulated device: flash, OTP, keys and a bootloader context.
#pragma once

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

#include "signer.h"

extern "C" {
#include "boot/boot.h"
#include "hal/flash_sim.h"
#include "hal/otp_sim.h"
}

namespace sbtest {

struct Keys {
    KeyPair root;
    KeyPair device;
    KeyPair log;
    static Keys generate() { return Keys{generate_p256(), generate_p256(), generate_p256()}; }
};

class Device {
public:
    static constexpr uint32_t kSector = 4096;
    static constexpr uint32_t kSlotSize = 8 * kSector;
    static constexpr uint32_t kFlashSize = 2 * kSector + 2 * kSlotSize;

    explicit Device(const Keys &keys) : keys_(keys), log_(keys.log), mem_(kFlashSize)
    {
        sb_flash_sim_init(&fsim, mem_.data(), kFlashSize, kSector);
        sb_flash_sim_bind(&fsim, &flash_);

        auto anchor = sha256(keys_.root.pub.data(), keys_.root.pub.size());
        auto log_anchor = sha256(keys_.log.pub.data(), keys_.log.pub.size());
        if (sb_otp_sim_provision(&osim, anchor.data(), log_anchor.data(),
                                 keys_.device.priv.data()) != 0) {
            throw std::runtime_error("provision failed");
        }
        sb_otp_sim_bind(&osim, &otp_);

        layout.state_off[0] = 0;
        layout.state_off[1] = kSector;
        layout.slot_off[0] = 2 * kSector;
        layout.slot_off[1] = 2 * kSector + kSlotSize;
        layout.slot_size = kSlotSize;

        ctx = std::make_unique<sb_ctx_t>();
        if (sb_ctx_init(ctx.get(), &flash_, &otp_, &layout, keys_.root.pub.data(),
                        keys_.log.pub.data()) != SB_OK) {
            throw std::runtime_error("sb_ctx_init failed");
        }
    }

    Device(const Device &) = delete;
    Device &operator=(const Device &) = delete;

    // Stage a package the way an application would, in small chunks.
    sb_err_t stage(const Bytes &pkg, size_t chunk = 1000)
    {
        sb_err_t err = sb_update_begin(ctx.get());
        for (size_t off = 0; err == SB_OK && off < pkg.size(); off += chunk) {
            size_t n = std::min(chunk, pkg.size() - off);
            err = sb_update_write(ctx.get(), static_cast<uint32_t>(off), pkg.data() + off, n);
        }
        if (err == SB_OK) {
            err = sb_update_finish(ctx.get());
        }
        return err;
    }

    sb_err_t boot(sb_boot_result_t *res = nullptr)
    {
        sb_boot_result_t local;
        return sb_boot(ctx.get(), res != nullptr ? res : &local);
    }

    sb_err_t confirm() { return sb_update_confirm(ctx.get()); }

    // Stage + boot + confirm; throws on any failure. Used to set up scenarios.
    void install_confirmed(const Bytes &pkg)
    {
        sb_boot_result_t res;
        if (stage(pkg) != SB_OK || boot(&res) != SB_OK || !(res.events & SB_EVT_INSTALLED) ||
            confirm() != SB_OK) {
            throw std::runtime_error("install_confirmed failed");
        }
    }

    Bytes read_image(const sb_boot_result_t &res) const
    {
        const uint8_t *p = mem_.data() + res.image_offset;
        return Bytes(p, p + res.manifest.image_size);
    }

    sb_state_t state() const
    {
        sb_state_t st;
        if (sb_state_load(ctx.get(), &st) != SB_OK) {
            throw std::runtime_error("sb_state_load failed");
        }
        return st;
    }

    // Capture / restore everything that survives a reset (flash + OTP).
    struct Snapshot {
        std::vector<uint8_t> mem;
        sb_otp_sim_t otp;
    };
    Snapshot snapshot() const { return Snapshot{mem_, osim}; }
    void restore(const Snapshot &s)
    {
        std::memcpy(mem_.data(), s.mem.data(), mem_.size());
        osim = s.otp;
        sb_flash_sim_power_cycle(&fsim);
    }

    uint8_t *raw() { return mem_.data(); }
    uint32_t slot_off(int slot) const { return layout.slot_off[slot]; }
    uint32_t image_off(int slot) const { return layout.slot_off[slot] + kSector; }
    uint32_t max_image() const { return kSlotSize - kSector; }
    uint32_t otp_counter() const { return osim.counter; }
    const Keys &keys() const { return keys_; }

    Bytes package(uint32_t version, uint32_t counter, const Bytes &image) const
    {
        PackageSpec spec;
        spec.fw_version = version;
        spec.security_counter = counter;
        spec.image = image;
        return make_package(spec, keys_.root, keys_.device.pub, &log_);
    }

    // Re-sign a modified package with the real root key and record it in the log.
    void resign(Bytes &pkg)
    {
        sbtest::resign(pkg, keys_.root);
        relog(pkg, log_);
    }

    TestLog &log() { return log_; }

    sb_flash_sim_t fsim{};
    sb_otp_sim_t osim{};
    sb_layout_t layout{};
    std::unique_ptr<sb_ctx_t> ctx;

private:
    Keys keys_;
    mutable TestLog log_; // package() appends: logically a log write, not a device change
    std::vector<uint8_t> mem_;
    sb_flash_t flash_{};
    sb_otp_t otp_{};
};

}  // namespace sbtest

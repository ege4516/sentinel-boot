// SPDX-License-Identifier: MIT
// libFuzzer target for the whole update path.
//
// A simulated device runs a confirmed v1. Each input is staged as if it were
// a downloaded package, then the device reboots. Security property checked
// on every execution:
//
//   The device always boots, and what it boots is byte-identical to one of
//   the two images the vendor actually signed.
//
// The fuzzer starts from a genuine v2 package, so it explores mutations of
// valid input rather than random noise. Keys are fixed so the committed seed
// corpus stays valid.
//
// Set SB_FUZZ_SEED_DIR=<dir> to (re)generate the seed corpus and exit.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "support/device.h"

using namespace sbtest;

namespace {

Keys fixed_keys()
{
    std::array<uint8_t, 32> root{}, device{}, log{};
    for (size_t i = 0; i < 32; i++) {
        root[i] = static_cast<uint8_t>(0x11 + i);
        device[i] = static_cast<uint8_t>(0xA1 + i);
        log[i] = static_cast<uint8_t>(0x51 + i);
    }
    return Keys{keypair_from_private(root), keypair_from_private(device),
                keypair_from_private(log)};
}

struct Harness {
    Keys keys = fixed_keys();
    Device dev{keys};
    Bytes img1 = make_image(3000, 1);
    Bytes img2 = make_image(5000, 2);
    Device::Snapshot base;

    Harness()
    {
        dev.install_confirmed(dev.package(0x01000000, 1, img1));
        base = dev.snapshot();
    }
};

Harness &harness()
{
    static Harness h;
    return h;
}

void write_file(const std::string &path, const Bytes &data)
{
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!f) {
        std::fprintf(stderr, "cannot write %s\n", path.c_str());
        std::exit(1);
    }
}

[[noreturn]] void violation(const char *what)
{
    std::fprintf(stderr, "SECURITY PROPERTY VIOLATED: %s\n", what);
    std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Harness &h = harness();
    if (const char *dir = std::getenv("SB_FUZZ_SEED_DIR")) {
        Bytes pkg = h.dev.package(0x02000000, 2, h.img2);
        write_file(std::string(dir) + "/update/valid_v2.pkg", pkg);
        // fuzz_manifest input = 4-byte capacity + manifest.
        Bytes m = {0x00, 0x70, 0x00, 0x00};
        m.insert(m.end(), pkg.begin(), pkg.begin() + SB_MANIFEST_LEN);
        write_file(std::string(dir) + "/manifest/valid_manifest.bin", m);
        // fuzz_proof input = proof block + manifest.
        Bytes pf(pkg.begin() + SB_MANIFEST_LEN, pkg.begin() + SB_HEADER_LEN);
        pf.insert(pf.end(), pkg.begin(), pkg.begin() + SB_MANIFEST_LEN);
        write_file(std::string(dir) + "/proof/valid_proof.bin", pf);
        std::printf("seed corpus written to %s\n", dir);
        std::exit(0);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Harness &h = harness();
    Device &dev = h.dev;
    dev.restore(h.base);

    const size_t max_pkg = SB_HEADER_LEN + dev.max_image();
    if (size > max_pkg) {
        size = max_pkg;
    }
    if (sb_update_begin(dev.ctx.get()) != SB_OK ||
        (size != 0 && sb_update_write(dev.ctx.get(), 0, data, size) != SB_OK) ||
        sb_update_finish(dev.ctx.get()) != SB_OK) {
        violation("staging API failed on an in-range package");
    }

    sb_boot_result_t res{};
    if (sb_boot(dev.ctx.get(), &res) != SB_OK) {
        violation("device failed to boot after a staged package");
    }
    Bytes running = dev.read_image(res);
    if (running != h.img1 && running != h.img2) {
        violation("device booted an image the vendor never signed");
    }
    if ((res.events & SB_EVT_INSTALLED) && running != h.img2) {
        violation("an update was installed but v1 is running");
    }
    if (dev.fsim.violations != 0) {
        violation("flash programmed without erase");
    }

    // A second reboot must agree with the first (no latent state damage).
    sb_boot_result_t again{};
    if (sb_boot(dev.ctx.get(), &again) != SB_OK || dev.read_image(again) != running) {
        violation("second boot disagrees with the first");
    }
    return 0;
}

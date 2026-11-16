/* SPDX-License-Identifier: MIT */
/**
 * @file selftest.c
 * On-target self-test: the unmodified boot/ core, cross-compiled for a
 * Cortex-M3, runs install, update, attack and power-loss scenarios against a
 * RAM-backed flash model. Results go to the semihosting console and the
 * process exit status tells QEMU (and CI) whether everything passed.
 *
 * This does not boot a real application; it exercises the bootloader logic on
 * the target CPU, with the real crypto library, in a bare-metal environment.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "boot/boot.h"
#include "fixtures.h"
#include "hal/flash_sim.h"
#include "hal/otp_sim.h"

#define SECTOR 4096u
#define SLOT_SIZE (4u * SECTOR) /* header sector + 12 KiB of image */
#define FLASH_SIZE (2u * SECTOR + 2u * SLOT_SIZE)

extern size_t startup_heap_peak(void);

static uint8_t g_flash_mem[FLASH_SIZE];
static uint8_t g_flash_snap[FLASH_SIZE];
static uint8_t g_tampered[sizeof(FX_PKG_V2)];
static sb_flash_sim_t g_fsim;
static sb_flash_t g_flash;
static sb_otp_sim_t g_osim, g_osim_snap;
static sb_otp_t g_otp;
static sb_ctx_t g_ctx;

static unsigned g_checks, g_failed;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        g_checks++;                                       \
        if (!(cond)) {                                    \
            g_failed++;                                   \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                          \
            printf("\n");                                 \
        }                                                 \
    } while (0)

/* The same pattern tools/gen_fixture.py used to build the images. */
static uint8_t pattern(uint32_t i, uint8_t seed)
{
    return (uint8_t)((uint8_t)((i * 2654435761u) >> 24) ^ seed);
}

static int image_is(const sb_boot_result_t *r, uint32_t size, uint8_t seed)
{
    if (r->manifest.image_size != size) {
        return 0;
    }
    for (uint32_t i = 0; i < size; i++) {
        if (g_flash_mem[r->image_offset + i] != pattern(i, seed)) {
            return 0;
        }
    }
    return 1;
}

static sb_err_t stage(const uint8_t *pkg, size_t len)
{
    sb_err_t err = sb_update_begin(&g_ctx);
    for (size_t off = 0; err == SB_OK && off < len; off += 1021u) {
        size_t n = len - off < 1021u ? len - off : 1021u;
        err = sb_update_write(&g_ctx, (uint32_t)off, pkg + off, n);
    }
    return err == SB_OK ? sb_update_finish(&g_ctx) : err;
}

static void setup_device(void)
{
    static const sb_layout_t layout = {
        .state_off = { 0, SECTOR },
        .slot_off = { 2u * SECTOR, 2u * SECTOR + SLOT_SIZE },
        .slot_size = SLOT_SIZE,
    };
    uint8_t anchor[SB_SHA256_LEN];
    uint8_t log_anchor[SB_SHA256_LEN];

    sb_flash_sim_init(&g_fsim, g_flash_mem, FLASH_SIZE, SECTOR);
    sb_flash_sim_bind(&g_fsim, &g_flash);
    memset(&g_osim, 0, sizeof(g_osim));
    sb_otp_sim_bind(&g_osim, &g_otp);
    CHECK(sb_sha256(FX_ROOT_PUB, sizeof(FX_ROOT_PUB), anchor) == SB_OK, "hash root key");
    CHECK(sb_sha256(FX_LOG_PUB, sizeof(FX_LOG_PUB), log_anchor) == SB_OK, "hash log key");
    CHECK(sb_otp_sim_provision(&g_osim, anchor, log_anchor, FX_DEVICE_PRIV) == 0, "provision otp");
    CHECK(sb_ctx_init(&g_ctx, &g_flash, &g_otp, &layout, FX_ROOT_PUB, FX_LOG_PUB) == SB_OK,
          "ctx init");
}

static void expect_rejected(const char *what, const uint8_t *pkg, size_t len, sb_err_t reason,
                            uint32_t keep_size, uint8_t keep_seed)
{
    sb_boot_result_t res;
    uint32_t counter = g_osim.counter;

    CHECK(stage(pkg, len) == SB_OK, "%s: stage", what);
    CHECK(sb_boot(&g_ctx, &res) == SB_OK, "%s: boot", what);
    CHECK((res.events & SB_EVT_UPDATE_REJECTED) && res.reject_reason == reason,
          "%s: expected rejection '%s', got events=0x%x reason='%s'", what, sb_strerror(reason),
          (unsigned)res.events, sb_strerror(res.reject_reason));
    CHECK(image_is(&res, keep_size, keep_seed), "%s: device must keep running the old image",
          what);
    CHECK(g_osim.counter == counter, "%s: counter must not move", what);
    printf("  %-34s rejected: %s\n", what, sb_strerror(res.reject_reason));
}

/* One full update life cycle, as the application and bootloader would run it. */
static void lifecycle(void)
{
    sb_boot_result_t res;
    if (stage(FX_PKG_V3, sizeof(FX_PKG_V3)) != SB_OK || sb_boot(&g_ctx, &res) != SB_OK) {
        return;
    }
    if (sb_update_confirm(&g_ctx) != SB_OK) {
        return;
    }
    (void)sb_boot(&g_ctx, &res);
}

static void power_loss_sweep(void)
{
    uint32_t total;
    unsigned kept_old = 0, got_new = 0;

    memcpy(g_flash_snap, g_flash_mem, FLASH_SIZE);
    g_osim_snap = g_osim;

    sb_flash_sim_fail_at(&g_fsim, SB_FLASH_SIM_NO_FAULT);
    lifecycle();
    total = g_fsim.op_count;
    CHECK(total > 10u, "update life cycle performs flash operations (%u)", (unsigned)total);

    for (uint32_t cut = 0; cut < total; cut++) {
        sb_boot_result_t res;
        int ok_old, ok_new;

        memcpy(g_flash_mem, g_flash_snap, FLASH_SIZE);
        g_osim = g_osim_snap;
        g_fsim.violations = 0;
        sb_flash_sim_power_cycle(&g_fsim);
        sb_flash_sim_fail_at(&g_fsim, cut);
        lifecycle();
        sb_flash_sim_power_cycle(&g_fsim); /* reboot */

        CHECK(sb_boot(&g_ctx, &res) == SB_OK, "cut %u: device must boot", (unsigned)cut);
        ok_old = image_is(&res, 5000u, 0x22);
        ok_new = image_is(&res, 2500u, 0x33);
        CHECK(ok_old || ok_new, "cut %u: booted image is not a signed release", (unsigned)cut);
        CHECK(res.manifest.security_counter >= g_osim.counter, "cut %u: counter ahead of image",
              (unsigned)cut);
        CHECK(g_fsim.violations == 0, "cut %u: flash programmed without erase", (unsigned)cut);
        if (ok_old) {
            kept_old++;
        } else if (ok_new) {
            got_new++;
        }
    }
    CHECK(kept_old > 0 && got_new > 0, "sweep reached both outcomes");
    printf("  power cut at each of %u flash operations: kept v2 %u times, reached v3 %u times\n",
           (unsigned)total, kept_old, got_new);
}

int main(void)
{
    sb_boot_result_t res;

    printf("sentinel-boot self-test on Cortex-M3 (QEMU mps2-an385)\n");
    printf("note: entropy source is a deterministic demo stub\n\n");
    setup_device();

    printf("[1] blank device, first install\n");
    CHECK(sb_boot(&g_ctx, &res) == SB_ERR_NO_IMAGE, "blank device has nothing to boot");
    CHECK(stage(FX_PKG_V1, sizeof(FX_PKG_V1)) == SB_OK, "stage v1");
    CHECK(sb_boot(&g_ctx, &res) == SB_OK && (res.events & SB_EVT_INSTALLED), "install v1");
    CHECK(image_is(&res, 3000u, 0x11), "decrypted v1 matches the signed image");
    CHECK(sb_update_confirm(&g_ctx) == SB_OK && g_osim.counter == 1u, "confirm v1");
    printf("  installed v1.0.0, counter %u\n", (unsigned)g_osim.counter);

    printf("[2] over-the-air update\n");
    CHECK(stage(FX_PKG_V2, sizeof(FX_PKG_V2)) == SB_OK, "stage v2");
    CHECK(sb_boot(&g_ctx, &res) == SB_OK && (res.events & SB_EVT_INSTALLED), "install v2");
    CHECK(image_is(&res, 5000u, 0x22), "decrypted v2 matches the signed image");
    CHECK(sb_update_confirm(&g_ctx) == SB_OK && g_osim.counter == 2u, "confirm v2");
    printf("  installed v2.0.0, counter %u\n", (unsigned)g_osim.counter);

    printf("[3] attacks\n");
    memcpy(g_tampered, FX_PKG_V2, sizeof(g_tampered));
    g_tampered[SB_HEADER_LEN + 100] ^= 0x01;
    expect_rejected("flipped ciphertext bit", g_tampered, sizeof(g_tampered), SB_ERR_DIGEST, 5000u,
                    0x22);
    expect_rejected("replayed signed v1 (rollback)", FX_PKG_V1, sizeof(FX_PKG_V1),
                    SB_ERR_ROLLBACK, 5000u, 0x22);
    expect_rejected("signed by attacker key", FX_PKG_EVIL, sizeof(FX_PKG_EVIL), SB_ERR_KEY, 5000u,
                    0x22);
    expect_rejected("root-signed but never logged", FX_PKG_UNLOGGED, sizeof(FX_PKG_UNLOGGED),
                    SB_ERR_LOG, 5000u, 0x22);

    printf("[4] power loss\n");
    power_loss_sweep();

    printf("\n%u checks, %u failed, peak heap %u bytes\n", g_checks, g_failed,
           (unsigned)startup_heap_peak());
    printf(g_failed == 0 ? "SELFTEST PASSED\n" : "SELFTEST FAILED\n");
    return g_failed == 0 ? 0 : 1;
}

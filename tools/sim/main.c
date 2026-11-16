/* SPDX-License-Identifier: MIT */
/**
 * @file main.c
 * sentinel-sim: drive the bootloader core against a file-backed device.
 *
 *   sentinel-sim <dir> provision <root_public.bin> <log_public.bin> <device_private.bin>
 *   sentinel-sim <dir> stage <package.bin>
 *   sentinel-sim <dir> boot
 *   sentinel-sim <dir> confirm
 *   sentinel-sim <dir> status
 *   sentinel-sim <dir> dump <out.bin>     (image selected by a verified boot)
 *
 * <dir> holds the device's persistent state: flash.bin, otp.bin and the root
 * and log public keys. Each invocation is one "power cycle".
 *
 * Exit status: 0 ok, 2 no bootable image, 1 any other error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot/boot.h"
#include "hal/flash_sim.h"
#include "hal/otp_sim.h"

#define SECTOR 4096u
#define SLOT_SIZE (64u * SECTOR)
#define FLASH_SIZE (2u * SECTOR + 2u * SLOT_SIZE)
#define MAX_PACKAGE (SB_HEADER_LEN + SLOT_SIZE)

static uint8_t g_mem[FLASH_SIZE];
static uint8_t g_pkg[MAX_PACKAGE];
static uint8_t g_root_pub[SB_P256_PUB_LEN];
static uint8_t g_log_pub[SB_P256_PUB_LEN];
static sb_flash_sim_t g_fsim;
static sb_otp_sim_t g_osim;
static sb_flash_t g_flash;
static sb_otp_t g_otp;
static sb_ctx_t g_ctx;

static char g_flash_path[512];
static char g_otp_path[512];
static char g_root_path[512];
static char g_log_path[512];

static long read_file(const char *path, uint8_t *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    int extra;
    if (f == NULL) {
        return -1;
    }
    n = fread(buf, 1, cap, f);
    extra = fgetc(f);
    (void)fclose(f);
    return extra == EOF ? (long)n : -2; /* -2: larger than the buffer */
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (f == NULL) {
        return -1;
    }
    n = fwrite(buf, 1, len, f);
    return (fclose(f) == 0 && n == len) ? 0 : -1;
}

static const char *slot_state_name(uint8_t s)
{
    static const char *const names[] = { "EMPTY", "DOWNLOADED", "DECRYPTING",
                                         "TRIAL", "CONFIRMED",  "INVALID" };
    return s <= SB_SLOT_INVALID ? names[s] : "?";
}

static void print_version(uint32_t v)
{
    printf("%u.%u.%u", (unsigned)(v >> 24), (unsigned)((v >> 16) & 0xFFu),
           (unsigned)(v & 0xFFFFu));
}

static int save_device(void)
{
    if (sb_flash_sim_save(&g_fsim, g_flash_path) != 0 ||
        sb_otp_sim_save(&g_osim, g_otp_path) != 0) {
        fprintf(stderr, "error: cannot write device state\n");
        return 1;
    }
    return 0;
}

/* Load an already provisioned device and build a bootloader context. */
static int open_device(void)
{
    static const sb_layout_t layout = {
        .state_off = { 0, SECTOR },
        .slot_off = { 2u * SECTOR, 2u * SECTOR + SLOT_SIZE },
        .slot_size = SLOT_SIZE,
    };
    sb_err_t err;

    if (sb_flash_sim_load(&g_fsim, g_flash_path) != 0 ||
        sb_otp_sim_load(&g_osim, g_otp_path) != 0 ||
        read_file(g_root_path, g_root_pub, sizeof(g_root_pub)) != (long)sizeof(g_root_pub) ||
        read_file(g_log_path, g_log_pub, sizeof(g_log_pub)) != (long)sizeof(g_log_pub)) {
        fprintf(stderr, "error: device not provisioned (run 'provision' first)\n");
        return 1;
    }
    err = sb_ctx_init(&g_ctx, &g_flash, &g_otp, &layout, g_root_pub, g_log_pub);
    if (err != SB_OK) {
        fprintf(stderr, "error: context init: %s\n", sb_strerror(err));
        return 1;
    }
    return 0;
}

static int cmd_provision(const char *root_pub_path, const char *log_pub_path,
                         const char *device_key_path)
{
    uint8_t device_key[SB_P256_PRIV_LEN];
    uint8_t root_anchor[SB_SHA256_LEN];
    uint8_t log_anchor[SB_SHA256_LEN];

    if (read_file(root_pub_path, g_root_pub, sizeof(g_root_pub)) != (long)sizeof(g_root_pub) ||
        read_file(log_pub_path, g_log_pub, sizeof(g_log_pub)) != (long)sizeof(g_log_pub) ||
        read_file(device_key_path, device_key, sizeof(device_key)) != (long)sizeof(device_key)) {
        fprintf(stderr, "error: cannot read key files (need 65, 65 and 32 bytes)\n");
        return 1;
    }
    if (sb_crypto_init() != SB_OK ||
        sb_sha256(g_root_pub, sizeof(g_root_pub), root_anchor) != SB_OK ||
        sb_sha256(g_log_pub, sizeof(g_log_pub), log_anchor) != SB_OK) {
        fprintf(stderr, "error: crypto init failed\n");
        return 1;
    }
    memset(&g_osim, 0, sizeof(g_osim));
    if (sb_otp_sim_provision(&g_osim, root_anchor, log_anchor, device_key) != 0 ||
        write_file(g_root_path, g_root_pub, sizeof(g_root_pub)) != 0 ||
        write_file(g_log_path, g_log_pub, sizeof(g_log_pub)) != 0) {
        fprintf(stderr, "error: provisioning failed (root and log keys must differ)\n");
        return 1;
    }
    sb_zeroize(device_key, sizeof(device_key));
    printf("provisioned: blank flash (%u KiB), root and log key anchors burned, counter = 0\n",
           (unsigned)(FLASH_SIZE / 1024u));
    return save_device();
}

static int cmd_stage(const char *pkg_path)
{
    long len = read_file(pkg_path, g_pkg, sizeof(g_pkg));
    sb_err_t err;
    size_t off = 0;

    if (len < 0) {
        fprintf(stderr, "error: cannot read package (missing or too large)\n");
        return 1;
    }
    err = sb_update_begin(&g_ctx);
    while (err == SB_OK && off < (size_t)len) {
        /* Odd chunk size on purpose: exercises split writes. */
        size_t n = (size_t)len - off;
        if (n > 1021u) {
            n = 1021u;
        }
        err = sb_update_write(&g_ctx, (uint32_t)off, g_pkg + off, n);
        off += n;
    }
    if (err == SB_OK) {
        err = sb_update_finish(&g_ctx);
    }
    if (err != SB_OK) {
        fprintf(stderr, "error: staging failed: %s\n", sb_strerror(err));
        (void)save_device();
        return 1;
    }
    printf("staged %ld bytes; the bootloader will verify it on next boot\n", len);
    return save_device();
}

static int do_boot(sb_boot_result_t *res, int verbose)
{
    sb_err_t err = sb_boot(&g_ctx, res);

    if (verbose) {
        if (res->events & SB_EVT_STATE_RECOVERED) {
            printf("[boot] boot state rebuilt by probing slots\n");
        }
        if (res->events & SB_EVT_UPDATE_REJECTED) {
            printf("[boot] staged update REJECTED: %s\n", sb_strerror(res->reject_reason));
        }
        if (res->events & SB_EVT_INSTALL_RESUMED) {
            printf("[boot] completed an interrupted install\n");
        }
        if (res->events & SB_EVT_INSTALLED) {
            printf("[boot] staged update verified, decrypted and installed\n");
        }
        if (res->events & SB_EVT_REVERTED) {
            printf("[boot] reverted to the previous image\n");
        }
        if (res->events & SB_EVT_COUNTER_ADVANCED) {
            printf("[boot] anti-rollback counter advanced\n");
        }
    }
    if (err == SB_ERR_NO_IMAGE) {
        if (verbose) {
            printf("[boot] NO BOOTABLE IMAGE\n");
        }
        return 2;
    }
    if (err != SB_OK) {
        fprintf(stderr, "error: boot failed: %s\n", sb_strerror(err));
        return 1;
    }
    if (verbose) {
        printf("[boot] OK slot %u, version ", (unsigned)res->slot);
        print_version(res->manifest.fw_version);
        printf(", security counter %u, %u bytes%s\n", (unsigned)res->manifest.security_counter,
               (unsigned)res->manifest.image_size,
               (res->events & SB_EVT_TRIAL_BOOT) ? " (TRIAL: awaiting confirm)" : "");
    }
    return 0;
}

static int cmd_boot(void)
{
    sb_boot_result_t res;
    int rc = do_boot(&res, 1);
    int save_rc = save_device();
    return rc != 0 ? rc : save_rc;
}

static int cmd_confirm(void)
{
    sb_err_t err = sb_update_confirm(&g_ctx);
    if (err != SB_OK) {
        fprintf(stderr, "error: confirm failed: %s\n", sb_strerror(err));
        return 1;
    }
    printf("running image confirmed; anti-rollback counter = %u\n", (unsigned)g_osim.counter);
    return save_device();
}

static int cmd_status(void)
{
    sb_state_t st;
    if (sb_state_load(&g_ctx, &st) != SB_OK) {
        return 1;
    }
    printf("active slot: %u   slot0: %s   slot1: %s   trials left: %u\n", (unsigned)st.active,
           slot_state_name(st.slot[0]), slot_state_name(st.slot[1]), (unsigned)st.trials_left);
    printf("otp anti-rollback counter: %u\n", (unsigned)g_osim.counter);
    return 0;
}

static int cmd_dump(const char *out_path)
{
    sb_boot_result_t res;
    int rc = do_boot(&res, 0);
    if (rc != 0) {
        return rc;
    }
    /* Only bytes the bootloader has just verified are ever exported. */
    if (write_file(out_path, g_mem + res.image_offset, res.manifest.image_size) != 0) {
        fprintf(stderr, "error: cannot write %s\n", out_path);
        return 1;
    }
    return save_device();
}

static void usage(void)
{
    fprintf(stderr,
            "usage: sentinel-sim <dir> provision <root_public.bin> <log_public.bin> "
            "<device_private.bin>\n"
            "       sentinel-sim <dir> stage <package.bin>\n"
            "       sentinel-sim <dir> boot | confirm | status\n"
            "       sentinel-sim <dir> dump <out.bin>\n");
}

int main(int argc, char **argv)
{
    const char *dir;
    const char *cmd;

    if (argc < 3) {
        usage();
        return 1;
    }
    dir = argv[1];
    cmd = argv[2];
    if (snprintf(g_flash_path, sizeof(g_flash_path), "%s/flash.bin", dir) >=
            (int)sizeof(g_flash_path) ||
        snprintf(g_otp_path, sizeof(g_otp_path), "%s/otp.bin", dir) >= (int)sizeof(g_otp_path) ||
        snprintf(g_root_path, sizeof(g_root_path), "%s/root_public.bin", dir) >=
            (int)sizeof(g_root_path) ||
        snprintf(g_log_path, sizeof(g_log_path), "%s/log_public.bin", dir) >=
            (int)sizeof(g_log_path)) {
        fprintf(stderr, "error: directory path too long\n");
        return 1;
    }

    sb_flash_sim_init(&g_fsim, g_mem, FLASH_SIZE, SECTOR);
    sb_flash_sim_bind(&g_fsim, &g_flash);
    sb_otp_sim_bind(&g_osim, &g_otp);

    if (strcmp(cmd, "provision") == 0 && argc == 6) {
        return cmd_provision(argv[3], argv[4], argv[5]);
    }
    if (open_device() != 0) {
        return 1;
    }
    if (strcmp(cmd, "stage") == 0 && argc == 4) {
        return cmd_stage(argv[3]);
    }
    if (strcmp(cmd, "boot") == 0 && argc == 3) {
        return cmd_boot();
    }
    if (strcmp(cmd, "confirm") == 0 && argc == 3) {
        return cmd_confirm();
    }
    if (strcmp(cmd, "status") == 0 && argc == 3) {
        return cmd_status();
    }
    if (strcmp(cmd, "dump") == 0 && argc == 4) {
        return cmd_dump(argv[3]);
    }
    usage();
    return 1;
}

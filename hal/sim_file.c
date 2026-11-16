/* SPDX-License-Identifier: MIT */
/**
 * @file sim_file.c
 * Host-only persistence for the simulators (used by the sentinel-sim CLI).
 * Kept out of flash_sim.c / otp_sim.c so those stay free of stdio and build
 * for a bare-metal target.
 */
#include <stdio.h>
#include <string.h>

#include "hal/flash_sim.h"
#include "hal/otp_sim.h"

#define OTP_FILE_LEN (32u + 32u + 32u + 4u + 1u)

int sb_flash_sim_save(const sb_flash_sim_t *sim, const char *path)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (f == NULL) {
        return -1;
    }
    n = fwrite(sim->mem, 1, sim->size, f);
    if (fclose(f) != 0 || n != sim->size) {
        return -1;
    }
    return 0;
}

int sb_flash_sim_load(sb_flash_sim_t *sim, const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) {
        return -1;
    }
    n = fread(sim->mem, 1, sim->size, f);
    (void)fclose(f);
    return n == sim->size ? 0 : -1;
}

int sb_otp_sim_save(const sb_otp_sim_t *sim, const char *path)
{
    uint8_t buf[OTP_FILE_LEN];
    FILE *f;
    size_t n;

    memcpy(buf, sim->root_key_hash, 32);
    memcpy(buf + 32, sim->log_key_hash, 32);
    memcpy(buf + 64, sim->device_key, 32);
    buf[96] = (uint8_t)(sim->counter & 0xFFu);
    buf[97] = (uint8_t)((sim->counter >> 8) & 0xFFu);
    buf[98] = (uint8_t)((sim->counter >> 16) & 0xFFu);
    buf[99] = (uint8_t)((sim->counter >> 24) & 0xFFu);
    buf[100] = sim->provisioned;

    f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    n = fwrite(buf, 1, sizeof(buf), f);
    if (fclose(f) != 0 || n != sizeof(buf)) {
        return -1;
    }
    return 0;
}

int sb_otp_sim_load(sb_otp_sim_t *sim, const char *path)
{
    uint8_t buf[OTP_FILE_LEN];
    FILE *f = fopen(path, "rb");
    size_t n;

    if (f == NULL) {
        return -1;
    }
    n = fread(buf, 1, sizeof(buf), f);
    (void)fclose(f);
    if (n != sizeof(buf)) {
        return -1;
    }
    memcpy(sim->root_key_hash, buf, 32);
    memcpy(sim->log_key_hash, buf + 32, 32);
    memcpy(sim->device_key, buf + 64, 32);
    sim->counter = (uint32_t)buf[96] | ((uint32_t)buf[97] << 8) | ((uint32_t)buf[98] << 16) |
                   ((uint32_t)buf[99] << 24);
    sim->provisioned = buf[100] != 0;
    return 0;
}

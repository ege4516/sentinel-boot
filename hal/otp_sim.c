/* SPDX-License-Identifier: MIT */
#include "hal/otp_sim.h"

#include <stdio.h>
#include <string.h>

#define OTP_FILE_LEN (32u + 32u + 4u + 1u)

static int otp_read_root(void *dev, uint8_t out[32])
{
    const sb_otp_sim_t *sim = (const sb_otp_sim_t *)dev;
    if (!sim->provisioned) {
        return -1;
    }
    memcpy(out, sim->root_key_hash, 32);
    return 0;
}

static int otp_read_device_key(void *dev, uint8_t out[32])
{
    const sb_otp_sim_t *sim = (const sb_otp_sim_t *)dev;
    if (!sim->provisioned) {
        return -1;
    }
    memcpy(out, sim->device_key, 32);
    return 0;
}

static int otp_read_counter(void *dev, uint32_t *out)
{
    const sb_otp_sim_t *sim = (const sb_otp_sim_t *)dev;
    if (!sim->provisioned) {
        return -1;
    }
    *out = sim->counter;
    return 0;
}

static int otp_advance(void *dev, uint32_t value)
{
    sb_otp_sim_t *sim = (sb_otp_sim_t *)dev;
    if (!sim->provisioned || value < sim->counter) {
        return -1; /* Fuses only burn one way. */
    }
    sim->counter = value;
    return 0;
}

int sb_otp_sim_provision(sb_otp_sim_t *sim, const uint8_t root_key_hash[32],
                         const uint8_t device_key[32])
{
    if (sim->provisioned) {
        return -1;
    }
    memcpy(sim->root_key_hash, root_key_hash, 32);
    memcpy(sim->device_key, device_key, 32);
    sim->counter = 0;
    sim->provisioned = 1;
    return 0;
}

void sb_otp_sim_bind(sb_otp_sim_t *sim, sb_otp_t *out)
{
    out->dev = sim;
    out->read_root_key_hash = otp_read_root;
    out->read_device_key = otp_read_device_key;
    out->read_counter = otp_read_counter;
    out->advance_counter = otp_advance;
}

int sb_otp_sim_save(const sb_otp_sim_t *sim, const char *path)
{
    uint8_t buf[OTP_FILE_LEN];
    FILE *f;
    size_t n;

    memcpy(buf, sim->root_key_hash, 32);
    memcpy(buf + 32, sim->device_key, 32);
    buf[64] = (uint8_t)(sim->counter & 0xFFu);
    buf[65] = (uint8_t)((sim->counter >> 8) & 0xFFu);
    buf[66] = (uint8_t)((sim->counter >> 16) & 0xFFu);
    buf[67] = (uint8_t)((sim->counter >> 24) & 0xFFu);
    buf[68] = sim->provisioned;

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
    memcpy(sim->device_key, buf + 32, 32);
    sim->counter = (uint32_t)buf[64] | ((uint32_t)buf[65] << 8) | ((uint32_t)buf[66] << 16) |
                   ((uint32_t)buf[67] << 24);
    sim->provisioned = buf[68] != 0;
    return 0;
}

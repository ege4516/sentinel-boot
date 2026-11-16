/* SPDX-License-Identifier: MIT */
#include "hal/otp_sim.h"

#include <string.h>

static int otp_read_root(void *dev, uint8_t out[32])
{
    const sb_otp_sim_t *sim = (const sb_otp_sim_t *)dev;
    if (!sim->provisioned) {
        return -1;
    }
    memcpy(out, sim->root_key_hash, 32);
    return 0;
}

static int otp_read_log(void *dev, uint8_t out[32])
{
    const sb_otp_sim_t *sim = (const sb_otp_sim_t *)dev;
    if (!sim->provisioned) {
        return -1;
    }
    memcpy(out, sim->log_key_hash, 32);
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
                         const uint8_t log_key_hash[32], const uint8_t device_key[32])
{
    if (sim->provisioned || memcmp(root_key_hash, log_key_hash, 32) == 0) {
        return -1;
    }
    memcpy(sim->root_key_hash, root_key_hash, 32);
    memcpy(sim->log_key_hash, log_key_hash, 32);
    memcpy(sim->device_key, device_key, 32);
    sim->counter = 0;
    sim->provisioned = 1;
    return 0;
}

void sb_otp_sim_bind(sb_otp_sim_t *sim, sb_otp_t *out)
{
    out->dev = sim;
    out->read_root_key_hash = otp_read_root;
    out->read_log_key_hash = otp_read_log;
    out->read_device_key = otp_read_device_key;
    out->read_counter = otp_read_counter;
    out->advance_counter = otp_advance;
}

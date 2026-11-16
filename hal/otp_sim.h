/* SPDX-License-Identifier: MIT */
/**
 * @file otp_sim.h
 * Simulated OTP / secure storage. On real hardware these values live in
 * fuses or a secure element; here they are plain memory (see threat model).
 */
#ifndef SB_OTP_SIM_H
#define SB_OTP_SIM_H

#include <stdint.h>

#include "hal/sb_hal.h"

typedef struct {
    uint8_t root_key_hash[32];
    uint8_t log_key_hash[32];
    uint8_t device_key[32];
    uint32_t counter;
    uint8_t provisioned;
} sb_otp_sim_t;

/**
 * Provision a blank device. Returns -1 if already provisioned (one-time) or if
 * the root and log anchors are equal (the two keys must be independent).
 */
int sb_otp_sim_provision(sb_otp_sim_t *sim, const uint8_t root_key_hash[32],
                         const uint8_t log_key_hash[32], const uint8_t device_key[32]);

void sb_otp_sim_bind(sb_otp_sim_t *sim, sb_otp_t *out);

int sb_otp_sim_save(const sb_otp_sim_t *sim, const char *path);
int sb_otp_sim_load(sb_otp_sim_t *sim, const char *path);

#endif /* SB_OTP_SIM_H */

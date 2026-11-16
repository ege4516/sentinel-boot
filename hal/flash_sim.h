/* SPDX-License-Identifier: MIT */
/**
 * @file flash_sim.h
 * RAM-backed NOR flash model with power-loss injection.
 *
 * Models the two properties that make update code hard to get right:
 * programming can only clear bits, and any operation can be cut short.
 */
#ifndef SB_FLASH_SIM_H
#define SB_FLASH_SIM_H

#include <stddef.h>
#include <stdint.h>

#include "hal/sb_hal.h"

#define SB_FLASH_SIM_NO_FAULT UINT32_MAX

typedef struct {
    uint8_t *mem;
    uint32_t size;
    uint32_t sector_size;
    uint32_t op_count;  /**< Mutating operations (write/erase) performed so far */
    uint32_t fail_at;   /**< Operation index that loses power, or NO_FAULT */
    int powered_off;    /**< Set once the fault fires; all later ops fail */
    uint32_t violations; /**< Writes that tried to set a 0 bit back to 1 */
} sb_flash_sim_t;

/** Bind a simulator to caller-owned memory and fill it with 0xFF. */
void sb_flash_sim_init(sb_flash_sim_t *sim, uint8_t *mem, uint32_t size, uint32_t sector_size);

/** Fill an sb_flash_t with this simulator's callbacks. */
void sb_flash_sim_bind(sb_flash_sim_t *sim, sb_flash_t *out);

/**
 * Arm a power loss: the mutating operation with index n (0-based, counted
 * from now) is applied only partially, and everything after it fails.
 */
void sb_flash_sim_fail_at(sb_flash_sim_t *sim, uint32_t n);

/** "Reboot": restore power and disarm the fault. Flash contents persist. */
void sb_flash_sim_power_cycle(sb_flash_sim_t *sim);

/** Persist / restore contents (used by the CLI simulator). 0 on success. */
int sb_flash_sim_save(const sb_flash_sim_t *sim, const char *path);
int sb_flash_sim_load(sb_flash_sim_t *sim, const char *path);

#endif /* SB_FLASH_SIM_H */

/* SPDX-License-Identifier: MIT */
#include "hal/flash_sim.h"

#include <string.h>

static int in_range(const sb_flash_sim_t *sim, uint32_t off, size_t len)
{
    return len <= sim->size && off <= sim->size - (uint32_t)len;
}

/* Returns 1 if this mutating operation is the one that loses power. */
static int consume_op(sb_flash_sim_t *sim)
{
    uint32_t idx = sim->op_count++;
    if (sim->fail_at != SB_FLASH_SIM_NO_FAULT && idx == sim->fail_at) {
        sim->powered_off = 1;
        return 1;
    }
    return 0;
}

static int sim_read(void *dev, uint32_t off, uint8_t *buf, size_t len)
{
    sb_flash_sim_t *sim = (sb_flash_sim_t *)dev;
    if (sim->powered_off || !in_range(sim, off, len)) {
        return -1;
    }
    memcpy(buf, sim->mem + off, len);
    return 0;
}

static int sim_write(void *dev, uint32_t off, const uint8_t *buf, size_t len)
{
    sb_flash_sim_t *sim = (sb_flash_sim_t *)dev;
    size_t n = len;
    int cut;

    if (sim->powered_off || !in_range(sim, off, len)) {
        return -1;
    }
    cut = consume_op(sim);
    if (cut) {
        n = len / 2; /* Only the first half reaches the cells. */
    }
    for (size_t i = 0; i < n; i++) {
        uint8_t cur = sim->mem[off + i];
        if ((uint8_t)(cur & buf[i]) != buf[i]) {
            sim->violations++; /* Tried to program a 0 back to 1. */
        }
        sim->mem[off + i] = (uint8_t)(cur & buf[i]);
    }
    return cut ? -1 : 0;
}

static int sim_erase(void *dev, uint32_t off)
{
    sb_flash_sim_t *sim = (sb_flash_sim_t *)dev;
    uint32_t n = sim->sector_size;
    int cut;

    if (sim->powered_off || !in_range(sim, off, sim->sector_size) ||
        (off % sim->sector_size) != 0) {
        return -1;
    }
    cut = consume_op(sim);
    if (cut) {
        n = sim->sector_size / 2; /* Interrupted erase: half the sector is blank. */
    }
    memset(sim->mem + off, 0xFF, n);
    return cut ? -1 : 0;
}

void sb_flash_sim_init(sb_flash_sim_t *sim, uint8_t *mem, uint32_t size, uint32_t sector_size)
{
    memset(sim, 0, sizeof(*sim));
    sim->mem = mem;
    sim->size = size;
    sim->sector_size = sector_size;
    sim->fail_at = SB_FLASH_SIM_NO_FAULT;
    memset(mem, 0xFF, size);
}

void sb_flash_sim_bind(sb_flash_sim_t *sim, sb_flash_t *out)
{
    out->dev = sim;
    out->size = sim->size;
    out->sector_size = sim->sector_size;
    out->read = sim_read;
    out->write = sim_write;
    out->erase = sim_erase;
}

void sb_flash_sim_fail_at(sb_flash_sim_t *sim, uint32_t n)
{
    sim->op_count = 0;
    sim->fail_at = n;
}

void sb_flash_sim_power_cycle(sb_flash_sim_t *sim)
{
    sim->powered_off = 0;
    sim->fail_at = SB_FLASH_SIM_NO_FAULT;
    sim->op_count = 0;
}

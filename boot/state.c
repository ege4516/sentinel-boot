/* SPDX-License-Identifier: MIT */
/**
 * @file state.c
 * Power-fail-safe boot state.
 *
 * The state record is stored in two sectors. An update always rewrites the
 * copy that does NOT hold the newest valid record, so a power cut at any
 * point leaves at least one intact copy: either the old state or the new one,
 * never a mix.
 */
#include <string.h>

#include "boot/internal.h"

#define STATE_MAGIC 0x54534253u /* "SBST" */
#define STATE_LEN 16u

static void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* CRC-32 (IEEE 802.3), bitwise: the record is 12 bytes, a table is not worth it. */
static uint32_t crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static int decode(const uint8_t rec[STATE_LEN], sb_state_t *out)
{
    if (rd_le32(rec) != STATE_MAGIC || rd_le32(rec + 12) != crc32(rec, 12)) {
        return 0;
    }
    out->seq = rd_le32(rec + 4);
    out->active = rec[8];
    out->slot[0] = rec[9];
    out->slot[1] = rec[10];
    out->trials_left = rec[11];
    /* A record with a good CRC but nonsensical fields is still rejected. */
    if (out->active >= SB_NUM_SLOTS || out->slot[0] > SB_SLOT_INVALID ||
        out->slot[1] > SB_SLOT_INVALID) {
        return 0;
    }
    return 1;
}

sb_err_t sb_state_load(const sb_ctx_t *ctx, sb_state_t *out)
{
    uint8_t rec[STATE_LEN];
    int found = 0;

    if (ctx == NULL || out == NULL) {
        return SB_ERR_PARAM;
    }

    memset(out, 0, sizeof(*out));
    for (uint8_t i = 0; i < 2; i++) {
        sb_state_t cand;
        memset(&cand, 0, sizeof(cand));
        if (ctx->flash->read(ctx->flash->dev, ctx->layout.state_off[i], rec, STATE_LEN) != 0) {
            return SB_ERR_FLASH;
        }
        if (decode(rec, &cand) && (!found || cand.seq > out->seq)) {
            *out = cand;
            out->copy = i;
            found = 1;
        }
    }
    out->valid = (uint8_t)found;
    if (!found) {
        /* Blank or corrupted: the caller decides how to recover. */
        out->active = 0;
        out->slot[0] = SB_SLOT_EMPTY;
        out->slot[1] = SB_SLOT_EMPTY;
        out->copy = 1; /* so the first store targets copy 0 */
    }
    return SB_OK;
}

sb_err_t sb_state_store(const sb_ctx_t *ctx, sb_state_t *st)
{
    uint8_t rec[STATE_LEN];
    uint8_t target;
    uint32_t off;

    if (ctx == NULL || st == NULL) {
        return SB_ERR_PARAM;
    }

    target = (uint8_t)(st->copy ^ 1u);
    off = ctx->layout.state_off[target];

    wr_le32(rec, STATE_MAGIC);
    wr_le32(rec + 4, st->seq + 1u);
    rec[8] = st->active;
    rec[9] = st->slot[0];
    rec[10] = st->slot[1];
    rec[11] = st->trials_left;
    wr_le32(rec + 12, crc32(rec, 12));

    if (ctx->flash->erase(ctx->flash->dev, off) != 0 ||
        ctx->flash->write(ctx->flash->dev, off, rec, STATE_LEN) != 0) {
        return SB_ERR_FLASH;
    }

    st->seq += 1u;
    st->copy = target;
    st->valid = 1;
    return SB_OK;
}

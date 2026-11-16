/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "boot/internal.h"

int sb_is_reject(sb_err_t err)
{
    switch (err) {
    case SB_ERR_FORMAT:
    case SB_ERR_KEY:
    case SB_ERR_SIGNATURE:
    case SB_ERR_ROLLBACK:
    case SB_ERR_DIGEST:
    case SB_ERR_AUTH:
    case SB_ERR_CRYPTO: /* fail closed: a backend error never accepts an image */
        return 1;
    default:
        return 0;
    }
}

static int layout_ok(const sb_flash_t *flash, const sb_layout_t *l)
{
    uint32_t ss = flash->sector_size;
    uint32_t start[4];
    uint32_t len[4];

    if (ss == 0 || ss > SB_MAX_SECTOR_SIZE || (ss % 16u) != 0 || ss < SB_MANIFEST_LEN) {
        return 0;
    }
    if (l->slot_size < 2u * ss || (l->slot_size % ss) != 0) {
        return 0;
    }
    start[0] = l->state_off[0];
    len[0] = ss;
    start[1] = l->state_off[1];
    len[1] = ss;
    start[2] = l->slot_off[0];
    len[2] = l->slot_size;
    start[3] = l->slot_off[1];
    len[3] = l->slot_size;

    for (int i = 0; i < 4; i++) {
        if ((start[i] % ss) != 0 || len[i] > flash->size || start[i] > flash->size - len[i]) {
            return 0;
        }
        for (int j = 0; j < i; j++) {
            /* Regions must not overlap. */
            if (start[i] < start[j] + len[j] && start[j] < start[i] + len[i]) {
                return 0;
            }
        }
    }
    return 1;
}

sb_err_t sb_ctx_init(sb_ctx_t *ctx, const sb_flash_t *flash, const sb_otp_t *otp,
                     const sb_layout_t *layout, const uint8_t root_pub[SB_P256_PUB_LEN])
{
    if (ctx == NULL || flash == NULL || otp == NULL || layout == NULL || root_pub == NULL) {
        return SB_ERR_PARAM;
    }
    if (flash->read == NULL || flash->write == NULL || flash->erase == NULL ||
        otp->read_root_key_hash == NULL || otp->read_device_key == NULL ||
        otp->read_counter == NULL || otp->advance_counter == NULL) {
        return SB_ERR_PARAM;
    }
    if (!layout_ok(flash, layout)) {
        return SB_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->flash = flash;
    ctx->otp = otp;
    ctx->layout = *layout;
    ctx->root_pub = root_pub;
    ctx->max_trials = SB_DEFAULT_TRIALS;
    return sb_crypto_init();
}

uint32_t sb_max_image_size(const sb_ctx_t *ctx)
{
    return ctx->layout.slot_size - ctx->flash->sector_size;
}

uint32_t sb_slot_image_off(const sb_ctx_t *ctx, uint8_t slot)
{
    return ctx->layout.slot_off[slot] + ctx->flash->sector_size;
}

sb_err_t sb_slot_authenticate(sb_ctx_t *ctx, uint8_t slot, uint8_t raw[SB_MANIFEST_LEN],
                              sb_manifest_t *mf)
{
    uint8_t anchor[SB_SHA256_LEN];
    uint32_t counter = 0;
    sb_err_t err;

    if (ctx->flash->read(ctx->flash->dev, ctx->layout.slot_off[slot], raw, SB_MANIFEST_LEN) != 0) {
        return SB_ERR_FLASH;
    }
    err = sb_manifest_parse(raw, SB_MANIFEST_LEN, sb_max_image_size(ctx), mf);
    if (err != SB_OK) {
        return err;
    }
    if (ctx->otp->read_root_key_hash(ctx->otp->dev, anchor) != 0) {
        return SB_ERR_OTP;
    }
    err = sb_manifest_verify(raw, mf, ctx->root_pub, anchor);
    if (err != SB_OK) {
        return err;
    }
    /* Only an authenticated counter is compared with OTP. */
    if (ctx->otp->read_counter(ctx->otp->dev, &counter) != 0) {
        return SB_ERR_OTP;
    }
    if (mf->security_counter < counter) {
        return SB_ERR_ROLLBACK;
    }
    return SB_OK;
}

sb_err_t sb_slot_digest(sb_ctx_t *ctx, uint8_t slot, uint32_t len, uint8_t out[SB_SHA256_LEN])
{
    sb_sha256_ctx_t sha;
    uint32_t off = sb_slot_image_off(ctx, slot);
    uint32_t done = 0;
    sb_err_t err;

    if (len > sb_max_image_size(ctx)) {
        return SB_ERR_RANGE;
    }
    err = sb_sha256_init(&sha);
    while (err == SB_OK && done < len) {
        uint32_t n = len - done;
        if (n > ctx->flash->sector_size) {
            n = ctx->flash->sector_size;
        }
        if (ctx->flash->read(ctx->flash->dev, off + done, ctx->buf_in, n) != 0) {
            return SB_ERR_FLASH;
        }
        err = sb_sha256_update(&sha, ctx->buf_in, n);
        done += n;
    }
    if (err == SB_OK) {
        err = sb_sha256_finish(&sha, out);
    }
    return err;
}

sb_err_t sb_slot_verify_plain(sb_ctx_t *ctx, uint8_t slot, sb_manifest_t *mf)
{
    uint8_t raw[SB_MANIFEST_LEN];
    uint8_t digest[SB_SHA256_LEN];
    sb_err_t err;

    err = sb_slot_authenticate(ctx, slot, raw, mf);
    if (err != SB_OK) {
        return err;
    }
    err = sb_slot_digest(ctx, slot, mf->image_size, digest);
    if (err != SB_OK) {
        return err;
    }
    return sb_ct_memeq(digest, mf->pt_digest, SB_SHA256_LEN) ? SB_OK : SB_ERR_DIGEST;
}

/* SPDX-License-Identifier: MIT */
/**
 * @file update.c
 * Staging of an encrypted package (application side) and its verified,
 * in-place installation (bootloader side).
 */
#include <string.h>

#include "boot/internal.h"

/* Domain-separation label for the image key. Must match tools/sentinel_sign.py. */
static const uint8_t KDF_LABEL[] = "sentinel-boot/v1/image-key";
#define KDF_LABEL_LEN (sizeof(KDF_LABEL) - 1u)

/* ---- Application side ---------------------------------------------------- */

sb_err_t sb_update_begin(sb_ctx_t *ctx)
{
    sb_state_t st;
    uint8_t target;
    sb_err_t err;

    if (ctx == NULL) {
        return SB_ERR_PARAM;
    }
    err = sb_state_load(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    /* While the running image is unconfirmed, the other slot is the only
     * known-good fallback. Refuse to overwrite it. */
    if (st.slot[st.active] == SB_SLOT_TRIAL) {
        return SB_ERR_STATE;
    }
    target = (uint8_t)(st.active ^ 1u);

    /* Record EMPTY before erasing, so a half-erased slot is never trusted. */
    st.slot[target] = SB_SLOT_EMPTY;
    err = sb_state_store(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    for (uint32_t off = 0; off < ctx->layout.slot_size; off += ctx->flash->sector_size) {
        if (ctx->flash->erase(ctx->flash->dev, ctx->layout.slot_off[target] + off) != 0) {
            return SB_ERR_FLASH;
        }
    }
    return SB_OK;
}

sb_err_t sb_update_write(sb_ctx_t *ctx, uint32_t pkg_off, const uint8_t *data, size_t len)
{
    sb_state_t st;
    uint8_t target;
    uint32_t max_pkg;
    sb_err_t err;

    if (ctx == NULL || (data == NULL && len != 0)) {
        return SB_ERR_PARAM;
    }
    max_pkg = SB_MANIFEST_LEN + sb_max_image_size(ctx);
    if (len > max_pkg || pkg_off > max_pkg - (uint32_t)len) {
        return SB_ERR_RANGE;
    }
    err = sb_state_load(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    target = (uint8_t)(st.active ^ 1u);
    if (st.slot[target] != SB_SLOT_EMPTY) {
        return SB_ERR_STATE;
    }

    while (len != 0) {
        uint32_t dst;
        size_t n = len;
        if (pkg_off < SB_MANIFEST_LEN) {
            /* Manifest bytes go to the header sector. */
            dst = ctx->layout.slot_off[target] + pkg_off;
            if (n > SB_MANIFEST_LEN - pkg_off) {
                n = SB_MANIFEST_LEN - pkg_off;
            }
        } else {
            /* Ciphertext goes to the image area. */
            dst = sb_slot_image_off(ctx, target) + (pkg_off - SB_MANIFEST_LEN);
        }
        if (ctx->flash->write(ctx->flash->dev, dst, data, n) != 0) {
            return SB_ERR_FLASH;
        }
        data += n;
        pkg_off += (uint32_t)n;
        len -= n;
    }
    return SB_OK;
}

sb_err_t sb_update_finish(sb_ctx_t *ctx)
{
    sb_state_t st;
    uint8_t target;
    sb_err_t err;

    if (ctx == NULL) {
        return SB_ERR_PARAM;
    }
    err = sb_state_load(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    target = (uint8_t)(st.active ^ 1u);
    if (st.slot[target] != SB_SLOT_EMPTY) {
        return SB_ERR_STATE;
    }
    /* No validation here on purpose: the application is not trusted to
     * verify updates. The bootloader does it on the next reset. */
    st.slot[target] = SB_SLOT_DOWNLOADED;
    return sb_state_store(ctx, &st);
}

sb_err_t sb_update_confirm(sb_ctx_t *ctx)
{
    uint8_t raw[SB_MANIFEST_LEN];
    sb_manifest_t mf;
    sb_state_t st;
    uint32_t counter = 0;
    sb_err_t err;

    if (ctx == NULL) {
        return SB_ERR_PARAM;
    }
    err = sb_state_load(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    if (st.slot[st.active] != SB_SLOT_TRIAL && st.slot[st.active] != SB_SLOT_CONFIRMED) {
        return SB_ERR_STATE;
    }
    err = sb_slot_authenticate(ctx, st.active, raw, &mf);
    if (err != SB_OK) {
        return err;
    }

    /* State first, fuse second. If power is lost in between, the next boot
     * sees a CONFIRMED image with a higher counter and finishes the job. The
     * opposite order could strand the device with no bootable fallback. */
    if (st.slot[st.active] != SB_SLOT_CONFIRMED) {
        st.slot[st.active] = SB_SLOT_CONFIRMED;
        st.trials_left = 0;
        err = sb_state_store(ctx, &st);
        if (err != SB_OK) {
            return err;
        }
    }
    if (ctx->otp->read_counter(ctx->otp->dev, &counter) != 0) {
        return SB_ERR_OTP;
    }
    if (mf.security_counter > counter &&
        ctx->otp->advance_counter(ctx->otp->dev, mf.security_counter) != 0) {
        return SB_ERR_OTP;
    }
    return SB_OK;
}

/* ---- Bootloader side ----------------------------------------------------- */

static sb_err_t derive_image_key(sb_ctx_t *ctx, const sb_manifest_t *mf,
                                 uint8_t key[SB_AES256_KEY_LEN])
{
    uint8_t dev_key[SB_P256_PRIV_LEN];
    uint8_t shared[SB_P256_SHARED_LEN];
    uint8_t info[KDF_LABEL_LEN + SB_P256_PUB_LEN];
    sb_err_t err;

    if (ctx->otp->read_device_key(ctx->otp->dev, dev_key) != 0) {
        return SB_ERR_OTP;
    }
    err = sb_ecdh_p256(dev_key, mf->eph_pub, shared);
    sb_zeroize(dev_key, sizeof(dev_key));
    if (err == SB_OK) {
        /* Binding the ephemeral key into info ties the derived key to this
         * exact package. */
        memcpy(info, KDF_LABEL, KDF_LABEL_LEN);
        memcpy(info + KDF_LABEL_LEN, mf->eph_pub, SB_P256_PUB_LEN);
        err = sb_hkdf_sha256(NULL, 0, shared, sizeof(shared), info, sizeof(info), key,
                             SB_AES256_KEY_LEN);
    }
    sb_zeroize(shared, sizeof(shared));
    return err;
}

static sb_err_t decrypt_in_place(sb_ctx_t *ctx, uint8_t slot, const uint8_t *raw,
                                 const sb_manifest_t *mf)
{
    uint8_t key[SB_AES256_KEY_LEN];
    sb_gcm_ctx_t gcm;
    uint32_t base = sb_slot_image_off(ctx, slot);
    uint32_t done = 0;
    sb_err_t err;

    err = derive_image_key(ctx, mf, key);
    if (err != SB_OK) {
        return err;
    }
    err = sb_gcm_decrypt_begin(&gcm, key, mf->nonce, raw, SB_MANIFEST_AAD_LEN);
    sb_zeroize(key, sizeof(key));
    if (err != SB_OK) {
        return err;
    }

    while (done < mf->image_size) {
        uint32_t n = mf->image_size - done;
        if (n > ctx->flash->sector_size) {
            n = ctx->flash->sector_size;
        }
        if (ctx->flash->read(ctx->flash->dev, base + done, ctx->buf_in, n) != 0) {
            err = SB_ERR_FLASH;
            break;
        }
        err = sb_gcm_decrypt_update(&gcm, ctx->buf_in, n, ctx->buf_out);
        if (err != SB_OK) {
            break;
        }
        if (ctx->flash->erase(ctx->flash->dev, base + done) != 0 ||
            ctx->flash->write(ctx->flash->dev, base + done, ctx->buf_out, n) != 0) {
            err = SB_ERR_FLASH;
            break;
        }
        done += n;
    }

    if (err == SB_OK) {
        err = sb_gcm_decrypt_finish(&gcm, mf->tag);
    } else {
        sb_gcm_decrypt_abort(&gcm);
    }
    sb_zeroize(ctx->buf_out, sizeof(ctx->buf_out));
    return err;
}

sb_err_t sb_install(sb_ctx_t *ctx, sb_state_t *st, uint8_t slot)
{
    uint8_t raw[SB_MANIFEST_LEN];
    uint8_t digest[SB_SHA256_LEN];
    sb_manifest_t mf;
    sb_state_t next;
    sb_err_t err;

    /* 1-3. Trust anchor, signature, anti-rollback. Nothing below runs on an
     *      unauthenticated manifest. */
    err = sb_slot_authenticate(ctx, slot, raw, &mf);
    if (err != SB_OK) {
        return err;
    }

    /* 4. The ciphertext is authenticated BEFORE any key is derived or any
     *    byte is decrypted, so the decryptor never processes attacker data. */
    err = sb_slot_digest(ctx, slot, mf.image_size, digest);
    if (err != SB_OK) {
        return err;
    }
    if (!sb_ct_memeq(digest, mf.ct_digest, SB_SHA256_LEN)) {
        return SB_ERR_DIGEST;
    }

    /* 5. Point of no return for this slot: from here it holds a mix of
     *    ciphertext and plaintext until decryption completes. */
    next = *st;
    next.slot[slot] = SB_SLOT_DECRYPTING;
    err = sb_state_store(ctx, &next);
    if (err != SB_OK) {
        return err;
    }
    *st = next;

    err = decrypt_in_place(ctx, slot, raw, &mf);
    if (err != SB_OK) {
        return err;
    }

    /* 6. Belt and braces: the plaintext on flash must match the signed digest. */
    err = sb_slot_digest(ctx, slot, mf.image_size, digest);
    if (err != SB_OK) {
        return err;
    }
    if (!sb_ct_memeq(digest, mf.pt_digest, SB_SHA256_LEN)) {
        return SB_ERR_DIGEST;
    }

    /* 7. One atomic record flips the active slot and starts the trial. */
    next = *st;
    next.slot[slot] = SB_SLOT_TRIAL;
    next.trials_left = ctx->max_trials;
    next.active = slot;
    err = sb_state_store(ctx, &next);
    if (err != SB_OK) {
        return err;
    }
    *st = next;
    return SB_OK;
}

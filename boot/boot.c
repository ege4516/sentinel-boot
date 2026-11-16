/* SPDX-License-Identifier: MIT */
/**
 * @file boot.c
 * Reset-time policy: install pending updates, run the trial/revert state
 * machine, and hand back a slot whose image was verified on this very boot.
 */
#include <string.h>

#include "boot/internal.h"

/* Both state copies are unreadable (blank device, or corruption beyond a
 * single power cut). Rebuild the state from what the slots provably hold:
 * a slot is CONFIRMED iff its signature, counter and plaintext digest check
 * out. Prefers the higher security counter, then the higher version. */
static sb_err_t recover_state(sb_ctx_t *ctx, sb_state_t *st)
{
    sb_manifest_t mf[SB_NUM_SLOTS];
    int ok[SB_NUM_SLOTS] = { 0, 0 };

    for (uint8_t s = 0; s < SB_NUM_SLOTS; s++) {
        sb_err_t err = sb_slot_verify_plain(ctx, s, &mf[s]);
        if (err == SB_OK) {
            ok[s] = 1;
        } else if (!sb_is_reject(err)) {
            return err;
        }
        st->slot[s] = ok[s] ? (uint8_t)SB_SLOT_CONFIRMED : (uint8_t)SB_SLOT_EMPTY;
    }
    st->trials_left = 0;
    st->active = 0;
    if (ok[1] && (!ok[0] || mf[1].security_counter > mf[0].security_counter ||
                  (mf[1].security_counter == mf[0].security_counter &&
                   mf[1].fw_version > mf[0].fw_version))) {
        st->active = 1;
    }
    if (!ok[0] && !ok[1]) {
        return SB_OK; /* Blank device: nothing worth persisting yet. */
    }
    return sb_state_store(ctx, st);
}

/* Deal with whatever the inactive slot holds: a staged package, or the
 * remains of an install that lost power. */
static sb_err_t process_pending(sb_ctx_t *ctx, sb_state_t *st, sb_boot_result_t *res)
{
    uint8_t slot = (uint8_t)(st->active ^ 1u);
    sb_manifest_t mf;
    sb_err_t err;

    if (st->slot[slot] == SB_SLOT_DECRYPTING) {
        /* Power was lost mid-install. If decryption had in fact finished
         * (only the final state write was lost), the slot verifies as
         * plaintext and the install can be completed. Otherwise the slot is
         * a mix of ciphertext and plaintext and is abandoned. */
        err = sb_slot_verify_plain(ctx, slot, &mf);
        if (err == SB_OK) {
            st->slot[slot] = SB_SLOT_TRIAL;
            st->trials_left = ctx->max_trials;
            st->active = slot;
            res->events |= SB_EVT_INSTALLED | SB_EVT_INSTALL_RESUMED;
            return sb_state_store(ctx, st);
        }
        if (!sb_is_reject(err)) {
            return err;
        }
        st->slot[slot] = SB_SLOT_INVALID;
        res->events |= SB_EVT_UPDATE_REJECTED;
        res->reject_reason = SB_ERR_STATE;
        return sb_state_store(ctx, st);
    }

    if (st->slot[slot] == SB_SLOT_DOWNLOADED) {
        err = sb_install(ctx, st, slot);
        if (err == SB_OK) {
            res->events |= SB_EVT_INSTALLED;
            return SB_OK;
        }
        if (!sb_is_reject(err)) {
            return err;
        }
        st->slot[slot] = SB_SLOT_INVALID;
        res->events |= SB_EVT_UPDATE_REJECTED;
        res->reject_reason = err;
        return sb_state_store(ctx, st);
    }
    return SB_OK;
}

static int bootable(uint8_t state)
{
    return state == SB_SLOT_TRIAL || state == SB_SLOT_CONFIRMED;
}

sb_err_t sb_boot(sb_ctx_t *ctx, sb_boot_result_t *result)
{
    sb_state_t st;
    sb_err_t err;
    int dirty = 0;
    int fallback = 0;

    if (ctx == NULL || result == NULL) {
        return SB_ERR_PARAM;
    }
    memset(result, 0, sizeof(*result));

    err = sb_state_load(ctx, &st);
    if (err != SB_OK) {
        return err;
    }
    if (!st.valid) {
        err = recover_state(ctx, &st);
        if (err != SB_OK) {
            return err;
        }
        if (st.valid) {
            result->events |= SB_EVT_STATE_RECOVERED;
        }
    }

    err = process_pending(ctx, &st, result);
    if (err != SB_OK) {
        return err;
    }

    /* Trial policy. The decrement is persisted BEFORE the image runs, so an
     * image that crashes or hangs still burns a trial. */
    if (st.slot[st.active] == SB_SLOT_TRIAL) {
        if (st.trials_left == 0) {
            st.slot[st.active] = SB_SLOT_INVALID;
            st.active = (uint8_t)(st.active ^ 1u);
            result->events |= SB_EVT_REVERTED;
        } else {
            st.trials_left--;
            result->events |= SB_EVT_TRIAL_BOOT;
        }
        err = sb_state_store(ctx, &st);
        if (err != SB_OK) {
            return err;
        }
    }

    /* Verify-then-boot, with one fallback to the other slot. Verification is
     * repeated on every boot: flash contents are never trusted across resets. */
    for (int attempt = 0; attempt < 2; attempt++) {
        uint8_t s = st.active;
        uint8_t other = (uint8_t)(s ^ 1u);

        if (bootable(st.slot[s])) {
            err = sb_slot_verify_plain(ctx, s, &result->manifest);
            if (err == SB_OK) {
                uint32_t counter = 0;
                if (ctx->otp->read_counter(ctx->otp->dev, &counter) != 0) {
                    return SB_ERR_OTP;
                }
                /* Completes a confirm that lost power before the fuse write. */
                if (st.slot[s] == SB_SLOT_CONFIRMED &&
                    result->manifest.security_counter > counter) {
                    if (ctx->otp->advance_counter(ctx->otp->dev,
                                                  result->manifest.security_counter) != 0) {
                        return SB_ERR_OTP;
                    }
                    result->events |= SB_EVT_COUNTER_ADVANCED;
                }
                result->slot = s;
                result->image_offset = sb_slot_image_off(ctx, s);
                return SB_OK;
            }
            if (!sb_is_reject(err)) {
                return err;
            }
            st.slot[s] = SB_SLOT_INVALID;
            result->events &= ~SB_EVT_TRIAL_BOOT;
            dirty = 1;
        }

        /* Only a CONFIRMED image is an acceptable fallback. */
        fallback = (attempt == 0 && st.slot[other] == SB_SLOT_CONFIRMED);
        if (fallback) {
            st.active = other;
            result->events |= SB_EVT_REVERTED;
            dirty = 1;
        }
        if (dirty) {
            err = sb_state_store(ctx, &st);
            if (err != SB_OK) {
                return err;
            }
            dirty = 0;
        }
        if (!fallback) {
            break;
        }
    }

    memset(&result->manifest, 0, sizeof(result->manifest));
    return SB_ERR_NO_IMAGE;
}

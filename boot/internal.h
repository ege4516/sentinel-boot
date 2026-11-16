/* SPDX-License-Identifier: MIT */
/** @file internal.h  Declarations shared between core translation units. */
#ifndef SB_INTERNAL_H
#define SB_INTERNAL_H

#include "boot/boot.h"

/** Persist a new state atomically (bumps seq, writes the older copy). */
sb_err_t sb_state_store(const sb_ctx_t *ctx, sb_state_t *st);

/** Flash offset of a slot's image area (just past the header sector). */
uint32_t sb_slot_image_off(const sb_ctx_t *ctx, uint8_t slot);

/**
 * Read a slot's manifest, check its signature against the trust anchor and
 * enforce the anti-rollback counter. Does not touch the image body.
 */
sb_err_t sb_slot_authenticate(sb_ctx_t *ctx, uint8_t slot, uint8_t raw[SB_MANIFEST_LEN],
                              sb_manifest_t *mf);

/** SHA-256 over the first len bytes of a slot's image area. */
sb_err_t sb_slot_digest(sb_ctx_t *ctx, uint8_t slot, uint32_t len, uint8_t out[SB_SHA256_LEN]);

/** Full check of an installed (plaintext) slot: authenticate + pt_digest. */
sb_err_t sb_slot_verify_plain(sb_ctx_t *ctx, uint8_t slot, sb_manifest_t *mf);

/**
 * Verify and decrypt the package staged in a slot, in place. On success the
 * slot holds plaintext and st has been stored with the slot in TRIAL and
 * active. On a verification failure st is left untouched.
 */
sb_err_t sb_install(sb_ctx_t *ctx, sb_state_t *st, uint8_t slot);

/** 1 if err means "the image is bad" rather than "the hardware failed". */
int sb_is_reject(sb_err_t err);

#endif /* SB_INTERNAL_H */

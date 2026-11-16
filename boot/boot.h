/* SPDX-License-Identifier: MIT */
/**
 * @file boot.h
 * Public API of the sentinel-boot core.
 *
 * Two callers exist:
 *  - the bootloader, which calls sb_boot() once per reset;
 *  - the application, which stages an update with sb_update_begin/write/finish
 *    and acknowledges a healthy new image with sb_update_confirm().
 *
 * The core performs no dynamic allocation and keeps all working memory in
 * sb_ctx_t.
 */
#ifndef SB_BOOT_H
#define SB_BOOT_H

#include <stddef.h>
#include <stdint.h>

#include "boot/manifest.h"
#include "boot/sb_error.h"
#include "hal/sb_hal.h"

#define SB_NUM_SLOTS 2u
#define SB_MAX_SECTOR_SIZE 4096u
#define SB_DEFAULT_TRIALS 3u

/** Flash partitioning. All offsets and sizes must be sector aligned. */
typedef struct {
    uint32_t state_off[2];            /**< Two one-sector boot-state copies */
    uint32_t slot_off[SB_NUM_SLOTS];  /**< Slot = 1 header sector + image area */
    uint32_t slot_size;               /**< Size of each slot, header included */
} sb_layout_t;

typedef enum {
    SB_SLOT_EMPTY = 0,      /**< Nothing usable */
    SB_SLOT_DOWNLOADED = 1, /**< Encrypted package staged, not yet verified */
    SB_SLOT_DECRYPTING = 2, /**< In-place decryption in progress */
    SB_SLOT_TRIAL = 3,      /**< Installed, awaiting confirmation */
    SB_SLOT_CONFIRMED = 4,  /**< Known-good image */
    SB_SLOT_INVALID = 5     /**< Rejected or abandoned */
} sb_slot_state_t;

/** Persistent boot state (stored twice, CRC protected). */
typedef struct {
    uint32_t seq;
    uint8_t active;                /**< Slot to boot */
    uint8_t slot[SB_NUM_SLOTS];    /**< sb_slot_state_t per slot */
    uint8_t trials_left;           /**< Boots left before a TRIAL slot is reverted */
    uint8_t valid;                 /**< RAM only: a valid copy was found */
    uint8_t copy;                  /**< RAM only: which copy holds this state */
} sb_state_t;

typedef struct {
    const sb_flash_t *flash;
    const sb_otp_t *otp;
    sb_layout_t layout;
    const uint8_t *root_pub;       /**< 65-byte root public key (untrusted storage) */
    uint8_t max_trials;
    uint8_t buf_in[SB_MAX_SECTOR_SIZE];
    uint8_t buf_out[SB_MAX_SECTOR_SIZE];
} sb_ctx_t;

/* Events reported by sb_boot(), OR-ed into sb_boot_result_t.events. */
#define SB_EVT_INSTALLED 0x01u        /**< A staged update was verified and installed */
#define SB_EVT_UPDATE_REJECTED 0x02u  /**< A staged update was rejected */
#define SB_EVT_TRIAL_BOOT 0x04u       /**< Booting an unconfirmed image */
#define SB_EVT_REVERTED 0x08u         /**< Fell back to the previous image */
#define SB_EVT_STATE_RECOVERED 0x10u  /**< Boot state was rebuilt by probing slots */
#define SB_EVT_COUNTER_ADVANCED 0x20u /**< OTP anti-rollback counter was raised */
#define SB_EVT_INSTALL_RESUMED 0x40u  /**< An interrupted install was completed */

typedef struct {
    uint8_t slot;               /**< Slot selected for boot */
    uint32_t image_offset;      /**< Flash offset of the verified image */
    sb_manifest_t manifest;     /**< Authenticated manifest of that image */
    uint32_t events;
    sb_err_t reject_reason;     /**< Why an update was rejected, if it was */
} sb_boot_result_t;

/**
 * Validate the layout and initialise a context.
 * @param root_pub Must stay valid for the lifetime of ctx.
 */
sb_err_t sb_ctx_init(sb_ctx_t *ctx, const sb_flash_t *flash, const sb_otp_t *otp,
                     const sb_layout_t *layout, const uint8_t root_pub[SB_P256_PUB_LEN]);

/** Largest image a slot can hold. */
uint32_t sb_max_image_size(const sb_ctx_t *ctx);

/**
 * Bootloader entry point. Installs a staged update if one is pending, applies
 * trial/revert policy, and returns a slot whose image has just been verified.
 *
 * @return SB_OK and a filled result, SB_ERR_NO_IMAGE if nothing is bootable,
 *         or SB_ERR_FLASH / SB_ERR_OTP on hardware failure.
 */
sb_err_t sb_boot(sb_ctx_t *ctx, sb_boot_result_t *result);

/** Erase the inactive slot and prepare it for a new package. */
sb_err_t sb_update_begin(sb_ctx_t *ctx);

/**
 * Write package bytes (manifest followed by ciphertext). Offsets are relative
 * to the start of the package; each byte must be written exactly once.
 */
sb_err_t sb_update_write(sb_ctx_t *ctx, uint32_t pkg_off, const uint8_t *data, size_t len);

/** Mark the staged package ready; it is verified and installed on next boot. */
sb_err_t sb_update_finish(sb_ctx_t *ctx);

/**
 * Called by a healthy application: make the running image permanent and
 * raise the OTP anti-rollback counter to its security counter.
 */
sb_err_t sb_update_confirm(sb_ctx_t *ctx);

/** Read the persistent boot state (for diagnostics). */
sb_err_t sb_state_load(const sb_ctx_t *ctx, sb_state_t *out);

#endif /* SB_BOOT_H */

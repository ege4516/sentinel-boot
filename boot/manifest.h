/* SPDX-License-Identifier: MIT */
/**
 * @file manifest.h
 * Signed update manifest: fixed-size, little-endian wire format.
 * See docs/image-format.md for the byte-level layout. A package is
 * manifest || proof block (boot/merkle.h) || ciphertext.
 */
#ifndef SB_MANIFEST_H
#define SB_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "boot/crypto_port.h"
#include "boot/sb_error.h"

#define SB_MANIFEST_MAGIC 0x314D4253u /* "SBM1" on the wire */
#define SB_MANIFEST_FORMAT 2u /* 2: requires a transparency-log inclusion proof */

/* Wire offsets */
#define SB_MF_OFF_MAGIC 0u
#define SB_MF_OFF_FORMAT 4u
#define SB_MF_OFF_FLAGS 6u
#define SB_MF_OFF_FW_VERSION 8u
#define SB_MF_OFF_SEC_COUNTER 12u
#define SB_MF_OFF_IMAGE_SIZE 16u
#define SB_MF_OFF_KEY_ID 20u
#define SB_MF_OFF_EPH_PUB 24u
#define SB_MF_OFF_NONCE 89u
#define SB_MF_OFF_TAG 101u
#define SB_MF_OFF_CT_DIGEST 117u
#define SB_MF_OFF_PT_DIGEST 149u
#define SB_MF_OFF_RESERVED 181u
#define SB_MF_OFF_SIGNATURE 184u

/** Bytes covered by the signature: everything before it. */
#define SB_MANIFEST_SIGNED_LEN 184u
/** Total manifest size on the wire. */
#define SB_MANIFEST_LEN 248u
/** Leading bytes bound into the AEAD as associated data (magic..key_id). */
#define SB_MANIFEST_AAD_LEN 24u
#define SB_KEY_ID_LEN 4u

typedef struct {
    uint16_t format;
    uint16_t flags;
    uint32_t fw_version;       /**< major<<24 | minor<<16 | patch */
    uint32_t security_counter; /**< Anti-rollback counter, compared with OTP */
    uint32_t image_size;       /**< Plaintext size == ciphertext size, bytes */
    uint8_t key_id[SB_KEY_ID_LEN]; /**< First bytes of SHA-256(root public key) */
    uint8_t eph_pub[SB_P256_PUB_LEN];
    uint8_t nonce[SB_GCM_NONCE_LEN];
    uint8_t tag[SB_GCM_TAG_LEN];
    uint8_t ct_digest[SB_SHA256_LEN];
    uint8_t pt_digest[SB_SHA256_LEN];
    uint8_t signature[SB_P256_SIG_LEN];
} sb_manifest_t;

/**
 * Parse and structurally validate a manifest. Performs NO cryptographic
 * checks: the result is untrusted until sb_manifest_verify() succeeds.
 *
 * @param buf            Raw bytes; must hold at least SB_MANIFEST_LEN.
 * @param len            Number of valid bytes in buf.
 * @param max_image_size Largest image the slot can hold.
 * @return SB_OK or SB_ERR_FORMAT / SB_ERR_PARAM.
 */
sb_err_t sb_manifest_parse(const uint8_t *buf, size_t len, uint32_t max_image_size,
                           sb_manifest_t *out);

/**
 * Authenticate a manifest against the device trust anchor.
 *
 * Order: (1) root key hashes to the OTP anchor, (2) key id matches,
 * (3) ECDSA signature over the signed region.
 *
 * @param raw           The same bytes passed to sb_manifest_parse().
 * @param mf            The parsed manifest.
 * @param root_pub      Root public key as stored in (untrusted) flash.
 * @param root_pub_hash SHA-256 of the root public key from OTP.
 */
sb_err_t sb_manifest_verify(const uint8_t raw[SB_MANIFEST_LEN], const sb_manifest_t *mf,
                            const uint8_t root_pub[SB_P256_PUB_LEN],
                            const uint8_t root_pub_hash[SB_SHA256_LEN]);

#endif /* SB_MANIFEST_H */

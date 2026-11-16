/* SPDX-License-Identifier: MIT */
/**
 * @file merkle.h
 * Transparency-log inclusion proofs (RFC 9162 section 2.1, SHA-256).
 *
 * Every release must be recorded in an append-only Merkle log run by a log
 * operator that holds a key separate from the firmware root key. A package
 * carries the signed tree head and an inclusion proof for its manifest. A
 * stolen root key is therefore not enough to ship firmware: the attacker would
 * also need the log key, or the unlogged release is visible to anyone who
 * audits the log.
 *
 * Not a blockchain: one operator, one signature. What it shares with a
 * blockchain is the append-only, publicly auditable hash structure.
 * Consistency between tree heads and freshness are NOT checked on the device.
 */
#ifndef SB_MERKLE_H
#define SB_MERKLE_H

#include <stddef.h>
#include <stdint.h>

#include "boot/crypto_port.h"
#include "boot/manifest.h"
#include "boot/sb_error.h"

#define SB_PROOF_MAX_DEPTH 8u

/* Proof block wire offsets (little-endian). */
#define SB_PF_OFF_INDEX 0u
#define SB_PF_OFF_TREE_SIZE 4u
#define SB_PF_OFF_PATH_LEN 8u
#define SB_PF_OFF_RESERVED 9u /* 3 bytes, zero */
#define SB_PF_OFF_ROOT 12u
#define SB_PF_OFF_SIGNATURE 44u
#define SB_PF_OFF_PATH 108u
#define SB_PROOF_LEN (SB_PF_OFF_PATH + SB_PROOF_MAX_DEPTH * SB_SHA256_LEN)

/** Manifest followed by proof block; the ciphertext starts right after. */
#define SB_HEADER_LEN (SB_MANIFEST_LEN + SB_PROOF_LEN)

typedef struct {
    uint32_t leaf_index;
    uint32_t tree_size;
    uint8_t path_len;
    uint8_t root[SB_SHA256_LEN];
    uint8_t signature[SB_P256_SIG_LEN]; /**< Log key's signature over the tree head */
    uint8_t path[SB_PROOF_MAX_DEPTH][SB_SHA256_LEN];
} sb_proof_t;

/** Leaf hash: SHA-256(0x00 || data). */
sb_err_t sb_merkle_leaf_hash(const uint8_t *data, size_t len, uint8_t out[SB_SHA256_LEN]);

/**
 * Verify an inclusion proof (RFC 9162 section 2.1.3.2).
 * @return SB_OK, SB_ERR_LOG if the proof does not lead to root, SB_ERR_PARAM.
 */
sb_err_t sb_merkle_verify_inclusion(uint32_t leaf_index, uint32_t tree_size,
                                    const uint8_t leaf_hash[SB_SHA256_LEN],
                                    const uint8_t (*path)[SB_SHA256_LEN], size_t path_len,
                                    const uint8_t root[SB_SHA256_LEN]);

/** Structural checks only (no cryptography). SB_ERR_LOG on any violation. */
sb_err_t sb_proof_parse(const uint8_t *buf, size_t len, sb_proof_t *out);

/**
 * Authenticate a manifest against the log.
 * Order: log key hashes to the OTP log anchor (SB_ERR_LOG_KEY), tree head
 * signature (SB_ERR_LOG_SIGNATURE), inclusion of the manifest (SB_ERR_LOG).
 * The leaf is SHA-256(0x00 || signed manifest region), so it commits to
 * every field the root key signed.
 */
sb_err_t sb_proof_verify(const uint8_t raw[SB_MANIFEST_LEN], const sb_proof_t *proof,
                         const uint8_t log_pub[SB_P256_PUB_LEN],
                         const uint8_t log_pub_hash[SB_SHA256_LEN]);

#endif /* SB_MERKLE_H */

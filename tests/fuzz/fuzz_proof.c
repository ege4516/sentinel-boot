/* SPDX-License-Identifier: MIT */
/**
 * @file fuzz_proof.c
 * libFuzzer target for the transparency-log proof block parser and verifier.
 *
 * Input layout: 364-byte proof block followed by a 248-byte manifest.
 * Checked properties: no memory errors (ASan/UBSan), and a proof that was
 * accepted has an in-range leaf index and a path no longer than the depth limit.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "boot/merkle.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* P-256 base point G: a valid public key, so verification reaches the signature check. */
static const uint8_t LOG_PUB[SB_P256_PUB_LEN] = {
    0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
    0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4,
    0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A,
    0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33,
    0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int ready;
    static uint8_t anchor[SB_SHA256_LEN];
    sb_proof_t proof;

    if (!ready) {
        if (sb_crypto_init() != SB_OK || sb_sha256(LOG_PUB, sizeof(LOG_PUB), anchor) != SB_OK) {
            abort();
        }
        ready = 1;
    }
    if (sb_proof_parse(data, size, &proof) != SB_OK) {
        return 0;
    }
    if (size < SB_PROOF_LEN || proof.leaf_index >= proof.tree_size ||
        proof.path_len > SB_PROOF_MAX_DEPTH) {
        abort(); /* parser accepted something it must not */
    }
    if (size >= SB_PROOF_LEN + SB_MANIFEST_LEN) {
        /* Almost always rejected at the signature; reaches the Merkle check only if the
         * fuzzer manages to forge a signature, which is the point of asserting no crash. */
        (void)sb_proof_verify(data + SB_PROOF_LEN, &proof, LOG_PUB, anchor);
    }
    return 0;
}

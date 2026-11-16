/* SPDX-License-Identifier: MIT */
/**
 * @file fuzz_manifest.c
 * libFuzzer target for the manifest parser and verifier: the first code that
 * touches attacker-controlled bytes.
 *
 * Input layout: 4 bytes little-endian "slot capacity", then manifest bytes.
 * Checked properties: no memory errors (ASan/UBSan), and a successful parse
 * always yields an image size within the capacity it was given.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "boot/manifest.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* P-256 base point G: a valid public key, so verification runs to the end. */
static const uint8_t ROOT_PUB[SB_P256_PUB_LEN] = {
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
    uint8_t raw[SB_MANIFEST_LEN];
    sb_manifest_t mf;
    uint32_t capacity;

    if (!ready) {
        if (sb_crypto_init() != SB_OK ||
            sb_sha256(ROOT_PUB, sizeof(ROOT_PUB), anchor) != SB_OK) {
            abort();
        }
        ready = 1;
    }
    if (size < 4) {
        return 0;
    }
    capacity = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
               ((uint32_t)data[3] << 24);
    data += 4;
    size -= 4;

    if (sb_manifest_parse(data, size, capacity, &mf) != SB_OK) {
        return 0;
    }
    if (size < SB_MANIFEST_LEN || mf.image_size == 0 || mf.image_size > capacity) {
        abort(); /* parser accepted something it must not */
    }

    memcpy(raw, data, SB_MANIFEST_LEN);
    /* Force the key id to match so every parsed input reaches the signature
     * check instead of stopping at the cheap key-id reject. */
    memcpy(raw + SB_MF_OFF_KEY_ID, anchor, SB_KEY_ID_LEN);
    memcpy(mf.key_id, anchor, SB_KEY_ID_LEN);
    (void)sb_manifest_verify(raw, &mf, ROOT_PUB, anchor);
    return 0;
}

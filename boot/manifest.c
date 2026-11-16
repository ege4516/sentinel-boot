/* SPDX-License-Identifier: MIT */
#include "boot/manifest.h"

#include <string.h>

_Static_assert(SB_MF_OFF_EPH_PUB + SB_P256_PUB_LEN == SB_MF_OFF_NONCE, "layout");
_Static_assert(SB_MF_OFF_NONCE + SB_GCM_NONCE_LEN == SB_MF_OFF_TAG, "layout");
_Static_assert(SB_MF_OFF_TAG + SB_GCM_TAG_LEN == SB_MF_OFF_CT_DIGEST, "layout");
_Static_assert(SB_MF_OFF_CT_DIGEST + SB_SHA256_LEN == SB_MF_OFF_PT_DIGEST, "layout");
_Static_assert(SB_MF_OFF_PT_DIGEST + SB_SHA256_LEN == SB_MF_OFF_RESERVED, "layout");
_Static_assert(SB_MF_OFF_SIGNATURE == SB_MANIFEST_SIGNED_LEN, "layout");
_Static_assert(SB_MF_OFF_SIGNATURE + SB_P256_SIG_LEN == SB_MANIFEST_LEN, "layout");

/* Explicit little-endian reads: no struct casts, no alignment assumptions. */
static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

sb_err_t sb_manifest_parse(const uint8_t *buf, size_t len, uint32_t max_image_size,
                           sb_manifest_t *out)
{
    if (buf == NULL || out == NULL) {
        return SB_ERR_PARAM;
    }
    if (len < SB_MANIFEST_LEN) {
        return SB_ERR_FORMAT;
    }
    if (rd_le32(buf + SB_MF_OFF_MAGIC) != SB_MANIFEST_MAGIC) {
        return SB_ERR_FORMAT;
    }

    memset(out, 0, sizeof(*out));
    out->format = rd_le16(buf + SB_MF_OFF_FORMAT);
    out->flags = rd_le16(buf + SB_MF_OFF_FLAGS);
    out->fw_version = rd_le32(buf + SB_MF_OFF_FW_VERSION);
    out->security_counter = rd_le32(buf + SB_MF_OFF_SEC_COUNTER);
    out->image_size = rd_le32(buf + SB_MF_OFF_IMAGE_SIZE);

    /* Unknown formats and flags are rejected, not ignored: a future format
     * must not be half-understood by an old bootloader. */
    if (out->format != SB_MANIFEST_FORMAT || out->flags != 0) {
        return SB_ERR_FORMAT;
    }
    if (out->image_size == 0 || out->image_size > max_image_size) {
        return SB_ERR_FORMAT;
    }
    for (size_t i = SB_MF_OFF_RESERVED; i < SB_MF_OFF_SIGNATURE; i++) {
        if (buf[i] != 0) {
            return SB_ERR_FORMAT;
        }
    }
    /* Only uncompressed SEC1 points are accepted. Curve membership is
     * checked by the crypto backend when the key is used. */
    if (buf[SB_MF_OFF_EPH_PUB] != 0x04) {
        return SB_ERR_FORMAT;
    }

    memcpy(out->key_id, buf + SB_MF_OFF_KEY_ID, SB_KEY_ID_LEN);
    memcpy(out->eph_pub, buf + SB_MF_OFF_EPH_PUB, SB_P256_PUB_LEN);
    memcpy(out->nonce, buf + SB_MF_OFF_NONCE, SB_GCM_NONCE_LEN);
    memcpy(out->tag, buf + SB_MF_OFF_TAG, SB_GCM_TAG_LEN);
    memcpy(out->ct_digest, buf + SB_MF_OFF_CT_DIGEST, SB_SHA256_LEN);
    memcpy(out->pt_digest, buf + SB_MF_OFF_PT_DIGEST, SB_SHA256_LEN);
    memcpy(out->signature, buf + SB_MF_OFF_SIGNATURE, SB_P256_SIG_LEN);
    return SB_OK;
}

sb_err_t sb_manifest_verify(const uint8_t raw[SB_MANIFEST_LEN], const sb_manifest_t *mf,
                            const uint8_t root_pub[SB_P256_PUB_LEN],
                            const uint8_t root_pub_hash[SB_SHA256_LEN])
{
    uint8_t digest[SB_SHA256_LEN];
    sb_err_t err;

    if (raw == NULL || mf == NULL || root_pub == NULL || root_pub_hash == NULL) {
        return SB_ERR_PARAM;
    }

    /* 1. The root key lives in ordinary flash; trust it only if it hashes
     *    to the immutable OTP anchor. */
    err = sb_sha256(root_pub, SB_P256_PUB_LEN, digest);
    if (err != SB_OK) {
        return err;
    }
    if (!sb_ct_memeq(digest, root_pub_hash, SB_SHA256_LEN)) {
        return SB_ERR_KEY;
    }

    /* 2. Key id is a cheap early reject for images signed for another key. */
    if (!sb_ct_memeq(digest, mf->key_id, SB_KEY_ID_LEN)) {
        return SB_ERR_KEY;
    }

    /* 3. Signature over the raw signed region (not the parsed struct). */
    err = sb_sha256(raw, SB_MANIFEST_SIGNED_LEN, digest);
    if (err != SB_OK) {
        return err;
    }
    return sb_ecdsa_p256_verify(root_pub, digest, mf->signature);
}

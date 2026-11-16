/* SPDX-License-Identifier: MIT */
#include "boot/merkle.h"

#include <string.h>


_Static_assert(SB_PF_OFF_ROOT + SB_SHA256_LEN == SB_PF_OFF_SIGNATURE, "layout");
_Static_assert(SB_PF_OFF_SIGNATURE + SB_P256_SIG_LEN == SB_PF_OFF_PATH, "layout");

/* Domain label of the signed tree head. Must match tools/sentinel_log.py. */
static const uint8_t TREE_HEAD_LABEL[] = "sentinel-boot/v1/tree-head";
#define TREE_HEAD_LABEL_LEN (sizeof(TREE_HEAD_LABEL) - 1u)

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

sb_err_t sb_merkle_leaf_hash(const uint8_t *data, size_t len, uint8_t out[SB_SHA256_LEN])
{
    static const uint8_t prefix = 0x00;
    sb_sha256_ctx_t ctx;
    sb_err_t err;

    if (data == NULL || out == NULL) {
        return SB_ERR_PARAM;
    }
    err = sb_sha256_init(&ctx);
    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, &prefix, 1);
    }
    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, data, len);
    }
    if (err == SB_OK) {
        err = sb_sha256_finish(&ctx, out);
    }
    return err;
}

/* out = SHA-256(0x01 || left || right). out may alias left or right. */
static sb_err_t node_hash(const uint8_t left[SB_SHA256_LEN], const uint8_t right[SB_SHA256_LEN],
                          uint8_t out[SB_SHA256_LEN])
{
    static const uint8_t prefix = 0x01;
    sb_sha256_ctx_t ctx;
    uint8_t tmp[SB_SHA256_LEN];
    sb_err_t err = sb_sha256_init(&ctx);

    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, &prefix, 1);
    }
    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, left, SB_SHA256_LEN);
    }
    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, right, SB_SHA256_LEN);
    }
    if (err == SB_OK) {
        err = sb_sha256_finish(&ctx, tmp);
    }
    if (err == SB_OK) {
        memcpy(out, tmp, SB_SHA256_LEN);
    }
    return err;
}

sb_err_t sb_merkle_verify_inclusion(uint32_t leaf_index, uint32_t tree_size,
                                    const uint8_t leaf_hash[SB_SHA256_LEN],
                                    const uint8_t (*path)[SB_SHA256_LEN], size_t path_len,
                                    const uint8_t root[SB_SHA256_LEN])
{
    uint8_t r[SB_SHA256_LEN];
    uint32_t fn;
    uint32_t sn;
    sb_err_t err;

    if (leaf_hash == NULL || root == NULL || (path == NULL && path_len != 0)) {
        return SB_ERR_PARAM;
    }
    /* RFC 9162 2.1.3.2 step 1 */
    if (tree_size == 0 || leaf_index >= tree_size) {
        return SB_ERR_LOG;
    }
    fn = leaf_index;
    sn = tree_size - 1u;
    memcpy(r, leaf_hash, SB_SHA256_LEN);

    for (size_t i = 0; i < path_len; i++) {
        if (sn == 0) {
            return SB_ERR_LOG; /* proof longer than the tree is deep */
        }
        if ((fn & 1u) != 0 || fn == sn) {
            err = node_hash(path[i], r, r);
            if (err != SB_OK) {
                return err;
            }
            if ((fn & 1u) == 0) {
                while ((fn & 1u) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            err = node_hash(r, path[i], r);
            if (err != SB_OK) {
                return err;
            }
        }
        fn >>= 1;
        sn >>= 1;
    }
    if (sn != 0 || !sb_ct_memeq(r, root, SB_SHA256_LEN)) {
        return SB_ERR_LOG;
    }
    return SB_OK;
}

sb_err_t sb_proof_parse(const uint8_t *buf, size_t len, sb_proof_t *out)
{
    if (buf == NULL || out == NULL) {
        return SB_ERR_PARAM;
    }
    if (len < SB_PROOF_LEN) {
        return SB_ERR_LOG;
    }
    memset(out, 0, sizeof(*out));
    out->leaf_index = rd_le32(buf + SB_PF_OFF_INDEX);
    out->tree_size = rd_le32(buf + SB_PF_OFF_TREE_SIZE);
    out->path_len = buf[SB_PF_OFF_PATH_LEN];

    if (out->tree_size == 0 || out->leaf_index >= out->tree_size ||
        out->path_len > SB_PROOF_MAX_DEPTH) {
        return SB_ERR_LOG;
    }
    for (size_t i = 0; i < 3; i++) {
        if (buf[SB_PF_OFF_RESERVED + i] != 0) {
            return SB_ERR_LOG;
        }
    }
    /* Unused path slots must be zero so a package has exactly one encoding. */
    for (size_t i = (size_t)out->path_len * SB_SHA256_LEN;
         i < (size_t)SB_PROOF_MAX_DEPTH * SB_SHA256_LEN; i++) {
        if (buf[SB_PF_OFF_PATH + i] != 0) {
            return SB_ERR_LOG;
        }
    }
    memcpy(out->root, buf + SB_PF_OFF_ROOT, SB_SHA256_LEN);
    memcpy(out->signature, buf + SB_PF_OFF_SIGNATURE, SB_P256_SIG_LEN);
    memcpy(out->path, buf + SB_PF_OFF_PATH, (size_t)out->path_len * SB_SHA256_LEN);
    return SB_OK;
}

sb_err_t sb_proof_verify(const uint8_t raw[SB_MANIFEST_LEN], const sb_proof_t *proof,
                         const uint8_t log_pub[SB_P256_PUB_LEN],
                         const uint8_t log_pub_hash[SB_SHA256_LEN])
{
    uint8_t digest[SB_SHA256_LEN];
    uint8_t head[TREE_HEAD_LABEL_LEN + 4u + SB_SHA256_LEN];
    uint8_t leaf[SB_SHA256_LEN];
    sb_err_t err;

    if (raw == NULL || proof == NULL || log_pub == NULL || log_pub_hash == NULL) {
        return SB_ERR_PARAM;
    }

    /* 1. The log key lives in ordinary flash; trust it only if it hashes to
     *    the log anchor burned into OTP. */
    err = sb_sha256(log_pub, SB_P256_PUB_LEN, digest);
    if (err != SB_OK) {
        return err;
    }
    if (!sb_ct_memeq(digest, log_pub_hash, SB_SHA256_LEN)) {
        return SB_ERR_LOG_KEY;
    }

    /* 2. Signed tree head: label || tree_size (LE32) || root. */
    memcpy(head, TREE_HEAD_LABEL, TREE_HEAD_LABEL_LEN);
    head[TREE_HEAD_LABEL_LEN + 0] = (uint8_t)(proof->tree_size & 0xFFu);
    head[TREE_HEAD_LABEL_LEN + 1] = (uint8_t)((proof->tree_size >> 8) & 0xFFu);
    head[TREE_HEAD_LABEL_LEN + 2] = (uint8_t)((proof->tree_size >> 16) & 0xFFu);
    head[TREE_HEAD_LABEL_LEN + 3] = (uint8_t)((proof->tree_size >> 24) & 0xFFu);
    memcpy(head + TREE_HEAD_LABEL_LEN + 4u, proof->root, SB_SHA256_LEN);
    err = sb_sha256(head, sizeof(head), digest);
    if (err != SB_OK) {
        return err;
    }
    err = sb_ecdsa_p256_verify(log_pub, digest, proof->signature);
    if (err == SB_ERR_SIGNATURE || err == SB_ERR_KEY) {
        return SB_ERR_LOG_SIGNATURE;
    }
    if (err != SB_OK) {
        return err;
    }

    /* 3. The leaf commits to the exact signed manifest bytes. */
    err = sb_merkle_leaf_hash(raw, SB_MANIFEST_SIGNED_LEN, leaf);
    if (err != SB_OK) {
        return err;
    }
    return sb_merkle_verify_inclusion(proof->leaf_index, proof->tree_size, leaf,
                                      (const uint8_t(*)[SB_SHA256_LEN])proof->path,
                                      proof->path_len, proof->root);
}

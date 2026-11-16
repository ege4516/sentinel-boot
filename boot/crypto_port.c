/* SPDX-License-Identifier: MIT */
#include "boot/crypto_port.h"

#include <string.h>

#include <psa/crypto.h>

_Static_assert(sizeof(psa_hash_operation_t) <= sizeof(((sb_sha256_ctx_t *)0)->opaque),
               "sb_sha256_ctx_t too small for the PSA backend");
_Static_assert(sizeof(psa_aead_operation_t) <= sizeof(((sb_gcm_ctx_t *)0)->opaque),
               "sb_gcm_ctx_t too small for the PSA backend");
_Static_assert(sizeof(mbedtls_svc_key_id_t) <= sizeof(uint32_t),
               "key handle does not fit sb_gcm_ctx_t");

static psa_hash_operation_t *hash_op(sb_sha256_ctx_t *ctx)
{
    return (psa_hash_operation_t *)(void *)ctx->opaque;
}

static psa_aead_operation_t *aead_op(sb_gcm_ctx_t *ctx)
{
    return (psa_aead_operation_t *)(void *)ctx->opaque;
}

const char *sb_strerror(sb_err_t err)
{
    switch (err) {
    case SB_OK: return "ok";
    case SB_ERR_PARAM: return "invalid parameter";
    case SB_ERR_CRYPTO: return "crypto backend failure";
    case SB_ERR_FORMAT: return "malformed manifest";
    case SB_ERR_KEY: return "untrusted or invalid key";
    case SB_ERR_SIGNATURE: return "signature rejected";
    case SB_ERR_ROLLBACK: return "rollback rejected";
    case SB_ERR_DIGEST: return "digest mismatch";
    case SB_ERR_AUTH: return "authentication tag rejected";
    case SB_ERR_FLASH: return "flash error";
    case SB_ERR_OTP: return "otp error";
    case SB_ERR_STATE: return "invalid state";
    case SB_ERR_NO_IMAGE: return "no bootable image";
    case SB_ERR_RANGE: return "out of range";
    case SB_ERR_LOG: return "transparency log proof rejected";
    case SB_ERR_LOG_KEY: return "untrusted log key";
    case SB_ERR_LOG_SIGNATURE: return "tree head signature rejected";
    default: return "unknown error";
    }
}

sb_err_t sb_crypto_init(void)
{
    return psa_crypto_init() == PSA_SUCCESS ? SB_OK : SB_ERR_CRYPTO;
}

/* ---- SHA-256 ------------------------------------------------------------ */

sb_err_t sb_sha256_init(sb_sha256_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SB_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    *hash_op(ctx) = psa_hash_operation_init();
    if (psa_hash_setup(hash_op(ctx), PSA_ALG_SHA_256) != PSA_SUCCESS) {
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

sb_err_t sb_sha256_update(sb_sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || (data == NULL && len != 0)) {
        return SB_ERR_PARAM;
    }
    if (len == 0) {
        return SB_OK;
    }
    if (psa_hash_update(hash_op(ctx), data, len) != PSA_SUCCESS) {
        (void)psa_hash_abort(hash_op(ctx));
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

sb_err_t sb_sha256_finish(sb_sha256_ctx_t *ctx, uint8_t out[SB_SHA256_LEN])
{
    size_t out_len = 0;
    if (ctx == NULL || out == NULL) {
        return SB_ERR_PARAM;
    }
    if (psa_hash_finish(hash_op(ctx), out, SB_SHA256_LEN, &out_len) != PSA_SUCCESS ||
        out_len != SB_SHA256_LEN) {
        (void)psa_hash_abort(hash_op(ctx));
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

sb_err_t sb_sha256(const uint8_t *data, size_t len, uint8_t out[SB_SHA256_LEN])
{
    sb_sha256_ctx_t ctx;
    sb_err_t err = sb_sha256_init(&ctx);
    if (err == SB_OK) {
        err = sb_sha256_update(&ctx, data, len);
    }
    if (err == SB_OK) {
        err = sb_sha256_finish(&ctx, out);
    }
    return err;
}

/* ---- ECDSA P-256 -------------------------------------------------------- */

sb_err_t sb_ecdsa_p256_verify(const uint8_t pub[SB_P256_PUB_LEN],
                              const uint8_t digest[SB_SHA256_LEN],
                              const uint8_t sig[SB_P256_SIG_LEN])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st;

    if (pub == NULL || digest == NULL || sig == NULL) {
        return SB_ERR_PARAM;
    }

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    /* Import validates that the point is on the curve. */
    st = psa_import_key(&attr, pub, SB_P256_PUB_LEN, &key);
    if (st != PSA_SUCCESS) {
        return st == PSA_ERROR_INVALID_ARGUMENT ? SB_ERR_KEY : SB_ERR_CRYPTO;
    }

    st = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest, SB_SHA256_LEN, sig,
                         SB_P256_SIG_LEN);
    (void)psa_destroy_key(key);

    if (st == PSA_SUCCESS) {
        return SB_OK;
    }
    if (st == PSA_ERROR_INVALID_SIGNATURE) {
        return SB_ERR_SIGNATURE;
    }
    return SB_ERR_CRYPTO;
}

/* ---- ECDH P-256 --------------------------------------------------------- */

sb_err_t sb_ecdh_p256(const uint8_t priv[SB_P256_PRIV_LEN],
                      const uint8_t peer_pub[SB_P256_PUB_LEN],
                      uint8_t shared[SB_P256_SHARED_LEN])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st;
    size_t out_len = 0;

    if (priv == NULL || peer_pub == NULL || shared == NULL) {
        return SB_ERR_PARAM;
    }

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    st = psa_import_key(&attr, priv, SB_P256_PRIV_LEN, &key);
    if (st != PSA_SUCCESS) {
        return st == PSA_ERROR_INVALID_ARGUMENT ? SB_ERR_KEY : SB_ERR_CRYPTO;
    }

    /* The backend rejects peer points that are not on the curve. */
    st = psa_raw_key_agreement(PSA_ALG_ECDH, key, peer_pub, SB_P256_PUB_LEN, shared,
                               SB_P256_SHARED_LEN, &out_len);
    (void)psa_destroy_key(key);

    if (st != PSA_SUCCESS || out_len != SB_P256_SHARED_LEN) {
        sb_zeroize(shared, SB_P256_SHARED_LEN);
        return st == PSA_ERROR_INVALID_ARGUMENT ? SB_ERR_KEY : SB_ERR_CRYPTO;
    }
    return SB_OK;
}

/* ---- HKDF-SHA256 -------------------------------------------------------- */

sb_err_t sb_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    static const uint8_t empty = 0;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t st;

    if (ikm == NULL || out == NULL || out_len == 0 || (salt == NULL && salt_len != 0) ||
        (info == NULL && info_len != 0)) {
        return SB_ERR_PARAM;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt_len != 0 ? salt : &empty, salt_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm, ikm_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            info_len != 0 ? info : &empty, info_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_key_derivation_output_bytes(&op, out, out_len);
    }
    (void)psa_key_derivation_abort(&op);

    if (st != PSA_SUCCESS) {
        sb_zeroize(out, out_len);
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

/* ---- AES-256-GCM (streaming decrypt) ------------------------------------ */

sb_err_t sb_gcm_decrypt_begin(sb_gcm_ctx_t *ctx,
                              const uint8_t key[SB_AES256_KEY_LEN],
                              const uint8_t nonce[SB_GCM_NONCE_LEN],
                              const uint8_t *aad, size_t aad_len)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t st;

    if (ctx == NULL || key == NULL || nonce == NULL || (aad == NULL && aad_len != 0)) {
        return SB_ERR_PARAM;
    }
    memset(ctx, 0, sizeof(*ctx));
    *aead_op(ctx) = psa_aead_operation_init();

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    st = psa_import_key(&attr, key, SB_AES256_KEY_LEN, &kid);
    if (st != PSA_SUCCESS) {
        return SB_ERR_CRYPTO;
    }
    ctx->key_handle = (uint32_t)kid;
    ctx->active = 1;

    st = psa_aead_decrypt_setup(aead_op(ctx), kid, PSA_ALG_GCM);
    if (st == PSA_SUCCESS) {
        st = psa_aead_set_nonce(aead_op(ctx), nonce, SB_GCM_NONCE_LEN);
    }
    if (st == PSA_SUCCESS && aad_len != 0) {
        st = psa_aead_update_ad(aead_op(ctx), aad, aad_len);
    }
    if (st != PSA_SUCCESS) {
        sb_gcm_decrypt_abort(ctx);
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

sb_err_t sb_gcm_decrypt_update(sb_gcm_ctx_t *ctx, const uint8_t *in, size_t len, uint8_t *out)
{
    size_t produced = 0;
    psa_status_t st;

    if (ctx == NULL || !ctx->active || (len != 0 && (in == NULL || out == NULL))) {
        return SB_ERR_PARAM;
    }
    if (len == 0) {
        return SB_OK;
    }
    st = psa_aead_update(aead_op(ctx), in, len, out, len, &produced);
    if (st != PSA_SUCCESS || produced != len) {
        sb_gcm_decrypt_abort(ctx);
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

sb_err_t sb_gcm_decrypt_finish(sb_gcm_ctx_t *ctx, const uint8_t tag[SB_GCM_TAG_LEN])
{
    uint8_t tail[16];
    size_t tail_len = 0;
    psa_status_t st;

    if (ctx == NULL || !ctx->active || tag == NULL) {
        return SB_ERR_PARAM;
    }
    st = psa_aead_verify(aead_op(ctx), tail, sizeof(tail), &tail_len, tag, SB_GCM_TAG_LEN);
    sb_gcm_decrypt_abort(ctx);

    if (st == PSA_ERROR_INVALID_SIGNATURE) {
        return SB_ERR_AUTH;
    }
    if (st != PSA_SUCCESS || tail_len != 0) {
        return SB_ERR_CRYPTO;
    }
    return SB_OK;
}

void sb_gcm_decrypt_abort(sb_gcm_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->active) {
        return;
    }
    (void)psa_aead_abort(aead_op(ctx));
    (void)psa_destroy_key((mbedtls_svc_key_id_t)ctx->key_handle);
    sb_zeroize(ctx, sizeof(*ctx));
}

/* ---- Helpers ------------------------------------------------------------ */

int sb_ct_memeq(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (a[i] ^ b[i]));
    }
    /* Map 0 -> 1 and non-zero -> 0 without a data-dependent branch. */
    return (int)(1u & (((uint32_t)diff - 1u) >> 8));
}

void sb_zeroize(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len-- != 0) {
        *v++ = 0;
    }
}

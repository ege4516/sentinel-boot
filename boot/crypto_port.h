/* SPDX-License-Identifier: MIT */
/**
 * @file crypto_port.h
 * Thin, fixed-purpose wrappers over the PSA Crypto API.
 *
 * The bootloader never calls the crypto library directly. Porting to another
 * backend (a hardware accelerator, a secure element) means reimplementing
 * this one file.
 */
#ifndef SB_CRYPTO_PORT_H
#define SB_CRYPTO_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "boot/sb_error.h"

#define SB_SHA256_LEN 32u
#define SB_P256_PUB_LEN 65u  /**< Uncompressed SEC1 point: 0x04 || X || Y */
#define SB_P256_PRIV_LEN 32u
#define SB_P256_SIG_LEN 64u  /**< Raw r || s (IEEE P1363), not DER */
#define SB_P256_SHARED_LEN 32u
#define SB_AES256_KEY_LEN 32u
#define SB_GCM_NONCE_LEN 12u
#define SB_GCM_TAG_LEN 16u

/** Opaque streaming SHA-256 context, sized for the backend. */
typedef struct {
    uint64_t opaque[32];
} sb_sha256_ctx_t;

/** Opaque streaming AES-256-GCM decryption context. */
typedef struct {
    uint64_t opaque[64];
    uint32_t key_handle;
    uint8_t active;
} sb_gcm_ctx_t;

/** Initialise the crypto backend. Idempotent. */
sb_err_t sb_crypto_init(void);

sb_err_t sb_sha256_init(sb_sha256_ctx_t *ctx);
sb_err_t sb_sha256_update(sb_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
sb_err_t sb_sha256_finish(sb_sha256_ctx_t *ctx, uint8_t out[SB_SHA256_LEN]);
sb_err_t sb_sha256(const uint8_t *data, size_t len, uint8_t out[SB_SHA256_LEN]);

/**
 * Verify an ECDSA P-256 signature over a SHA-256 digest.
 * @return SB_OK, SB_ERR_SIGNATURE on rejection, SB_ERR_KEY if the public key
 *         is not a valid curve point, SB_ERR_CRYPTO otherwise.
 */
sb_err_t sb_ecdsa_p256_verify(const uint8_t pub[SB_P256_PUB_LEN],
                              const uint8_t digest[SB_SHA256_LEN],
                              const uint8_t sig[SB_P256_SIG_LEN]);

/** ECDH on P-256. Output is the raw X coordinate of the shared point. */
sb_err_t sb_ecdh_p256(const uint8_t priv[SB_P256_PRIV_LEN],
                      const uint8_t peer_pub[SB_P256_PUB_LEN],
                      uint8_t shared[SB_P256_SHARED_LEN]);

/** HKDF-SHA256 (RFC 5869), extract-then-expand. salt may be NULL if salt_len is 0. */
sb_err_t sb_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len);

/**
 * Begin a streaming AES-256-GCM decryption.
 * Plaintext produced by sb_gcm_update() is UNAUTHENTICATED until
 * sb_gcm_finish() returns SB_OK.
 */
sb_err_t sb_gcm_decrypt_begin(sb_gcm_ctx_t *ctx,
                              const uint8_t key[SB_AES256_KEY_LEN],
                              const uint8_t nonce[SB_GCM_NONCE_LEN],
                              const uint8_t *aad, size_t aad_len);

/**
 * Decrypt a chunk. Every call except the last must pass a multiple of 16
 * bytes; out must hold len bytes. in and out must not overlap.
 */
sb_err_t sb_gcm_decrypt_update(sb_gcm_ctx_t *ctx, const uint8_t *in, size_t len, uint8_t *out);

/** Check the tag and release the key. SB_ERR_AUTH if the tag is wrong. */
sb_err_t sb_gcm_decrypt_finish(sb_gcm_ctx_t *ctx, const uint8_t tag[SB_GCM_TAG_LEN]);

/** Release a context without checking the tag. Safe on an inactive context. */
void sb_gcm_decrypt_abort(sb_gcm_ctx_t *ctx);

/** Constant-time comparison. Returns 1 if equal, 0 otherwise. */
int sb_ct_memeq(const uint8_t *a, const uint8_t *b, size_t len);

/** Zeroise memory in a way the compiler may not elide. */
void sb_zeroize(void *p, size_t len);

#endif /* SB_CRYPTO_PORT_H */

/* SPDX-License-Identifier: MIT */
#ifndef SB_ERROR_H
#define SB_ERROR_H

/** Status codes shared by every sentinel-boot module. Zero is success. */
typedef enum {
    SB_OK = 0,
    SB_ERR_PARAM = -1,        /**< NULL pointer or out-of-range argument */
    SB_ERR_CRYPTO = -2,       /**< Crypto backend failure (not an auth failure) */
    SB_ERR_FORMAT = -3,       /**< Manifest is malformed */
    SB_ERR_KEY = -4,          /**< Root key does not match the OTP anchor / key id */
    SB_ERR_SIGNATURE = -5,    /**< Manifest signature rejected */
    SB_ERR_ROLLBACK = -6,     /**< Security counter below the OTP counter */
    SB_ERR_DIGEST = -7,       /**< Ciphertext or plaintext digest mismatch */
    SB_ERR_AUTH = -8,         /**< AEAD tag rejected */
    SB_ERR_FLASH = -9,        /**< Flash driver error */
    SB_ERR_OTP = -10,         /**< OTP driver error */
    SB_ERR_STATE = -11,       /**< Operation not valid in the current slot state */
    SB_ERR_NO_IMAGE = -12,    /**< No bootable image in any slot */
    SB_ERR_RANGE = -13        /**< Offset/length outside the slot */
} sb_err_t;

/** Human readable name for a status code. Never returns NULL. */
const char *sb_strerror(sb_err_t err);

#endif /* SB_ERROR_H */

/* SPDX-License-Identifier: MIT */
/**
 * @file sb_hal.h
 * Hardware abstraction consumed by the bootloader core. A port provides one
 * flash device and one OTP / secure-storage device.
 */
#ifndef SB_HAL_H
#define SB_HAL_H

#include <stddef.h>
#include <stdint.h>

/** NOR-flash-like device. All functions return 0 on success, non-zero on error. */
typedef struct {
    void *dev;
    uint32_t size;        /**< Total size in bytes */
    uint32_t sector_size; /**< Erase granularity in bytes (power of two) */
    int (*read)(void *dev, uint32_t off, uint8_t *buf, size_t len);
    /** Program bytes. Can only clear bits (1 -> 0); erase first. */
    int (*write)(void *dev, uint32_t off, const uint8_t *buf, size_t len);
    /** Erase the sector starting at off (must be sector aligned) to 0xFF. */
    int (*erase)(void *dev, uint32_t off);
} sb_flash_t;

/** One-time-programmable / secure storage. Models a root of trust. */
typedef struct {
    void *dev;
    /** SHA-256 of the root public key (trust anchor). */
    int (*read_root_key_hash)(void *dev, uint8_t out[32]);
    /** SHA-256 of the transparency-log public key (second trust anchor). */
    int (*read_log_key_hash)(void *dev, uint8_t out[32]);
    /** Device ECDH P-256 private key used to unwrap image keys. */
    int (*read_device_key)(void *dev, uint8_t out[32]);
    /** Monotonic anti-rollback counter. */
    int (*read_counter)(void *dev, uint32_t *out);
    /** Raise the counter. Must fail if value is lower than the current one. */
    int (*advance_counter)(void *dev, uint32_t value);
} sb_otp_t;

#endif /* SB_HAL_H */

/* SPDX-License-Identifier: MIT */
/*
 * Bare-metal tweaks applied on top of Mbed TLS's default configuration for the
 * QEMU Cortex-M3 self-test. Only the crypto library (mbedcrypto) is built.
 */
#ifndef SB_MBEDTLS_USER_CONFIG_H
#define SB_MBEDTLS_USER_CONFIG_H

/* No operating system services on the target. */
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_NET_C

/* No persistent key store: keys live only for the duration of an operation. */
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C

/*
 * Entropy. The emulated board has no hardware RNG, so the platform entropy
 * source is replaced by mbedtls_hardware_poll() in demo_entropy.c.
 * THAT FUNCTION IS DETERMINISTIC AND FOR THE EMULATOR ONLY. A real port must
 * read a TRNG here.
 */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

#endif /* SB_MBEDTLS_USER_CONFIG_H */

/* SPDX-License-Identifier: MIT */
/*
 * !!! DEMO ONLY !!!
 *
 * Entropy source for the emulated board. The QEMU machine has no hardware
 * random number generator, so this is a fixed-seed xorshift generator: its
 * output is completely predictable. Everything generated with it (ephemeral
 * ECDH keys, ECDSA nonces inside the library) is NOT secret.
 *
 * The self-test only VERIFIES signatures and DECRYPTS with a fixed test key,
 * so it needs entropy only to initialise the library and for blinding. A real
 * port must replace this with a TRNG driver.
 */
#include <stddef.h>
#include <stdint.h>

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    static uint32_t state = 0x2545F491u;
    (void)data;
    for (size_t i = 0; i < len; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        output[i] = (unsigned char)state;
    }
    *olen = len;
    return 0;
}

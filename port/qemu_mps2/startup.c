/* SPDX-License-Identifier: MIT */
/**
 * @file startup.c
 * Vector table, C runtime initialisation and heap for the QEMU self-test.
 * Console output and process exit go through ARM semihosting (newlib rdimon).
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack, _heap_start, _heap_end;
extern int main(void);
extern void initialise_monitor_handles(void);

/* ARM semihosting SYS_EXIT_EXTENDED (0x20): unlike newlib's _exit(), it carries a real
 * exit status, which QEMU hands back to the shell. */
static void semihost_exit(int status)
{
    static uint32_t block[2];
    register uint32_t op __asm__("r0") = 0x20u;
    register uint32_t arg __asm__("r1");
    block[0] = 0x20026u; /* ADP_Stopped_ApplicationExit */
    block[1] = (uint32_t)status;
    arg = (uint32_t)(uintptr_t)block;
    __asm__ volatile("bkpt 0xAB" : "+r"(op) : "r"(arg) : "memory");
    for (;;) {
    }
}

void Reset_Handler(void);
void *_sbrk(ptrdiff_t incr);
size_t startup_heap_peak(void);
static void Default_Handler(void);

/* Cortex-M3 system exception vectors (no external interrupts are used). */
#define VEC(f) ((uintptr_t)(f))
__attribute__((section(".isr_vector"), used)) static const uintptr_t vectors[16] = {
    VEC(&_estack), /* initial stack pointer */
    VEC(Reset_Handler),
    VEC(Default_Handler), /* NMI */
    VEC(Default_Handler), /* HardFault */
    VEC(Default_Handler), /* MemManage */
    VEC(Default_Handler), /* BusFault */
    VEC(Default_Handler), /* UsageFault */
    0, 0, 0, 0,
    VEC(Default_Handler), /* SVCall */
    VEC(Default_Handler), /* DebugMon */
    0,
    VEC(Default_Handler), /* PendSV */
    VEC(Default_Handler), /* SysTick */
};

void Reset_Handler(void)
{
    uint32_t *src = &_sidata;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }
    for (dst = &_sbss; dst < &_ebss;) {
        *dst++ = 0;
    }
    initialise_monitor_handles();
    setvbuf(stdout, NULL, _IONBF, 0);
    semihost_exit(main());
}

static void Default_Handler(void)
{
    puts("FAULT: unexpected exception");
    semihost_exit(2);
}

/* newlib heap: everything between .bss and the reserved stack. */
static char *g_brk;
static char *g_brk_max;

void *_sbrk(ptrdiff_t incr)
{
    char *prev;
    if (g_brk == NULL) {
        g_brk = (char *)&_heap_start;
        g_brk_max = g_brk;
    }
    if (incr > 0 && (size_t)incr > (size_t)((char *)&_heap_end - g_brk)) {
        errno = ENOMEM;
        return (void *)-1;
    }
    prev = g_brk;
    g_brk += incr;
    if (g_brk > g_brk_max) {
        g_brk_max = g_brk;
    }
    return prev;
}

/** Peak heap usage in bytes (for the size report). */
size_t startup_heap_peak(void)
{
    return g_brk_max == NULL ? 0u : (size_t)(g_brk_max - (char *)&_heap_start);
}

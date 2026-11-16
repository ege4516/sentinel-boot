/* Linker script for QEMU mps2-an385 (Cortex-M3).
 * Memory map taken from `info mtree` of the emulated machine:
 *   0x00000000  4 MiB  SSRAM1  (the Cortex-M3 boot alias; holds code and constants)
 *   0x20000000  4 MiB  SSRAM2/3 (data, heap, stack)
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
}

ENTRY(Reset_Handler)

_stack_size = 64K;
_estack     = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH

    .text :
    {
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > FLASH

    .ARM.exidx : { *(.ARM.exidx*) } > FLASH

    _sidata = LOADADDR(.data);

    .data :
    {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss (NOLOAD) :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        _ebss = .;
    } > RAM

    . = ALIGN(8);
    _heap_start = .;
    _heap_end   = _estack - _stack_size;
    PROVIDE(end = _heap_start); /* referenced by newlib's own (unused) _sbrk */

    /DISCARD/ : { *(.ARM.attributes*) }
}

ASSERT(_heap_start < _heap_end, "no room left for the heap")

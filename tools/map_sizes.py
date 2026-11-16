#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Attribute the linked size of a firmware ELF to its inputs using the GNU ld map file.

Usage: map_sizes.py <firmware.map>

Reports flash (code + read-only data, plus the initial values of .data) and
RAM (.data + .bss, excluding heap and stack) per input group. Only sections
that survived --gc-sections are counted.
"""
import re
import sys
from collections import defaultdict

SECTION = re.compile(r"^ (\.[\w.$]+)\s*(0x[0-9a-f]+)?\s*(0x[0-9a-f]+)?\s*(.*)$")
CONT = re.compile(r"^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.*)$")

GROUPS = [
    ("sentinel-boot core (boot/)", re.compile(r"libsb_boot\.a")),
    ("simulated HAL", re.compile(r"libsb_hal_sim_core\.a")),
    ("Mbed TLS crypto (mbedcrypto + 3rdparty)", re.compile(r"libmbedcrypto\.a|libeverest\.a|libp256m\.a")),
    ("newlib / libgcc / semihosting", re.compile(r"libc\.a|libgcc\.a|librdimon\.a|libm\.a|libg\.a|crt0")),
    ("self-test harness + startup", re.compile(r"CMakeFiles/sb_selftest")),
]


def classify(path):
    for name, rx in GROUPS:
        if rx.search(path):
            return name
    return "other"


def main():
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    text = text.split("Linker script and memory map", 1)[1]
    lines = text.splitlines()

    flash = defaultdict(int)
    ram = defaultdict(int)
    i = 0
    while i < len(lines):
        m = SECTION.match(lines[i])
        if not m or lines[i].startswith(" *"):
            i += 1
            continue
        name, addr, size, rest = m.groups()
        if addr is None:  # long section name: details on the next line
            i += 1
            if i >= len(lines):
                break
            c = CONT.match(lines[i])
            if not c:
                continue
            addr, size, rest = c.groups()
        i += 1
        if size is None or int(size, 16) == 0 or not rest.strip():
            continue
        n = int(size, 16)
        group = classify(rest.strip())
        if name.startswith((".text", ".rodata", ".ARM", ".isr_vector")):
            flash[group] += n
        elif name.startswith(".data"):
            flash[group] += n
            ram[group] += n
        elif name.startswith((".bss", "COMMON")):
            ram[group] += n

    print("%-44s %10s %10s" % ("input group", "flash (B)", "RAM (B)"))
    for name in sorted(set(flash) | set(ram)):
        print("%-44s %10d %10d" % (name, flash[name], ram[name]))
    print("%-44s %10d %10d" % ("total", sum(flash.values()), sum(ram.values())))


if __name__ == "__main__":
    main()

# sentinel-boot

Secure boot and encrypted OTA update chain for Cortex-M class devices, written in C11.
Signed and encrypted firmware packages, A/B slots with trial boots, power-fail-safe
state handling and hardware-backed (simulated) anti-rollback, with a test suite
that attacks it.

> Educational reference implementation, **not production-ready**. It runs on a host simulator
> and, as a self-test, on an emulated Cortex-M3 (QEMU); there is no real-hardware port.
> See [Limitations](#limitations-and-non-goals).

## What it does

```
 vendor (offline)                         device
┌───────────────────┐   package     ┌────────────────────────────────────────────┐
│ sentinel_sign.py  │──────────────▶│ app: stage package into the inactive slot  │
│  ECDH(eph, dev)   │ manifest(248B)│        (not trusted to verify anything)    │
│  HKDF → AES key   │  + ciphertext └──────────────────┬─────────────────────────┘
│  AES-256-GCM      │                                  │ reset
│  ECDSA P-256 sign │               ┌──────────────────▼─────────────────────────┐
└───────────────────┘               │ bootloader (sb_boot)                       │
                                    │  1 root key hash == OTP anchor             │
                                    │  2 signature, key id                       │
                                    │  3 security counter >= OTP counter         │
                                    │  4 SHA-256(ciphertext) == manifest         │
                                    │  5 ECDH → HKDF → decrypt in place + tag    │
                                    │  6 SHA-256(plaintext) == manifest          │
                                    │  7 trial boot ─ confirm ─ raise OTP counter│
                                    └────────────────────────────────────────────┘
```

Nothing is decrypted before the signature and the ciphertext digest check out. Signature,
counter and plaintext digest are re-verified on every boot.

| Purpose            | Primitive                                   | Library (PSA API) |
|--------------------|---------------------------------------------|-------------------|
| Manifest signature | ECDSA P-256 / SHA-256, raw `r‖s`            | Mbed TLS 3.6.8    |
| Image key          | ephemeral ECDH P-256 → HKDF-SHA256          | Mbed TLS 3.6.8    |
| Image encryption   | AES-256-GCM, header bound as AAD            | Mbed TLS 3.6.8    |
| Integrity          | SHA-256, constant-time compares             | Mbed TLS 3.6.8    |

Byte-level format: [docs/image-format.md](docs/image-format.md).
Threat model: [docs/threat-model.md](docs/threat-model.md).

## Demo

```
$ examples/demo.sh
== ATTACK 1: one flipped bit in a validly signed package
[boot] staged update REJECTED: digest mismatch
[boot] OK slot 0, version 2.0.0, security counter 2, 90000 bytes
== ATTACK 2: replay of the genuine, signed 1.0.0 (rollback)
[boot] staged update REJECTED: rollback rejected
== ATTACK 3: firmware signed by an attacker's key
[boot] staged update REJECTED: untrusted or invalid key
== ATTACK 4: package encrypted for a different device
[boot] staged update REJECTED: authentication tag rejected
== Final state: still running genuine 2.0.0
running image is byte-identical to the signed 2.0.0 firmware
```

## Build and run

Needs Linux or WSL2 (Ubuntu 22.04 tested), CMake ≥ 3.22, Ninja, GCC, Clang and
Python 3 with `cryptography`. Dependencies (Mbed TLS, GoogleTest) are fetched at
pinned versions with SHA-256 verification.

```sh
sudo apt-get install build-essential cmake ninja-build clang python3-pip
python3 -m pip install cryptography

cmake --preset host-asan && cmake --build --preset host-asan && ctest --preset host-asan
examples/demo.sh ~/sb-build/host-asan/sentinel-sim
```

Other presets: `host-debug` (GCC), `host-fuzz` (libFuzzer, needs `libfuzzer-14-dev`),
`host-coverage`. Build trees go to `~/sb-build/<preset>`.

```sh
# fuzz the manifest parser and the whole update path
cmake --preset host-fuzz && cmake --build --preset host-fuzz
~/sb-build/host-fuzz/tests/fuzz/fuzz_manifest -max_total_time=60 -max_len=400  /tmp/c1 tests/fuzz/corpus/manifest
~/sb-build/host-fuzz/tests/fuzz/fuzz_update   -max_total_time=60 -max_len=6000 /tmp/c2 tests/fuzz/corpus/update

# do the tests notice when a security check is removed?
python3 tools/mutation_check.py
```

Cortex-M3 self-test under QEMU (`qemu-system-arm` ≥ 6.2, `gcc-arm-none-eabi`, `libnewlib-arm-none-eabi`):

```sh
sudo apt-get install qemu-system-arm gcc-arm-none-eabi libnewlib-arm-none-eabi
cmake --preset qemu-mps2 && cmake --build --preset qemu-mps2 && ctest --preset qemu-mps2
python3 tools/map_sizes.py ~/sb-build/qemu-mps2/port/qemu_mps2/sb_selftest.map   # size report
```

The firmware uses the machine's memory map as printed by QEMU (`info mtree`): code in the
4 MiB SSRAM1 boot alias at `0x0`, data, heap and a 64 KiB stack in SSRAM2/3 at `0x20000000`.
Console output and the exit status go through ARM semihosting. Test packages are generated
at build time with fresh test keys that never leave the build directory.

## Verification

Measured on this repository (WSL2, Ubuntu 22.04, clang 14 / GCC 11):

| Check | Result |
|-------|--------|
| Unit and integration tests | 74 / 74 pass, also under ASan + UBSan |
| Known-answer tests | 769 [Wycheproof](https://github.com/C2SP/wycheproof) vectors (ECDSA P-256, ECDH P-256, HKDF-SHA256, AES-256-GCM); encodings the format cannot represent are skipped and counted |
| Manifest corruption | every single-bit flip of the 248-byte manifest is rejected |
| Power loss | power cut injected at each of 43 flash operations of an update life cycle (plus trial-expiry and first-install sweeps); the device always boots a signed image, the OTP counter never exceeds it, and it stays updatable |
| Cross-implementation | packages from the Python signer (OpenSSL) install on the C bootloader (Mbed TLS) byte-for-byte |
| Mutation check | 19 / 19 deliberately removed security checks are caught by the tests |
| Fuzzing | 5 min each, no findings: parser 132,733 runs, full update path 8,239 runs (invariant: the device only ever boots an image the vendor signed) |
| Valgrind | 0 errors, 0 leaks on the end-to-end scenarios |
| Static analysis | clang-tidy (`bugprone`, `cert`, `clang-analyzer`, `performance`) clean on `boot/`, `hal/`, `tools/sim/` |
| On target (Cortex-M3, QEMU `mps2-an385`) | The unmodified `boot/` core, cross-compiled with `arm-none-eabi-gcc` and run under QEMU against the real Mbed TLS: install, OTA update, three attacks and a power cut at each of 22 flash operations, 117 checks, 0 failed (`ctest --preset qemu-mps2`, ~1 s). Removing the rollback check makes it fail with exit status 1 |
| Linked size (`-Os`, Cortex-M3) | `boot/` core 4.9 KB flash; Mbed TLS 128 KB; newlib + semihosting 35 KB; whole self-test ELF 189 KB flash, 108 KB RAM (mostly the self-test's own flash model and buffers). Peak heap 18.9 KB, all of it the crypto library's. `sb_ctx_t` holds two 4 KiB sector buffers |
| Coverage | 90.1 % lines, 73.7 % branches of `boot/` + `hal/` (remaining branches are mostly defensive error paths) |

The fuzzing runs are short; they show the harness works, not that the code is exhaustively
fuzzed. CI (`.github/workflows/ci.yml`) is configured to repeat the build, tests, Valgrind,
clang-tidy and a 60 s fuzz run on every push; it has not run yet, so there is no badge.

## Layout

```
boot/    bootloader core (platform independent; its own code never allocates)
           crypto_port  PSA wrappers: the only file that touches the crypto library
           manifest     parser and signature verification
           state        CRC-protected boot state, two alternating copies
           update       staging API, verified in-place installation
           boot         reset-time policy: install, trial, revert, recover
hal/     flash model with power-loss injection, OTP model, HAL interface
port/    qemu_mps2/: Cortex-M3 startup, linker script, Mbed TLS bare-metal config, self-test
cmake/   arm-none-eabi toolchain file
tools/   sentinel_sign.py (signer), sim/ (CLI device), mutation_check.py,
         gen_fixture.py (QEMU test packages), map_sizes.py (size report)
tests/   unit, power-fail, fuzz, interop, Wycheproof vectors
docs/    image format, threat model
```

Porting means implementing `hal/sb_hal.h` (a flash and an OTP device) and, if the
crypto library changes, `boot/crypto_port.c`.

## Limitations and non-goals

- OTP and key storage are **simulated** in RAM. A real device needs fuses or a secure element.
- **No side-channel or fault-injection resistance.** Constant-time code is best effort in C.
- Verified-then-executed images are not protected against a flash rewrite in between (TOCTOU).
- One root key, no rotation or revocation. Static device key, so no forward secrecy toward the device.
- An interrupted install is abandoned, not resumed; the package must be downloaded again.
- Emulator only: the Cortex-M3 build runs in QEMU, not on silicon. Flash and OTP are RAM models, so there is no real flash driver, timing or wear behaviour, and no application is chain-loaded.
- The emulated board has no RNG: `port/qemu_mps2/demo_entropy.c` is a fixed-seed generator and its output is predictable. It is acceptable only because the self-test merely verifies and decrypts with fixed test keys; a real port needs a TRNG.
- The crypto library allocates from the heap (18.9 KB peak on target); only the core's own code is allocation-free.
- Not audited, not certified, not for production.

## License

MIT. Wycheproof test vectors (`tests/vectors/`) are derived from Project Wycheproof, Apache-2.0.

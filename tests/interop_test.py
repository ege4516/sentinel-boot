#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-implementation test: Python signer -> C bootloader.

Packages are produced by tools/sentinel_sign.py (pyca/cryptography, OpenSSL)
and consumed by the bootloader core (Mbed TLS PSA) through the sentinel-sim
CLI. Agreement between two unrelated crypto stacks is what pins down the wire
format: signature encoding, point encoding, the ECDH output convention, the
HKDF inputs and the placement of the GCM tag.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FAILURES = []


def check(cond, what):
    print("  [%s] %s" % ("ok" if cond else "FAIL", what))
    if not cond:
        FAILURES.append(what)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sim", required=True)
    ap.add_argument("--signer", required=True)
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="sb-interop-"))
    keys, dev = work / "keys", work / "device"
    dev.mkdir()

    def signer(*a):
        subprocess.run([sys.executable, args.signer, *map(str, a)], check=True,
                       stdout=subprocess.DEVNULL)

    def sim(*a):
        p = subprocess.run([args.sim, str(dev), *map(str, a)], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
        return p.returncode, p.stdout

    def sign(image, version, counter, out, device_pub=None):
        signer("sign", "--root-key", keys / "root_private.pem",
               "--device-pub", device_pub or keys / "device_public.bin",
               "--image", image, "--version", version, "--security-counter", counter,
               "--out", out)

    def running_image():
        rc, _ = sim("dump", work / "dump.bin")
        return (work / "dump.bin").read_bytes() if rc == 0 else None

    signer("keygen", keys)
    fw1, fw2 = os.urandom(50001), os.urandom(123456)
    (work / "fw1.bin").write_bytes(fw1)
    (work / "fw2.bin").write_bytes(fw2)
    sign(work / "fw1.bin", "1.0.0", 1, work / "v1.pkg")
    sign(work / "fw2.bin", "2.1.7", 2, work / "v2.pkg")

    print("provision + first install")
    rc, _ = sim("provision", keys / "root_public.bin", keys / "device_private.bin")
    check(rc == 0, "provision")
    rc, _ = sim("boot")
    check(rc == 2, "blank device reports no image")
    check(sim("stage", work / "v1.pkg")[0] == 0, "stage v1")
    rc, out = sim("boot")
    check(rc == 0 and "installed" in out and "version 1.0.0" in out, "boot installs v1")
    check(sim("confirm")[0] == 0, "confirm v1")
    check(running_image() == fw1, "decrypted v1 is byte-identical to the signer's input")

    print("update to v2")
    check(sim("stage", work / "v2.pkg")[0] == 0, "stage v2")
    rc, out = sim("boot")
    check(rc == 0 and "installed" in out and "version 2.1.7" in out, "boot installs v2")
    check(sim("confirm")[0] == 0, "confirm v2")
    check(running_image() == fw2, "decrypted v2 is byte-identical to the signer's input")

    print("tampered package")
    bad = bytearray((work / "v2.pkg").read_bytes())
    bad[len(bad) // 2] ^= 0x01
    (work / "tampered.pkg").write_bytes(bad)
    check(sim("stage", work / "tampered.pkg")[0] == 0, "stage tampered")
    rc, out = sim("boot")
    check(rc == 0 and "REJECTED: digest mismatch" in out, "tampered ciphertext rejected")
    check(running_image() == fw2, "device still runs v2")

    print("rollback")
    check(sim("stage", work / "v1.pkg")[0] == 0, "stage genuine old v1")
    rc, out = sim("boot")
    check(rc == 0 and "REJECTED: rollback rejected" in out, "old release rejected")
    check(running_image() == fw2, "device still runs v2")

    print("package for another device")
    signer("keygen", work / "other")
    sign(work / "fw1.bin", "3.0.0", 3, work / "other.pkg",
         device_pub=work / "other" / "device_public.bin")
    check(sim("stage", work / "other.pkg")[0] == 0, "stage foreign package")
    rc, out = sim("boot")
    check(rc == 0 and "REJECTED: authentication tag rejected" in out,
          "package wrapped for another device rejected")
    check(running_image() == fw2, "device still runs v2")

    if FAILURES:
        print("\n%d check(s) failed; work dir kept at %s" % (len(FAILURES), work))
        return 1
    print("\nall interop checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

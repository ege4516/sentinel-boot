#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Do the tests actually notice when a security check is removed?

Each mutation below deletes or weakens exactly one defence in the bootloader.
The script applies it, rebuilds, runs the test suite and expects at least one
test to fail ("killed"). A mutation that survives means the corresponding
check is not really covered, whatever line coverage says.

Usage (from the repo root, inside the build environment):
    python3 tools/mutation_check.py [--preset host-debug]

The working tree is restored after every mutation, including on Ctrl-C.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (name, file, original text, replacement)
MUTATIONS = [
    ("skip anti-rollback check", "boot/verify.c",
     "if (mf->security_counter < counter) {", "if (0) {"),
    ("skip OTP trust-anchor check on the root key", "boot/manifest.c",
     "if (!sb_ct_memeq(digest, root_pub_hash, SB_SHA256_LEN)) {", "if (0) {"),
    ("skip key-id check", "boot/manifest.c",
     "if (!sb_ct_memeq(digest, mf->key_id, SB_KEY_ID_LEN)) {", "if (0) {"),
    ("accept any signature", "boot/manifest.c",
     "return sb_ecdsa_p256_verify(root_pub, digest, mf->signature);",
     "(void)sb_ecdsa_p256_verify(root_pub, digest, mf->signature); return SB_OK;"),
    ("skip ciphertext digest check before decrypting", "boot/update.c",
     "if (!sb_ct_memeq(digest, mf.ct_digest, SB_SHA256_LEN)) {", "if (0) {"),
    ("skip plaintext digest check after decrypting", "boot/update.c",
     "if (!sb_ct_memeq(digest, mf.pt_digest, SB_SHA256_LEN)) {", "if (0) {"),
    ("skip plaintext digest check on every boot", "boot/verify.c",
     "return sb_ct_memeq(digest, mf->pt_digest, SB_SHA256_LEN) ? SB_OK : SB_ERR_DIGEST;",
     "return SB_OK;"),
    ("ignore the GCM tag", "boot/crypto_port.c",
     "if (st == PSA_ERROR_INVALID_SIGNATURE) {\n        return SB_ERR_AUTH;",
     "if (st == PSA_ERROR_INVALID_SIGNATURE) {\n        return SB_OK;"),
    ("drop the AAD binding", "boot/update.c",
     "sb_gcm_decrypt_begin(&gcm, key, mf->nonce, raw, SB_MANIFEST_AAD_LEN);",
     "sb_gcm_decrypt_begin(&gcm, key, mf->nonce, raw, 0);"),
    ("drop the image size upper bound", "boot/manifest.c",
     "if (out->image_size == 0 || out->image_size > max_image_size) {",
     "if (out->image_size == 0 || out->image_size > max_image_size + 1u) {"),
    ("accept unknown manifest flags", "boot/manifest.c",
     "if (out->format != SB_MANIFEST_FORMAT || out->flags != 0) {",
     "if (out->format != SB_MANIFEST_FORMAT) {"),
    ("constant-time compare always says equal", "boot/crypto_port.c",
     "return (int)(1u & (((uint32_t)diff - 1u) >> 8));", "(void)diff; return 1;"),
    ("never burn a trial", "boot/boot.c",
     "st.trials_left--;", "(void)st.trials_left;"),
    ("rewrite the newest state copy in place (not power-fail safe)", "boot/state.c",
     "target = (uint8_t)(st->copy ^ 1u);", "target = st->copy;"),
    ("program flash without erasing first", "boot/update.c",
     "if (ctx->flash->erase(ctx->flash->dev, base + done) != 0 ||\n            ctx->flash->write",
     "if (ctx->flash->write"),
    ("allow overwriting the fallback while on trial", "boot/update.c",
     "if (st.slot[st.active] == SB_SLOT_TRIAL) {\n        return SB_ERR_STATE;",
     "if (0) {\n        return SB_ERR_STATE;"),
    ("burn the counter before the image is confirmed", "boot/boot.c",
     "if (st.slot[s] == SB_SLOT_CONFIRMED &&\n                    result->manifest.security_counter > counter) {",
     "if (result->manifest.security_counter > counter) {"),
    ("accept a non-CONFIRMED slot as fallback", "boot/boot.c",
     "fallback = (attempt == 0 && st.slot[other] == SB_SLOT_CONFIRMED);",
     "fallback = (attempt == 0);"),
    ("skip CRC check on the boot state record", "boot/state.c",
     "if (rd_le32(rec) != STATE_MAGIC || rd_le32(rec + 12) != crc32(rec, 12)) {",
     "if (rd_le32(rec) != STATE_MAGIC) {"),
]


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", default="host-debug")
    args = ap.parse_args()

    if run(["cmake", "--preset", args.preset]).returncode != 0:
        sys.exit("configure failed")

    survived = []
    for name, rel, old, new in MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            sys.exit("mutation '%s': pattern must occur exactly once in %s (found %d)" %
                     (name, rel, text.count(old)))
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            build = run(["cmake", "--build", "--preset", args.preset])
            if build.returncode != 0:
                verdict = "killed (does not compile)"
            else:
                test = run(["ctest", "--preset", args.preset, "-j", "8"])
                if test.returncode != 0:
                    failed = [l for l in test.stdout.splitlines() if "tests failed" in l]
                    verdict = "killed (%s)" % (failed[0].strip() if failed else "tests failed")
                else:
                    verdict = "SURVIVED"
                    survived.append(name)
        finally:
            path.write_bytes(original)
        print("%-62s %s" % (name, verdict), flush=True)

    run(["cmake", "--build", "--preset", args.preset])  # leave a clean build behind
    print("\n%d/%d mutations killed" % (len(MUTATIONS) - len(survived), len(MUTATIONS)))
    for name in survived:
        print("  survived: " + name)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())

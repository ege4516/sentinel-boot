#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""sentinel-boot signing tool.

Builds an update package (signed manifest, transparency-log proof block, then
the encrypted image) for the sentinel-boot bootloader. This is an independent
implementation of the format in docs/image-format.md, built on the
`cryptography` package rather than on the Mbed TLS code the bootloader uses.

  sentinel_sign.py keygen    <out-dir>
  sentinel_sign.py sign      --root-key K --log-key L --log-dir D --device-pub P
                             --image I --version X.Y.Z --security-counter N --out PKG
  sentinel_sign.py inspect   <package>
  sentinel_sign.py log-audit --log-dir D --log-pub L.bin

Two keys with two roles: the root key signs firmware, the log key belongs to
the log operator and signs tree heads. The bootloader trusts both through
separate hash anchors in OTP. Both private keys are kept in unencrypted PEM
files here for demonstration only; a real release process would keep them in
separate HSMs under separate control.
"""
import argparse
import hashlib
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

import sentinel_log  # noqa: E402

MAGIC = 0x314D4253  # "SBM1"
FORMAT = 2
SIGNED_LEN = 184
MANIFEST_LEN = 248
PROOF_LEN = sentinel_log.PROOF_LEN
HEADER_LEN = MANIFEST_LEN + PROOF_LEN
AAD_LEN = 24
KDF_LABEL = b"sentinel-boot/v1/image-key"

# magic, format, flags, fw_version, security_counter, image_size, key_id
HEADER = struct.Struct("<IHHIII4s")
assert HEADER.size == AAD_LEN


def pub_bytes(public_key):
    """Uncompressed SEC1 point: 0x04 || X || Y (65 bytes)."""
    return public_key.public_bytes(serialization.Encoding.X962,
                                   serialization.PublicFormat.UncompressedPoint)


def parse_version(text):
    parts = text.split(".")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("version must be MAJOR.MINOR.PATCH")
    major, minor, patch = (int(p) for p in parts)
    if not (0 <= major <= 255 and 0 <= minor <= 255 and 0 <= patch <= 65535):
        raise argparse.ArgumentTypeError("version component out of range")
    return (major << 24) | (minor << 16) | patch


def format_version(v):
    return "%d.%d.%d" % (v >> 24, (v >> 16) & 0xFF, v & 0xFFFF)


def build_package(root_key, device_pub, image, fw_version, security_counter,
                  log=None, log_key=None, proof_override=None):
    """Return manifest || proof block || ciphertext.

    Normally the release is appended to `log` and the proof comes from the new
    tree head. `proof_override` supplies a ready-made proof block instead and
    skips logging; it exists to demonstrate that such a package is rejected.
    """
    if not image:
        raise ValueError("image is empty")

    root_pub = pub_bytes(root_key.public_key())
    key_id = hashlib.sha256(root_pub).digest()[:4]
    header = HEADER.pack(MAGIC, FORMAT, 0, fw_version, security_counter, len(image), key_id)

    # A fresh ephemeral key per package gives a fresh AES key per package, so
    # the (key, nonce) pair can never repeat.
    device_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_pub)
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_pub = pub_bytes(eph.public_key())
    shared = eph.exchange(ec.ECDH(), device_key)  # raw X coordinate
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=KDF_LABEL + eph_pub).derive(shared)

    nonce = os.urandom(12)
    sealed = AESGCM(aes_key).encrypt(nonce, image, header)  # ciphertext || tag
    ciphertext, tag = sealed[:-16], sealed[-16:]

    signed = (header + eph_pub + nonce + tag + hashlib.sha256(ciphertext).digest() +
              hashlib.sha256(image).digest() + b"\x00" * 3)
    assert len(signed) == SIGNED_LEN

    # The bootloader expects raw r || s, not the DER structure produced here.
    der = root_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    manifest = signed + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert len(manifest) == MANIFEST_LEN

    if proof_override is not None:
        proof = proof_override
    else:
        # The log leaf is the signed region of the manifest.
        proof = log.append(signed, fw_version, security_counter, log_key)
    assert len(proof) == PROOF_LEN
    return manifest + proof + ciphertext


def load_priv(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def write_keypair(out, name, key):
    (out / (name + "_private.pem")).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (out / (name + "_public.bin")).write_bytes(pub_bytes(key.public_key()))


def cmd_keygen(args):
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    root = ec.generate_private_key(ec.SECP256R1())
    log = ec.generate_private_key(ec.SECP256R1())
    write_keypair(out, "root", root)
    write_keypair(out, "log", log)

    device = ec.generate_private_key(ec.SECP256R1())
    (out / "device_private.bin").write_bytes(
        device.private_numbers().private_value.to_bytes(32, "big"))
    (out / "device_public.bin").write_bytes(pub_bytes(device.public_key()))

    print("wrote root, log and device keys to %s" % out)
    print("root key hash (OTP anchor): %s" %
          hashlib.sha256(pub_bytes(root.public_key())).hexdigest())
    print("log key hash  (OTP anchor): %s" %
          hashlib.sha256(pub_bytes(log.public_key())).hexdigest())


def cmd_sign(args):
    root_key = load_priv(args.root_key)
    device_pub = Path(args.device_pub).read_bytes()
    image = Path(args.image).read_bytes()

    if args.reuse_proof_from:
        # Attack demonstration: a package signed with the root key but never
        # logged, carrying a proof block copied from another release.
        proof = Path(args.reuse_proof_from).read_bytes()[MANIFEST_LEN:HEADER_LEN]
        pkg = build_package(root_key, device_pub, image, args.version, args.security_counter,
                            proof_override=proof)
        logged = "NOT logged (proof copied)"
    else:
        if not (args.log_key and args.log_dir):
            sys.exit("--log-key and --log-dir are required (or --reuse-proof-from for the demo)")
        pkg = build_package(root_key, device_pub, image, args.version, args.security_counter,
                            log=sentinel_log.Log(args.log_dir), log_key=load_priv(args.log_key))
        logged = "logged"
    Path(args.out).write_bytes(pkg)
    print("wrote %s: version %s, security counter %d, image %d bytes, package %d bytes, %s" %
          (args.out, format_version(args.version), args.security_counter, len(image),
           len(pkg), logged))


def cmd_inspect(args):
    pkg = Path(args.package).read_bytes()
    if len(pkg) < HEADER_LEN:
        sys.exit("package shorter than manifest + proof block")
    magic, fmt, flags, version, counter, size, key_id = HEADER.unpack_from(pkg, 0)
    print("magic            0x%08x%s" % (magic, "" if magic == MAGIC else "  (BAD)"))
    print("format / flags   %d / %d" % (fmt, flags))
    print("fw version       %s" % format_version(version))
    print("security counter %d" % counter)
    print("image size       %d (package carries %d)" % (size, len(pkg) - HEADER_LEN))
    print("key id           %s" % key_id.hex())
    print("eph public key   %s" % pkg[24:89].hex())
    print("gcm nonce        %s" % pkg[89:101].hex())
    print("gcm tag          %s" % pkg[101:117].hex())
    print("ct sha256        %s" % pkg[117:149].hex())
    print("pt sha256        %s" % pkg[149:181].hex())
    print("signature (r||s) %s" % pkg[184:248].hex())
    index, tree_size, path_len = struct.unpack_from("<IIB", pkg, MANIFEST_LEN)
    print("log leaf index   %d of tree size %d (proof length %d)" % (index, tree_size, path_len))
    print("log root         %s" % pkg[MANIFEST_LEN + 12:MANIFEST_LEN + 44].hex())


def cmd_log_audit(args):
    log_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), Path(args.log_pub).read_bytes())
    report, ok = sentinel_log.Log(args.log_dir).audit(log_pub)
    print(report)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate demo root, log and device keys")
    p.add_argument("out_dir")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("sign", help="encrypt, sign and log a firmware image")
    p.add_argument("--root-key", required=True, help="firmware root private key (PEM)")
    p.add_argument("--log-key", help="transparency-log private key (PEM)")
    p.add_argument("--log-dir", help="log directory (created on first use)")
    p.add_argument("--device-pub", required=True, help="device public key (65 bytes)")
    p.add_argument("--image", required=True, help="plaintext firmware image")
    p.add_argument("--version", required=True, type=parse_version, help="MAJOR.MINOR.PATCH")
    p.add_argument("--security-counter", required=True, type=int)
    p.add_argument("--out", required=True)
    p.add_argument("--reuse-proof-from", metavar="PKG",
                   help="attack demo: skip logging, copy the proof block from another package")
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("inspect", help="print the manifest and proof of a package")
    p.add_argument("package")
    p.set_defaults(fn=cmd_inspect)

    p = sub.add_parser("log-audit", help="list a log and verify its signed tree head")
    p.add_argument("--log-dir", required=True)
    p.add_argument("--log-pub", required=True, help="log public key (65 bytes)")
    p.set_defaults(fn=cmd_log_audit)

    args = ap.parse_args()
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()

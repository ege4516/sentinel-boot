#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""sentinel-boot signing tool.

Builds an update package (signed manifest followed by the encrypted image) for
the sentinel-boot bootloader. This is an independent implementation of the
format in docs/image-format.md, built on the `cryptography` package rather
than on the Mbed TLS code the bootloader uses.

  sentinel_sign.py keygen  <out-dir>
  sentinel_sign.py sign    --root-key K --device-pub P --image I
                           --version X.Y.Z --security-counter N --out PKG
  sentinel_sign.py inspect <package>

The root private key is the crown jewel of this scheme. This tool keeps it in
an unencrypted PEM file for demonstration only; a real release process would
keep it in an HSM and never on a build machine.
"""
import argparse
import hashlib
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = 0x314D4253  # "SBM1"
FORMAT = 1
SIGNED_LEN = 184
MANIFEST_LEN = 248
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


def build_package(root_key, device_pub, image, fw_version, security_counter):
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
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    manifest = signed + signature
    assert len(manifest) == MANIFEST_LEN
    return manifest + ciphertext


def cmd_keygen(args):
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    root = ec.generate_private_key(ec.SECP256R1())
    (out / "root_private.pem").write_bytes(root.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (out / "root_public.bin").write_bytes(pub_bytes(root.public_key()))

    device = ec.generate_private_key(ec.SECP256R1())
    (out / "device_private.bin").write_bytes(
        device.private_numbers().private_value.to_bytes(32, "big"))
    (out / "device_public.bin").write_bytes(pub_bytes(device.public_key()))

    print("wrote root_private.pem, root_public.bin, device_private.bin, "
          "device_public.bin to %s" % out)
    print("root key hash (OTP anchor): %s" %
          hashlib.sha256(pub_bytes(root.public_key())).hexdigest())


def cmd_sign(args):
    root_key = serialization.load_pem_private_key(Path(args.root_key).read_bytes(),
                                                  password=None)
    device_pub = Path(args.device_pub).read_bytes()
    image = Path(args.image).read_bytes()
    pkg = build_package(root_key, device_pub, image, args.version, args.security_counter)
    Path(args.out).write_bytes(pkg)
    print("wrote %s: version %s, security counter %d, image %d bytes, package %d bytes" %
          (args.out, format_version(args.version), args.security_counter, len(image),
           len(pkg)))


def cmd_inspect(args):
    pkg = Path(args.package).read_bytes()
    if len(pkg) < MANIFEST_LEN:
        sys.exit("package shorter than a manifest")
    magic, fmt, flags, version, counter, size, key_id = HEADER.unpack_from(pkg, 0)
    print("magic            0x%08x%s" % (magic, "" if magic == MAGIC else "  (BAD)"))
    print("format / flags   %d / %d" % (fmt, flags))
    print("fw version       %s" % format_version(version))
    print("security counter %d" % counter)
    print("image size       %d (package carries %d)" % (size, len(pkg) - MANIFEST_LEN))
    print("key id           %s" % key_id.hex())
    print("eph public key   %s" % pkg[24:89].hex())
    print("gcm nonce        %s" % pkg[89:101].hex())
    print("gcm tag          %s" % pkg[101:117].hex())
    print("ct sha256        %s" % pkg[117:149].hex())
    print("pt sha256        %s" % pkg[149:181].hex())
    print("signature (r||s) %s" % pkg[184:248].hex())


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate demo root and device keys")
    p.add_argument("out_dir")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("sign", help="encrypt and sign a firmware image")
    p.add_argument("--root-key", required=True, help="root private key (PEM)")
    p.add_argument("--device-pub", required=True, help="device public key (65 bytes)")
    p.add_argument("--image", required=True, help="plaintext firmware image")
    p.add_argument("--version", required=True, type=parse_version, help="MAJOR.MINOR.PATCH")
    p.add_argument("--security-counter", required=True, type=int)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("inspect", help="print the manifest of a package")
    p.add_argument("package")
    p.set_defaults(fn=cmd_inspect)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

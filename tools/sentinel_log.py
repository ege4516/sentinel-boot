#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Append-only Merkle transparency log for sentinel-boot releases.

Follows RFC 9162 section 2.1 with SHA-256. The tree is built straight from the
recursive *definition* (MTH, PATH) rather than from the iterative stack
algorithm, so it is an independent check on the C verifier in boot/merkle.c.

The log operator holds a key that is separate from the firmware root key. It
signs a tree head (tree size and root hash) every time a release is appended.
Packages carry the tree head signature and an inclusion proof for their own
manifest. This is a Merkle transparency log, not a blockchain.

Log directory layout:
  log.json   {"entries": [{"data": hex, "fw_version": n, "security_counter": n}, ...]}
  head.json  latest signed tree head {"tree_size", "root", "signature"}
"""
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                            encode_dss_signature)

TREE_HEAD_LABEL = b"sentinel-boot/v1/tree-head"
MAX_DEPTH = 8
PROOF_LEN = 108 + MAX_DEPTH * 32  # must match SB_PROOF_LEN in boot/merkle.h


def sha256(data):
    return hashlib.sha256(data).digest()


def leaf_hash(data):
    return sha256(b"\x00" + data)


def node_hash(left, right):
    return sha256(b"\x01" + left + right)


def _split(n):
    """Largest power of two strictly smaller than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(entries):
    """Merkle Tree Hash of a list of leaf data, straight from RFC 9162 2.1.1."""
    n = len(entries)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaf_hash(entries[0])
    k = _split(n)
    return node_hash(mth(entries[:k]), mth(entries[k:]))


def path(m, entries):
    """Inclusion proof PATH(m, D_n) from RFC 9162 2.1.3.1."""
    n = len(entries)
    if not 0 <= m < n:
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return path(m, entries[:k]) + [mth(entries[k:])]
    return path(m - k, entries[k:]) + [mth(entries[:k])]


def tree_head_tbs(tree_size, root):
    return TREE_HEAD_LABEL + struct.pack("<I", tree_size) + root


def sign_head(log_key, tree_size, root):
    """Raw r||s ECDSA P-256 signature over SHA-256(tree head)."""
    der = log_key.sign(tree_head_tbs(tree_size, root), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_head(log_pub_key, tree_size, root, signature):
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                               int.from_bytes(signature[32:], "big"))
    log_pub_key.verify(der, tree_head_tbs(tree_size, root), ec.ECDSA(hashes.SHA256()))


def proof_block(index, entries, log_key):
    """Serialise the proof block for entries[index] against the tree of all entries."""
    size = len(entries)
    p = path(index, entries)
    if len(p) > MAX_DEPTH:
        raise ValueError("log has outgrown the %d-hash proof limit" % MAX_DEPTH)
    root = mth(entries)
    block = struct.pack("<IIB3x", index, size, len(p))
    block += root + sign_head(log_key, size, root)
    block += b"".join(p) + b"\x00" * (32 * (MAX_DEPTH - len(p)))
    assert len(block) == PROOF_LEN
    return block


class Log:
    """A log directory on disk."""

    def __init__(self, directory):
        self.dir = Path(directory)
        self.entries = []   # leaf data (bytes)
        self.meta = []      # human-readable annotations
        f = self.dir / "log.json"
        if f.exists():
            for e in json.loads(f.read_text(encoding="utf-8"))["entries"]:
                self.entries.append(bytes.fromhex(e["data"]))
                self.meta.append({"fw_version": e["fw_version"],
                                  "security_counter": e["security_counter"]})

    def append(self, data, fw_version, security_counter, log_key):
        """Record a release and return its proof block (against the new tree head)."""
        self.entries.append(data)
        self.meta.append({"fw_version": fw_version, "security_counter": security_counter})
        index = len(self.entries) - 1
        block = proof_block(index, self.entries, log_key)
        self.save(log_key)
        return block

    def save(self, log_key):
        self.dir.mkdir(parents=True, exist_ok=True)
        entries = [{"data": d.hex(), **m} for d, m in zip(self.entries, self.meta)]
        (self.dir / "log.json").write_text(json.dumps({"entries": entries}, indent=1),
                                           encoding="utf-8", newline="\n")
        root = mth(self.entries)
        head = {"tree_size": len(self.entries), "root": root.hex(),
                "signature": sign_head(log_key, len(self.entries), root).hex()}
        (self.dir / "head.json").write_text(json.dumps(head, indent=1), encoding="utf-8",
                                            newline="\n")

    def audit(self, log_pub_key):
        """Recompute the tree and check the published head. Returns a printable report."""
        head = json.loads((self.dir / "head.json").read_text(encoding="utf-8"))
        root = mth(self.entries)
        lines = ["log with %d entries" % len(self.entries)]
        for i, (d, m) in enumerate(zip(self.entries, self.meta)):
            v = m["fw_version"]
            lines.append("  [%d] leaf %s  version %d.%d.%d  security counter %d" %
                         (i, leaf_hash(d).hex()[:16], v >> 24, (v >> 16) & 0xFF, v & 0xFFFF,
                          m["security_counter"]))
        ok_root = head["tree_size"] == len(self.entries) and head["root"] == root.hex()
        try:
            verify_head(log_pub_key, head["tree_size"], bytes.fromhex(head["root"]),
                        bytes.fromhex(head["signature"]))
            ok_sig = True
        except Exception:
            ok_sig = False
        lines.append("recomputed root  %s" % root.hex())
        lines.append("head matches log: %s, head signature valid: %s" % (ok_root, ok_sig))
        return "\n".join(lines), ok_root and ok_sig

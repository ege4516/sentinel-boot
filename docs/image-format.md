# Update package format (version 2)

A package is a fixed 248-byte **manifest**, a fixed 364-byte **log proof block**, and the
**ciphertext** of the firmware image: 612 bytes of header followed by `image_size` bytes. All
integers are little-endian. Fields are read one by one; the parser never casts the buffer to a
struct. Format 1 (manifest and ciphertext only, no proof) is rejected.

## Manifest layout (offset 0, 248 bytes)

| Offset | Size | Field              | Notes |
|-------:|-----:|--------------------|-------|
| 0      | 4    | `magic`            | `0x314D4253`, bytes `53 42 4D 31` ("SBM1") |
| 4      | 2    | `format`           | Must be `2`. Other values are rejected, not ignored |
| 6      | 2    | `flags`            | Must be `0` |
| 8      | 4    | `fw_version`       | `major<<24 \| minor<<16 \| patch` |
| 12     | 4    | `security_counter` | Anti-rollback counter, compared with the OTP counter |
| 16     | 4    | `image_size`       | Plaintext size = ciphertext size; `1 .. slot capacity` |
| 20     | 4    | `key_id`           | First 4 bytes of SHA-256(root public key) |
| 24     | 65   | `eph_pub`          | Ephemeral ECDH public key, uncompressed SEC1 (`0x04 \|\| X \|\| Y`) |
| 89     | 12   | `nonce`            | AES-GCM nonce |
| 101    | 16   | `tag`              | AES-GCM tag |
| 117    | 32   | `ct_digest`        | SHA-256 of the ciphertext |
| 149    | 32   | `pt_digest`        | SHA-256 of the plaintext image |
| 181    | 3    | reserved           | Must be zero |
| 184    | 64   | `signature`        | ECDSA P-256, raw `r \|\| s` (IEEE P1363, **not** DER) |

## Log proof block (offset 248, 364 bytes)

| Offset | Size | Field        | Notes |
|-------:|-----:|--------------|-------|
| 0      | 4    | `leaf_index` | Position of this release in the log; must be `< tree_size` |
| 4      | 4    | `tree_size`  | Number of entries in the tree the proof refers to; `>= 1` |
| 8      | 1    | `path_len`   | Number of hashes used, `0..8` |
| 9      | 3    | reserved     | Must be zero |
| 12     | 32   | `root`       | Merkle tree hash of that tree |
| 44     | 64   | `signature`  | Log key, ECDSA P-256 raw `r \|\| s`, over the tree head |
| 108    | 256  | `path`       | 8 slots of 32 bytes; slots beyond `path_len` must be zero |

The tree is the Merkle tree of RFC 9162 section 2.1 with SHA-256:
`leaf = SHA-256(0x00 || data)`, `node = SHA-256(0x01 || left || right)`. The leaf data of a
release is the **signed region of its manifest** (`manifest[0:184]`), so the leaf commits to every
field the firmware root key signed. The tree head that the log key signs is
`SHA-256("sentinel-boot/v1/tree-head" || tree_size (LE32) || root)`.

## Cryptographic construction

- **Manifest signature.** `SHA-256(manifest[0:184])`, signed with the firmware root key
  (ECDSA P-256). The signed region contains every other manifest field, including both
  digests, the nonce, the tag and the ephemeral key. The proof block is *outside* this
  signature: it is verified against the log key instead.
- **Image key.** The signer generates a fresh ephemeral P-256 key pair for every
  package and computes ECDH with the device public key. The shared secret is the
  raw 32-byte X coordinate. Then
  `key = HKDF-SHA256(salt = empty, ikm = shared, info = "sentinel-boot/v1/image-key" || eph_pub, L = 32)`.
  A fresh key per package means the `(key, nonce)` pair can never repeat.
- **Encryption.** AES-256-GCM with the 12-byte nonce. The associated data is
  `manifest[0:24]` (magic through key id), so the version, counter, size and key
  id are authenticated by the AEAD as well as by the signature.

## Two keys, two roles

| Key | Held by | Signs | Device trusts it through |
|-----|---------|-------|--------------------------|
| Firmware root key | Release engineering | manifests | SHA-256 anchor in OTP |
| Log key | Log operator | tree heads | second SHA-256 anchor in OTP |

The anchors must differ. Without the log key an attacker who steals the root key can produce a
correctly signed manifest but not a proof that it is in the log, so the device refuses it, and
nobody auditing the log ever sees a release they did not expect.

## Verification order on the device

1. SHA-256 of the root public key (kept in ordinary flash) equals the root anchor in OTP.
2. `key_id` matches that hash.
3. ECDSA signature over `manifest[0:184]`.
4. The proof block parses: sizes in range, reserved bytes and unused path slots zero.
5. SHA-256 of the log public key (ordinary flash) equals the log anchor in OTP.
6. The log key's signature over the tree head verifies.
7. The inclusion proof leads from `SHA-256(0x00 || manifest[0:184])` to `root`.
8. `security_counter` >= OTP counter.
9. SHA-256 of the staged ciphertext equals `ct_digest`. Nothing is decrypted
   before this point, so the AEAD never processes unauthenticated input.
10. Derive the key, decrypt sector by sector, check the GCM tag.
11. SHA-256 of the plaintext on flash equals `pt_digest`.

Steps 1-8 and 11 are repeated on **every** boot; flash contents are not trusted across resets.

## Flash layout used by the simulator

```
[ state copy 0 ] [ state copy 1 ] [ slot 0 ............ ] [ slot 1 ............ ]
   1 sector         1 sector         header sector + image   header sector + image
```

A slot's first sector holds the manifest and the proof block (612 bytes); the image starts at the
next sector. During installation the ciphertext in the image area is replaced by plaintext, one
sector at a time.

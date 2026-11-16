# Update package format

A package is a fixed 248-byte **manifest** followed by the **ciphertext** of the
firmware image. All integers are little-endian. Fields are read one by one; the
parser never casts the buffer to a struct.

## Manifest layout

| Offset | Size | Field              | Notes |
|-------:|-----:|--------------------|-------|
| 0      | 4    | `magic`            | `0x314D4253`, bytes `53 42 4D 31` ("SBM1") |
| 4      | 2    | `format`           | Must be `1`. Unknown formats are rejected, not ignored |
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

The ciphertext follows at offset 248 and is exactly `image_size` bytes long.

## Cryptographic construction

- **Signature.** `SHA-256(manifest[0:184])`, signed with the root key
  (ECDSA P-256). The signed region contains every other field, including both
  digests, the nonce, the tag and the ephemeral key.
- **Image key.** The signer generates a fresh ephemeral P-256 key pair for every
  package and computes ECDH with the device public key. The shared secret is the
  raw 32-byte X coordinate. Then
  `key = HKDF-SHA256(salt = empty, ikm = shared, info = "sentinel-boot/v1/image-key" \|\| eph_pub, L = 32)`.
  A fresh key per package means the `(key, nonce)` pair can never repeat.
- **Encryption.** AES-256-GCM with the 12-byte nonce. The associated data is
  `manifest[0:24]` (magic through key id), so the version, counter, size and key
  id are authenticated by the AEAD as well as by the signature.

## Verification order on the device

1. SHA-256 of the root public key (kept in ordinary flash) equals the anchor in OTP.
2. `key_id` matches that hash.
3. ECDSA signature over `manifest[0:184]`.
4. `security_counter` >= OTP counter.
5. SHA-256 of the staged ciphertext equals `ct_digest`. Nothing is decrypted
   before this point, so the AEAD never processes unauthenticated input.
6. Derive the key, decrypt sector by sector, check the GCM tag.
7. SHA-256 of the plaintext on flash equals `pt_digest`.

Steps 1-4 and 7 are repeated on **every** boot; flash contents are not trusted
across resets.

## Flash layout used by the simulator

```
[ state copy 0 ] [ state copy 1 ] [ slot 0 ............ ] [ slot 1 ............ ]
   1 sector         1 sector         header sector + image   header sector + image
```

A slot's first sector holds the manifest; the image starts at the next sector.
During installation the ciphertext in the image area is replaced by plaintext,
one sector at a time.

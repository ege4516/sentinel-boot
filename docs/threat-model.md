# Threat model

Scope: the boot and update path of a Cortex-M class device. The code runs on a
host simulator; where real hardware would differ, that is stated.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Firmware integrity | Only vendor-signed code may run |
| Firmware confidentiality | Images are IP; they travel and rest encrypted |
| Root key hash (OTP) | The trust anchor of the whole chain |
| Device ECDH private key | Unwraps image keys; its disclosure exposes that device's packages |
| Anti-rollback counter | Stops re-installation of old, vulnerable releases |
| Availability | An update must never leave the device unable to boot |

## Adversary capabilities (in scope)

- Controls the network and the update server: can replay, reorder, truncate, modify or fabricate packages.
- Controls the application that stages updates (it is not trusted to verify anything).
- Can write arbitrary bytes to external flash between resets (including the root public key stored there).
- Can cut power at any moment, including in the middle of a flash write or erase.
- Holds genuine, vendor-signed old releases.

## Mitigations and the test that proves each one

| Threat | Mitigation | Test |
|--------|------------|------|
| Forged firmware | ECDSA P-256 over the whole manifest; root key must hash to the OTP anchor | `Manifest.RejectsManifestSignedByAnotherKey`, `Manifest.RejectsSubstitutedRootKey`, `BootReject.SignedByAttackerKey` |
| Modified manifest field | Signature covers every field except itself; exhaustive single-bit flips | `Manifest.AnyBitFlipInSignedRegionIsRejected`, `...InSignatureIsRejected` |
| Modified ciphertext | `ct_digest` checked before decryption, GCM tag after | `BootReject.TamperedCiphertext`, `TruncatedPackage` |
| Re-labelled ciphertext (new version, same bytes) | Header bound into the AEAD as associated data | `BootReject.HeaderIsBoundToCiphertextAsAad` |
| Rollback to a signed old release | `security_counter` >= OTP counter; counter raised only after confirmation | `BootReject.RollbackToOlderSecurityCounter` |
| Package meant for another device | Image key derived from the device key; tag fails | `BootReject.PackageEncryptedForAnotherDevice` |
| Parser exploitation | Fixed layout, explicit LE reads, size bounded by slot, reserved bytes zero, no dynamic allocation; libFuzzer + ASan/UBSan | `fuzz_manifest`, `fuzz_update`, `Manifest.EnforcesImageSizeBounds` |
| Tampering with flash at rest | Signature and plaintext digest re-verified on every boot | `Boot.CorruptedActiveImageFallsBackToConfirmedSlot`, `TamperedManifestOfInstalledImageRefusesToBoot` |
| Bricking by power loss | Two CRC-protected state copies written alternately; erase-before-program; unconfirmed images revert | `PowerFail.*` (cut at every flash operation, 43 cut points in the update life cycle) |
| Bricking by a bad update | Trial boots; a trial slot reverts if never confirmed; the fallback slot is protected while a trial runs | `Boot.UnconfirmedUpdateRevertsAfterTrialsExpire`, `UpdateIsRefusedWhileRunningImageIsOnTrial` |
| Plaintext leaking via staging | Packages are staged encrypted | `Boot.StagedPackageIsEncryptedAtRest` |

`tools/mutation_check.py` removes each of these defences one at a time and
requires the suite to fail; all 19 mutations are detected.

## Design decisions worth knowing

- **Confirm order.** `sb_update_confirm()` marks the slot CONFIRMED first and raises
  the OTP counter second. A power cut in between is repaired on the next boot. The
  opposite order could burn the counter while the only valid fallback becomes
  unacceptable.
- **Interrupted installs.** Decryption happens in place. A cut during decryption
  leaves ciphertext and plaintext mixed; the slot is then declared invalid and the
  device keeps running the old image. The package must be downloaded again. If the
  cut came after the last sector but before the state record, the finished plaintext
  verifies and the install is completed instead.
- **Rollback consequence.** Once an image with counter N is confirmed, images with a
  lower counter are no longer acceptable fallbacks. This is the intended price of
  anti-rollback (`Boot.ConfirmedCounterBumpRetiresOlderFallback`).
- **Equal counters are accepted.** The counter marks security-relevant releases; a
  release that does not raise it can still be installed and reverted.

## Assumptions

- The bootloader and the OTP anchor are immutable (mask ROM or locked flash).
- The signing key never leaves the vendor's signing environment.
- The signing host has a sound random number generator.
- The crypto backend (Mbed TLS 3.6.8) is correct and rejects invalid curve points.

## Out of scope and known limitations

- **OTP and key storage are simulated** in plain memory. On real hardware the root
  anchor and the device key belong in fuses or a secure element; the HAL interface
  (`hal/sb_hal.h`) is the seam for that.
- **No side-channel or fault-injection resistance.** Constant-time comparison and
  zeroisation are best effort in C; there is no glitch detection and no hardened
  branches.
- **Time of check vs time of use.** The image is verified and then handed to the
  caller; an attacker who can rewrite flash after verification and before
  execution is not defended against. Real ports need execute-from-verified-RAM or
  hardware flash protection.
- **No key rotation or revocation.** There is one root key and no way to retire it.
- **Static device key.** There is no forward secrecy toward the device: leaking the
  device key exposes every package recorded for that device.
- **The application can call confirm.** A compromised but validly signed application
  can confirm itself; the trial mechanism protects against faulty updates, not
  against a malicious vendor.
- **The boot-state record is CRC-checked, not authenticated.** The in-scope adversary
  who can write flash can forge it: switch the active slot, or mark an unconfirmed but
  validly signed image CONFIRMED (which also lets `sb_boot` raise the OTP counter to
  that image's counter). They still cannot make the device run unsigned code, code with
  a counter below the OTP value, or a modified image, because signature, counter and
  plaintext digest are re-verified from the slot contents on every boot. Authenticating
  the record (MAC under a device-unique key) is future work.
- **Not tested on hardware.** Everything runs on a host simulator. There is no
  Cortex-M port yet (the core compiles cleanly for Cortex-M3, but was never linked or run).

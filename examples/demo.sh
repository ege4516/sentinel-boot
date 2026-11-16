#!/usr/bin/env bash
# sentinel-boot demo: install, update, tamper, rollback, wrong-device.
# Usage: examples/demo.sh [path/to/sentinel-sim]
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SIM="${1:-${SIM:-$HOME/sb-build/host-debug/sentinel-sim}}"
SIGN="python3 $HERE/tools/sentinel_sign.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DEV="$WORK/device"; KEYS="$WORK/keys"; mkdir -p "$DEV"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
sim() { "$SIM" "$DEV" "$@"; }

[ -x "$SIM" ] || { echo "sentinel-sim not found at $SIM (build first)" >&2; exit 1; }

head -c 40000  /dev/urandom > "$WORK/fw1.bin"
head -c 90000  /dev/urandom > "$WORK/fw2.bin"
$SIGN keygen "$KEYS" > /dev/null

say "Factory: provision device (root key hash burned to OTP, counter = 0)"
sim provision "$KEYS/root_public.bin" "$KEYS/device_private.bin"

say "Sign firmware 1.0.0 (counter 1) and 2.0.0 (counter 2)"
$SIGN sign --root-key "$KEYS/root_private.pem" --device-pub "$KEYS/device_public.bin" \
  --image "$WORK/fw1.bin" --version 1.0.0 --security-counter 1 --out "$WORK/v1.pkg"
$SIGN sign --root-key "$KEYS/root_private.pem" --device-pub "$KEYS/device_public.bin" \
  --image "$WORK/fw2.bin" --version 2.0.0 --security-counter 2 --out "$WORK/v2.pkg"

say "Install 1.0.0"
sim stage "$WORK/v1.pkg"; sim boot; sim confirm

say "Over-the-air update to 2.0.0"
sim stage "$WORK/v2.pkg"; sim boot; sim confirm; sim status

say "ATTACK 1: one flipped bit in a validly signed package"
cp "$WORK/v2.pkg" "$WORK/tampered.pkg"
printf '\xff' | dd of="$WORK/tampered.pkg" bs=1 seek=50000 conv=notrunc status=none
sim stage "$WORK/tampered.pkg"; sim boot

say "ATTACK 2: replay of the genuine, signed 1.0.0 (rollback)"
sim stage "$WORK/v1.pkg"; sim boot

say "ATTACK 3: firmware signed by an attacker's key"
$SIGN keygen "$WORK/evil" > /dev/null
$SIGN sign --root-key "$WORK/evil/root_private.pem" --device-pub "$KEYS/device_public.bin" \
  --image "$WORK/fw2.bin" --version 9.9.9 --security-counter 99 --out "$WORK/evil.pkg"
sim stage "$WORK/evil.pkg"; sim boot

say "ATTACK 4: package encrypted for a different device"
$SIGN sign --root-key "$KEYS/root_private.pem" --device-pub "$WORK/evil/device_public.bin" \
  --image "$WORK/fw2.bin" --version 3.0.0 --security-counter 3 --out "$WORK/other.pkg"
sim stage "$WORK/other.pkg"; sim boot

say "Final state: still running genuine 2.0.0"
sim status
sim dump "$WORK/running.bin"
cmp "$WORK/running.bin" "$WORK/fw2.bin" && echo "running image is byte-identical to the signed 2.0.0 firmware"

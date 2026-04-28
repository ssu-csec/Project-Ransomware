"""
HDLocker Recovery Tool (PoC)
===============================
Decrypts HDLocker-encrypted files (.bat_HD, .py_HD, etc.) by XOR-ing with a
recovered keystream.

USAGE
-----
1. Recover keystream:
   Provide one (plaintext, ciphertext) pair from the SAME session:
       python hdlocker_recovery.py --recover-keystream \\
              --plaintext orig.bat --ciphertext orig.bat_HD \\
              --out keystream.bin

2. Decrypt other files (up to keystream length):
       python hdlocker_recovery.py --decrypt \\
              --keystream keystream.bin --in encrypted.txt_HD \\
              --out decrypted.txt

NOTES
-----
- HDLocker file format: [9-byte "HDLocker_" magic][13-byte per-file header][N-byte ciphertext]
- The cipher is a stream cipher: ciphertext_byte[i] = plaintext_byte[i] XOR keystream[i]
- The keystream is generated from the 32-byte key (in HD_*.log) but the
  generation algorithm is heavily obfuscated.
- This tool works by recovering keystream bytes from known (PT, CT) pairs and
  applying them. To decrypt files larger than your recovered keystream, you need
  a longer known plaintext.
- For maximum coverage, use the LARGEST known plaintext you have (e.g., Pin's
  documentation HTML files, README, .vsixmanifest, etc.).
"""

import argparse
import os
import sys

MAGIC = b"HDLocker_"
HEADER_LEN = 13  # bytes between magic and ciphertext (per-file IV/metadata)


def recover_keystream(pt_path: str, ct_path: str, out_path: str):
    pt = open(pt_path, "rb").read()
    ct_full = open(ct_path, "rb").read()

    if not ct_full.startswith(MAGIC):
        sys.exit(f"[!] {ct_path} does not start with 'HDLocker_' magic.")

    ct = ct_full[len(MAGIC) + HEADER_LEN:]  # skip magic + 13-byte header
    n = min(len(pt), len(ct))
    keystream = bytes(pt[i] ^ ct[i] for i in range(n))

    with open(out_path, "wb") as f:
        f.write(keystream)
    print(f"[+] Recovered {len(keystream)} bytes of keystream -> {out_path}")
    print(f"    First 32 bytes: {keystream[:32].hex()}")
    return keystream


def decrypt_file(ct_path: str, ks_path: str, out_path: str):
    ct_full = open(ct_path, "rb").read()
    keystream = open(ks_path, "rb").read()

    if not ct_full.startswith(MAGIC):
        sys.exit(f"[!] {ct_path} not a HDLocker file (no magic).")

    ct = ct_full[len(MAGIC) + HEADER_LEN:]

    if len(ct) > len(keystream):
        print(f"[!] WARNING: ciphertext ({len(ct)} B) longer than keystream ({len(keystream)} B).")
        print(f"    Only first {len(keystream)} bytes will be decrypted properly.")

    n = min(len(ct), len(keystream))
    pt = bytes(ct[i] ^ keystream[i] for i in range(n))

    with open(out_path, "wb") as f:
        f.write(pt)
    print(f"[+] Decrypted {n} bytes -> {out_path}")
    if len(ct) > n:
        print(f"    ({len(ct) - n} bytes left unencrypted-tail)")
    return pt


def verify_decryption(decrypted_path: str, original_path: str):
    """Check that decryption recovered the original plaintext."""
    decrypted = open(decrypted_path, "rb").read()
    original = open(original_path, "rb").read()
    n = min(len(decrypted), len(original))
    matches = sum(1 for i in range(n) if decrypted[i] == original[i])
    pct = 100.0 * matches / n if n else 0
    print(f"\n=== VERIFICATION ===")
    print(f"  decrypted: {len(decrypted)} bytes")
    print(f"  original:  {len(original)} bytes")
    print(f"  byte-match: {matches}/{n} ({pct:.2f}%)")
    if matches == n and len(decrypted) == len(original):
        print(f"  ★★★ PERFECT MATCH — recovery confirmed working! ★★★")
    return matches == n


def main():
    p = argparse.ArgumentParser(description="HDLocker recovery PoC")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recover-keystream", help="Recover keystream from known PT/CT pair")
    r.add_argument("--plaintext", required=True)
    r.add_argument("--ciphertext", required=True)
    r.add_argument("--out", required=True)

    d = sub.add_parser("decrypt", help="Decrypt a file using a recovered keystream")
    d.add_argument("--keystream", required=True)
    d.add_argument("--in", dest="in_path", required=True)
    d.add_argument("--out", required=True)

    v = sub.add_parser("verify", help="Verify a decrypted file against the original")
    v.add_argument("--decrypted", required=True)
    v.add_argument("--original", required=True)

    args = p.parse_args()

    if args.cmd == "recover-keystream":
        recover_keystream(args.plaintext, args.ciphertext, args.out)
    elif args.cmd == "decrypt":
        decrypt_file(args.in_path, args.keystream, args.out)
    elif args.cmd == "verify":
        verify_decryption(args.decrypted, args.original)


if __name__ == "__main__":
    main()

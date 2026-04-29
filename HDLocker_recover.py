"""
hdlocker_decrypt.py — HDLocker universal recovery tool (self-contained).

Usage:
    python hdlocker_decrypt.py --note HD_xxx.log --in-dir locked/ --out-dir recovered/

What it does:
  1. Reads the ransom note (HD_*.log) → extracts master_key (32 B).
  2. Picks the first *_HD file in --in-dir.
  3. Brute-forces the 16-byte TEA_KEY through hdlocker_keyspace.bin
     (binary's GBK ransom-note text region, ~73 KB, ~73,000 candidates).
  4. Validates the candidate by recovering ASCII / common file headers.
  5. With the discovered TEA_KEY, batch-decrypts every *_HD file in the folder.

No dmp, no trace, no server connection — just the tool + ransom note + locked files.

Dependencies (must be in same folder as this script):
    hdlocker_keyspace.bin   — 73 KB blob extracted from HDLocker.exe binary
"""
import argparse
import os
import struct
import sys
import time

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def resource_path(relname):
    """Locate bundled resource — works in source run AND PyInstaller exe."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relname)
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, relname)

# ---- TEA-BE-16round primitive ----
DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF
MAGIC = b'HDLocker_'

def tea_dec(in8, key, rounds=16):
    v0, v1 = struct.unpack('>II', in8); k = struct.unpack('>IIII', key)
    s = (DELTA * rounds) & MASK32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) & MASK32) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & MASK32
        v0 = (v0 - ((((v1 << 4) & MASK32) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & MASK32
        s = (s - DELTA) & MASK32
    return struct.pack('>II', v0, v1)


def recover_pt(body, key, iv=b'\x00'*8):
    """Decrypt body (CBC-variant) with given TEA_KEY."""
    pt = bytearray()
    nblocks = len(body) // 8
    if nblocks == 0:
        return bytes(pt)
    tea_out_prev = body[0:8]
    tea_in_prev  = tea_dec(tea_out_prev, key)
    pt += bytes(tea_in_prev[j] ^ iv[j] for j in range(8))
    body_prev = body[0:8]
    for i in range(1, nblocks):
        c = body[i*8:i*8+8]
        tea_out_i = bytes(c[j] ^ tea_in_prev[j] for j in range(8))
        tea_in_i  = tea_dec(tea_out_i, key)
        pt_i      = bytes(tea_in_i[j] ^ body_prev[j] for j in range(8))
        pt += pt_i
        tea_in_prev  = tea_in_i
        body_prev    = c
    return bytes(pt)


def score_candidate(pt):
    """Score recovered PT: count printable bytes after 0..7 byte prefix."""
    if len(pt) < 16:
        return 0
    best = 0
    for prefix_len in range(0, 9):
        chunk = pt[prefix_len:prefix_len+16]
        if len(chunk) < 16:
            continue
        s = sum(1 for b in chunk if (0x20 <= b < 0x7f) or b in (0x09, 0x0a, 0x0d))
        if s > best:
            best = s
    return best


def longest_ascii_run(data):
    """Length of longest contiguous run of printable bytes (incl. \\t \\n \\r)."""
    best = cur = 0
    for b in data:
        if (0x20 <= b < 0x7f) or b in (0x09, 0x0a, 0x0d):
            cur += 1
            if cur > best: best = cur
        else:
            cur = 0
    return best


def find_tea_key(body, keyspace, top_n=5):
    """Brute-force TEA_KEY: 3-pass scoring.
       Pass 1: coarse 24-byte printability filter
       Pass 2: refine with 1024 bytes
       Pass 3: full decrypt, longest-ASCII-run wins (handles per-file prefix)"""
    coarse = []
    test_body = body[:24]
    for off in range(len(keyspace) - 16 + 1):
        key = keyspace[off:off+16]
        try:
            pt = recover_pt(test_body, key)
        except Exception:
            continue
        s = score_candidate(pt)
        if s >= 12:
            coarse.append((s, off, key))
    coarse.sort(reverse=True)
    coarse = coarse[:max(top_n, 200)]   # widen for ambiguous cases

    refine_body = body[:min(1024, len(body))]
    refined = []
    for s_coarse, off, key in coarse:
        try:
            pt = recover_pt(refine_body, key)
        except Exception:
            continue
        nuls = pt.count(0)
        ok = sum(1 for b in pt if (0x20 <= b < 0x7f) or b in (9,10,13))
        run = longest_ascii_run(pt)
        # primary: longest contiguous ASCII run; secondary: total printable
        refined.append((run, ok - 2*nuls, off, key))
    refined.sort(reverse=True)
    return [(run, off, key) for run, _ok, off, key in refined[:top_n]]


def _is_ascii(b):
    return (0x20 <= b < 0x7f) or b in (9, 10, 13)


def detect_prefix_length(pt_padded, filename=''):
    """Per-file prefix detection (3..10), trail_pad fixed at 7.

    Multi-signal scoring:
      - Magic match at offset (strong)
      - Extension-based first-byte hint (strong)
      - ASCII-run length (medium)
      - Penalty for non-printable first byte (avoid trivial garbage)
      - Tie-break: prefer LARGER prefix (defense against ASCII-letter prefix
        metadata that gets bonus from longer ASCII run). 정답 prefix 가
        wrong-smaller prefix 와 score 동률이면 큰 게 정답 (false ASCII run
        less likely with larger offset)."""
    body_size = len(pt_padded)
    magics = [
        (b'\xef\xbb\xbf', 5000),
        (b'\xff\xfe', 3000), (b'\xfe\xff', 3000),
        (b'\r\n\r\n', 5000),
        (b'#include', 5000), (b'#ifndef', 5000),
        (b'#define ', 5000), (b'#pragma ', 5000),
        (b'<?xml', 5000), (b'<!DOC', 5000),
        (b'<html', 5000), (b'<HTML', 5000),
        (b'PK\x03\x04', 5000),
        (b'\x89PNG', 5000), (b'GIF89', 5000), (b'GIF87', 5000),
        (b'\xff\xd8\xff', 5000), (b'%PDF', 5000), (b'\x7fELF', 5000),
        (b'/*', 1500), (b'//', 1500),
        (b'#i', 800), (b'#d', 800), (b'#p', 800), (b'#l', 800),
        (b'\r\n', 800),
        (b'MZ', 500),
    ]
    ext = ''
    if filename:
        ext = os.path.splitext(filename.lower())[1]
        if ext.endswith('_hd'): ext = ext[:-3]
    EXT_FIRST_BYTES = {
        '.c':    set(b'/*#'),  '.cpp':  set(b'/*#'),
        '.cc':   set(b'/*#'),  '.cxx':  set(b'/*#'),
        '.h':    set(b'/*#'),  '.hpp':  set(b'/*#'),
        '.hxx':  set(b'/*#'),
        '.py':   set(b'#"\'idfcr'),
        '.js':   set(b'/*({\'""'),
        '.java': set(b'/*p'),
        '.cs':   set(b'/*u'),
        '.go':   set(b'/*p'),
        '.rs':   set(b'/*u'),
        '.md':   set(b'#*-=>'),
        '.xml':  set(b'<'), '.html': set(b'<'), '.htm': set(b'<'),
        '.json': set(b'{['),
        '.yaml': set(b'-#'), '.yml': set(b'-#'),
        '.idl':  set(b'/*#i['),
        '.grammar': set(b'/*#'),
    }
    expected_bytes = EXT_FIRST_BYTES.get(ext, set())

    PREFIX_CANDIDATES = (3, 4, 5, 6, 7, 8, 9, 10)
    best_off = 7; best_score = -10**9
    for off in PREFIX_CANDIDATES:
        if off + 7 > body_size:
            continue
        score = 0
        for m, w in magics:
            if pt_padded[off:off+len(m)] == m:
                ms = w - off * 10
                if ms > score: score = ms
        run = 0
        for b in pt_padded[off:off+128]:
            if _is_ascii(b): run += 1
            else: break
        score += run
        if expected_bytes and off < body_size:
            first = pt_padded[off]
            if first in expected_bytes:
                score += 2000
        if score > best_score:
            best_score = score; best_off = off
    return best_off


def extract_master_key(note_path):
    data = open(note_path, 'rb').read()
    marker = bytes.fromhex('c3dcd4bfa3ba')  # GBK '密钥：'
    j = data.find(marker)
    if j < 0:
        raise ValueError("'密钥：' marker not found in ransom note")
    after = data[j + 6:]
    end = min(x for x in [after.find(b'\r\n'), after.find(b'\n'), 64] if x > 0)
    return after[:end]


CIPHER_REGION_SIZE = 50016   # 16-byte header + 50000-byte cipher (large-file format)
LARGE_FILE_THRESHOLD = 50016 # if body > this, file uses large-file format

def decrypt_file(in_path, out_path, key, expected_prefix=None):
    data = open(in_path, 'rb').read()
    if not data.startswith(MAGIC):
        return False, "missing HDLocker_ magic"
    body = data[len(MAGIC):]

    if len(body) > LARGE_FILE_THRESHOLD:
        # Large-file format: plain_tail | 16B sep | 50000B cipher
        # plain_tail length = body_len - 50016
        plain_tail_len = len(body) - CIPHER_REGION_SIZE
        plain_tail = body[:plain_tail_len]
        cipher_region = body[plain_tail_len:]   # 50016 bytes
        # cipher_region[0:16] is the per-file 16B separator (likely IV-related);
        # cipher_region[16:] is 50000 bytes of cipher == 6250 blocks
        # But the trace shows the 50016 region as 6252 blocks total starting from
        # cipher_region[0:8] (with 0x25cd setup, then 0x268e body, then 0x2749 final).
        # Decrypt the entire 50016 bytes; the first 9 bytes of the result are
        # per-file prefix metadata, the remaining 50007 includes 50000 of orig file
        # plus 7 trailing bytes that are part of the prefix system.
        dec = recover_pt(cipher_region, key)
        # The decrypted cipher of the head: dec[9:] aligned with orig[0:50000]
        # However the "9-byte prefix" is actually 9 bytes of metadata before
        # the file content begins.
        head_plain = dec[9:9 + 50000]
        # Reconstruct: head + tail
        content = head_plain + plain_tail
        open(out_path, 'wb').write(content)
        return True, f"{len(content)}B (large-file format: head 50000 + tail {plain_tail_len})"
    else:
        # Small-file format: prefix + content + 7-byte trail-pad (fixed).
        pt_padded = recover_pt(body, key)
        # If known_size_dir is given, use it to compute exact prefix
        prefix_len = None
        known_size_dir = expected_prefix if isinstance(expected_prefix, str) else None
        if known_size_dir:
            base = os.path.basename(in_path)
            if base.endswith('_HD'): base = base[:-3]
            orig_path = os.path.join(known_size_dir, base)
            if os.path.isfile(orig_path):
                osz = os.path.getsize(orig_path)
                # prefix = body_size - osz - 7 (trail_pad=7 fixed)
                derived = len(pt_padded) - osz - 7
                if 3 <= derived <= 10:
                    prefix_len = derived
        if prefix_len is None:
            prefix_len = detect_prefix_length(pt_padded, os.path.basename(in_path))
        if len(pt_padded) >= prefix_len + 7:
            content = pt_padded[prefix_len:-7]
        else:
            content = pt_padded[prefix_len:]
        open(out_path, 'wb').write(content)
        return True, f"{len(content)}B (small-file, prefix={prefix_len}, trail_pad=7)"


def find_default_note(in_dir):
    """Search in_dir and its parent for HD_*.log."""
    for d in (in_dir, os.path.dirname(in_dir.rstrip('\\/'))):
        if not d or not os.path.isdir(d): continue
        for fn in os.listdir(d):
            if fn.startswith('HD_') and fn.endswith('.log'):
                return os.path.join(d, fn)
    return None


def prompt(question, default=None):
    """Prompt user; strip surrounding quotes. EOF-safe."""
    extra = f" [{default}]" if default else ""
    try:
        s = input(f"  {question}{extra}: ").strip().strip('"').strip("'")
    except EOFError:
        s = ''
    return s if s else default


def main():
    ap = argparse.ArgumentParser(
        description='HDLocker Universal Decryptor — recovers files locked by HDLocker.',
        epilog='Run with no arguments for interactive mode.')
    ap.add_argument('--note',    help='ransom note (HD_*.log)')
    ap.add_argument('--in-dir',  help='folder with *_HD locked files')
    ap.add_argument('--out-dir', help='output folder for recovered files')
    ap.add_argument('--known-size', help='[testing] folder with original files; '
                    'when given, exact prefix is derived from each file\'s size '
                    '(guarantees 100%% byte-exact recovery)')
    ap.add_argument('--keyspace',
                    default=resource_path('hdlocker_keyspace.bin'),
                    help='keyspace blob (default: bundled with exe)')
    args = ap.parse_args()

    print("=" * 70)
    print("HDLocker Universal Recovery Tool")
    print("=" * 70)

    # Interactive mode if --in-dir / --out-dir omitted
    if not args.in_dir:
        print("\n[Interactive mode]  Drag-drop a folder, or paste its path.")
        args.in_dir = prompt("Locked folder (--in-dir)")
        if not args.in_dir or not os.path.isdir(args.in_dir):
            print(f"[!] invalid folder: {args.in_dir}")
            input("\nPress Enter to exit...")
            sys.exit(1)
    if not args.out_dir:
        default_out = os.path.join(os.path.dirname(args.in_dir.rstrip('\\/')) or '.',
                                   'HDLocker_recovered')
        args.out_dir = prompt("Output folder (--out-dir)", default_out)
    if not args.note:
        guess = find_default_note(args.in_dir)
        if guess:
            print(f"  [auto] found ransom note: {guess}")
            args.note = guess
        else:
            args.note = prompt("Ransom note HD_*.log (optional, Enter to skip)", '')
            if not args.note: args.note = None

    # Load keyspace
    if not os.path.exists(args.keyspace):
        print(f"[!] keyspace not found: {args.keyspace}")
        sys.exit(1)
    keyspace = open(args.keyspace, 'rb').read()
    print(f"[*] keyspace: {len(keyspace):,} bytes  ({len(keyspace)-15:,} TEA_KEY candidates)")

    # Master key (optional)
    if args.note and os.path.exists(args.note):
        try:
            mk = extract_master_key(args.note)
            print(f"[*] master_key (from ransom note): {mk.hex()}")
        except Exception as e:
            print(f"[!] could not extract master_key: {e}")

    # Find _HD files
    if not os.path.isdir(args.in_dir):
        print(f"[!] not a folder: {args.in_dir}")
        sys.exit(1)
    hd_files = sorted(f for f in os.listdir(args.in_dir) if f.endswith('_HD'))
    if not hd_files:
        print(f"[!] no *_HD files in {args.in_dir}")
        sys.exit(1)
    print(f"[*] found {len(hd_files)} _HD file(s) in {args.in_dir}")

    # Brute-force TEA_KEY: pick the file whose CIPHER region is largest
    # (more bytes → more reliable ASCII-run scoring). For large files we use
    # the 50016-byte cipher region (already very long); for small files we
    # use the whole body and prefer the LARGEST small body.
    sized = []
    for f in hd_files:
        bs = os.path.getsize(os.path.join(args.in_dir, f)) - len(MAGIC)
        if bs < 16: continue
        # cipher region length used for brute-force
        if bs > LARGE_FILE_THRESHOLD:
            cipher_len = CIPHER_REGION_SIZE
        else:
            cipher_len = bs
        sized.append((cipher_len, bs, f))
    if not sized:
        print("[!] no usable files"); sys.exit(2)
    # Pick file with the longest usable cipher region (biggest = most reliable)
    sized.sort(reverse=True)
    cipher_len, body_size, first = sized[0]
    first_path = os.path.join(args.in_dir, first)
    full_body = open(first_path, 'rb').read()[len(MAGIC):]
    if body_size > LARGE_FILE_THRESHOLD:
        body = full_body[body_size - CIPHER_REGION_SIZE:]
        print(f"\n[*] Brute-forcing TEA_KEY using {first} (large-format, cipher region 50016 B)...")
    else:
        body = full_body
        print(f"\n[*] Brute-forcing TEA_KEY using {first} (small-format, body {body_size} B)...")
    t0 = time.time()
    cands = find_tea_key(body, keyspace, top_n=3)
    elapsed = time.time() - t0

    if not cands:
        print(f"[!] no TEA_KEY candidate found. This file may be from a different "
              f"HDLocker variant (different keyspace).")
        sys.exit(2)

    print(f"[*] Brute-force took {elapsed:.1f}s.  Top {len(cands)} candidates:")
    for s, off, key in cands:
        print(f"    score={s:>3}  offset=0x{off:>5x}  key={key.hex()}")

    best_score, best_off, TEA_KEY = cands[0]
    print(f"\n[+] Selected TEA_KEY = {TEA_KEY.hex()}  (score={best_score}, offset=0x{best_off:x})")

    # Determine prefix length from first file
    pt_padded = recover_pt(body, TEA_KEY)
    prefix_len = detect_prefix_length(pt_padded)
    print(f"[+] Prefix length: {prefix_len} bytes")

    # Batch decrypt
    os.makedirs(args.out_dir, exist_ok=True)
    print(f"\n[*] Decrypting {len(hd_files)} file(s)...")
    if args.known_size and os.path.isdir(args.known_size):
        print(f"[*] Using --known-size hint from: {args.known_size}")
    ok_count = 0
    for fn in hd_files:
        in_p  = os.path.join(args.in_dir, fn)
        out_name = fn[:-3] if fn.endswith('_HD') else fn + '.recovered'
        out_p = os.path.join(args.out_dir, out_name)
        # Use known-size dir as expected_prefix hint when provided
        hint = args.known_size if args.known_size else prefix_len
        try:
            ok, info = decrypt_file(in_p, out_p, TEA_KEY, hint)
            if ok:
                print(f"  [OK] {fn} -> {out_name}  ({info})")
                ok_count += 1
            else:
                print(f"  [!!] {fn}: {info}")
        except Exception as e:
            print(f"  [!!] {fn}: {e}")

    print(f"\n{'='*70}")
    print(f"Recovery complete: {ok_count}/{len(hd_files)} files")
    print(f"Output: {args.out_dir}")
    print(f"{'='*70}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback; traceback.print_exc()
    finally:
        # Pause so the window doesn't disappear when double-clicked
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass

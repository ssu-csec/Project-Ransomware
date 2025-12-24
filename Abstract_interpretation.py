# -*- coding: utf-8 -*-
"""
summarize_traces_v2.py
- Keep v1 pipeline: CSV -> match traces -> extract features -> canonicalize -> export
- Stronger compression across threads:
  (1) coarse grouping by binned addresses
  (2) GLOBAL merge per image using SimHash LSH + Hamming threshold
"""

import os
import re
import csv
import json
import argparse
from pathlib import Path
from dataclasses import dataclass
from collections import Counter, defaultdict

# -----------------------------
# Helpers
# -----------------------------
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def parse_hex_any(x):
    if x is None:
        return None
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if not s or not HEX_RE.match(s):
        return None
    return int(s, 16)

def safe_int(x, default=0):
    try:
        if x is None or str(x).strip() == "":
            return default
        return int(float(x))
    except Exception:
        return default

def hamming64(a, b):
    return (a ^ b).bit_count()

def fnv1a64(data: bytes) -> int:
    h = 1469598103934665603
    for b in data:
        h ^= b
        h = (h * 1099511628211) & ((1 << 64) - 1)
    return h

# -----------------------------
# Trace parse + SimHash
# -----------------------------
MNEMONIC_RE = re.compile(
    r'^\s*(?:0x)?[0-9a-fA-F]{6,16}\s*[:\s]\s*([A-Za-z]{2,10})\b|^\s*([A-Za-z]{2,10})\b'
)

def extract_trace_features(txt_path: Path, max_lines=4000, topk=12):
    counts = Counter()
    tokens = []
    n_lines = 0

    try:
        with txt_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if n_lines >= max_lines:
                    break
                n_lines += 1
                m = MNEMONIC_RE.match(line)
                if not m:
                    continue
                mn = (m.group(1) or m.group(2) or "").lower()
                if not mn:
                    continue
                counts[mn] += 1
                tokens.append(mn)
    except Exception:
        return 0, "", 0

    # SimHash 64 (weighted)
    v = [0] * 64
    tok_counts = Counter(tokens)
    for tok, w in tok_counts.items():
        h = fnv1a64(tok.encode("utf-8"))
        for i in range(64):
            v[i] += w if ((h >> i) & 1) else -w

    simh = 0
    for i in range(64):
        if v[i] >= 0:
            simh |= (1 << i)

    mn_top = ";".join([f"{mn}:{cnt}" for mn, cnt in counts.most_common(topk)])
    return simh, mn_top, n_lines

def read_snippet(txt_path: Path, n=80):
    try:
        out = []
        with txt_path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= n:
                    break
                out.append(line.rstrip("\n"))
        return out
    except Exception:
        return []

# -----------------------------
# Trace indexing / matching
# -----------------------------
TID_PAT = re.compile(r'(?:^|[_\-.])T(\d+)(?:[_\-.]|$)', re.IGNORECASE)
LID_PAT = re.compile(r'(?:^|[_\-.])L(\d+)(?:[_\-.]|$)', re.IGNORECASE)
SADDR_PAT = re.compile(r'(?:^|[_\-.])S([0-9a-fA-F]{6,16})(?:[_\-.]|$)', re.IGNORECASE)

@dataclass
class TraceMeta:
    path: Path
    tid: int | None
    lid: int | None
    saddr: int | None
    size: int

def index_trace_files(trace_dir: Path):
    metas = []
    for p in trace_dir.rglob("*.txt"):
        name = p.name
        tid = int(TID_PAT.search(name).group(1)) if TID_PAT.search(name) else None
        lid = int(LID_PAT.search(name).group(1)) if LID_PAT.search(name) else None
        saddr = parse_hex_any(SADDR_PAT.search(name).group(1)) if SADDR_PAT.search(name) else None
        try:
            size = p.stat().st_size
        except Exception:
            size = 0
        metas.append(TraceMeta(path=p, tid=tid, lid=lid, saddr=saddr, size=size))
    return metas

def best_match_trace(row, by_tid, by_tid_lid, by_tid_saddr):
    tid = row.get("tid")
    rank_thread = row.get("rank_thread")
    start_addr = row.get("start_addr_int")

    if tid is not None and rank_thread is not None:
        p = by_tid_lid.get((tid, rank_thread))
        if p:
            return p
    if tid is not None and start_addr is not None:
        p = by_tid_saddr.get((tid, start_addr))
        if p:
            return p
    if tid is not None:
        cands = by_tid.get(tid)
        if cands:
            return max(cands, key=lambda m: m.size).path
    return None

# -----------------------------
# Union-Find
# -----------------------------
class DSU:
    def __init__(self, n):
        self.p = list(range(n))
        self.sz = [1] * n
    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.sz[ra] < self.sz[rb]:
            ra, rb = rb, ra
        self.p[rb] = ra
        self.sz[ra] += self.sz[rb]

# -----------------------------
# Canonical key (coarse)
# -----------------------------
def make_coarse_key(row, bin_size=64, include_func=True):
    img = (row.get("img") or "").strip()
    func = (row.get("func") or "").strip()
    s = row.get("start_addr_int")
    e = row.get("end_addr_int")
    sbin = (s // bin_size) * bin_size if isinstance(s, int) else None
    ebin = (e // bin_size) * bin_size if isinstance(e, int) else None
    return (img, func, sbin, ebin) if include_func else (img, sbin, ebin)

# -----------------------------
# GLOBAL merge by SimHash LSH (per image)
# -----------------------------
def simhash_lsh_candidates(items, band_bits=16):
    """
    items: list of (idx, simhash64)
    returns: dict bucket -> list idx
    """
    buckets = defaultdict(list)
    mask = (1 << band_bits) - 1
    bands = 64 // band_bits
    for idx, h in items:
        if h == 0:
            continue
        for b in range(bands):
            key = (b, (h >> (b * band_bits)) & mask)
            buckets[key].append(idx)
    return buckets

def global_merge(rows, dsu: DSU, tau=12, delta=128, band_bits=16, max_bucket=200):
    """
    Merge across thread and across coarse bins:
    - same img
    - candidate pairs from SimHash LSH
    - accept if hamming(simhash) <= tau and (optionally) address near <= delta
    """
    # group indices by image
    by_img = defaultdict(list)
    for i, r in enumerate(rows):
        by_img[r["img"]].append(i)

    for img, idxs in by_img.items():
        # build LSH buckets
        items = [(i, rows[i].get("simhash64", 0)) for i in idxs]
        buckets = simhash_lsh_candidates(items, band_bits=band_bits)

        for _, cand in buckets.items():
            if len(cand) < 2:
                continue
            # avoid blow-up
            if len(cand) > max_bucket:
                # heuristic: keep only top by iter (most informative)
                cand = sorted(cand, key=lambda i: rows[i].get("iter", 0), reverse=True)[:max_bucket]

            # pairwise inside bucket
            for a_i in range(len(cand)):
                a = cand[a_i]
                ha = rows[a].get("simhash64", 0)
                if ha == 0:
                    continue
                sa = rows[a].get("start_addr_int")
                ea = rows[a].get("end_addr_int")
                for b_i in range(a_i + 1, len(cand)):
                    b = cand[b_i]
                    hb = rows[b].get("simhash64", 0)
                    if hb == 0:
                        continue
                    if hamming64(ha, hb) > tau:
                        continue

                    # optional address sanity check (recommended to reduce false merge)
                    sb = rows[b].get("start_addr_int")
                    eb = rows[b].get("end_addr_int")
                    ok_addr = True
                    if isinstance(sa, int) and isinstance(sb, int) and delta > 0:
                        ok_addr &= abs(sa - sb) <= delta
                    if isinstance(ea, int) and isinstance(eb, int) and delta > 0:
                        ok_addr &= abs(ea - eb) <= delta

                    if ok_addr:
                        dsu.union(a, b)

# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--trace_dir", required=True)
    ap.add_argument("--out_dir", required=True)

    ap.add_argument("--bin_size", type=int, default=64)
    ap.add_argument("--include_func", type=int, default=1)

    ap.add_argument("--max_trace_lines", type=int, default=4000)
    ap.add_argument("--rep_snippet_lines", type=int, default=80)

    # Strong compression knobs
    ap.add_argument("--global_tau", type=int, default=12, help="SimHash hamming threshold for global merge (0 disables)")
    ap.add_argument("--global_delta", type=int, default=128, help="addr delta gate for global merge (0 disables)")
    ap.add_argument("--band_bits", type=int, default=16, help="LSH band bits (64 must be divisible by this)")
    ap.add_argument("--max_bucket", type=int, default=200, help="limit per LSH bucket to avoid O(k^2) explosion")

    args = ap.parse_args()

    csv_path = Path(args.csv)
    trace_dir = Path(args.trace_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- Load CSV ----
    rows = []
    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        headers = [h.strip() for h in (reader.fieldnames or [])]
        lower_map = {h.lower(): h for h in headers}

        def col(*cands):
            for c in cands:
                if c.lower() in lower_map:
                    return lower_map[c.lower()]
            return None

        c_tid = col("tid")
        c_rank_thread = col("rank_thread", "thread_rank", "rankthread")
        c_iter = col("iter", "itercount", "iters", "iteration", "iterations")
        c_score = col("score")
        c_img = col("img", "image", "module")
        c_func = col("func", "function", "symbol")
        c_s = col("start_addr", "start", "startaddr")
        c_e = col("end_addr", "end", "endaddr")

        opt = {k: col(k) for k in ["memr","memw","stackr","stackw","xor","addsub","shlshr","mul","body_len"]}

        for i, r in enumerate(reader):
            row = {
                "occ_id": i,
                "tid": safe_int(r.get(c_tid)) if c_tid else None,
                "rank_thread": safe_int(r.get(c_rank_thread)) if c_rank_thread else None,
                "iter": safe_int(r.get(c_iter), 0) if c_iter else 0,
                "score": float(r.get(c_score)) if (c_score and r.get(c_score)) else 0.0,
                "img": (r.get(c_img) or "").strip() if c_img else "",
                "func": (r.get(c_func) or "").strip() if c_func else "",
                "start_addr": (r.get(c_s) or "").strip() if c_s else "",
                "end_addr": (r.get(c_e) or "").strip() if c_e else "",
            }
            row["start_addr_int"] = parse_hex_any(row["start_addr"])
            row["end_addr_int"] = parse_hex_any(row["end_addr"])
            for k, cn in opt.items():
                row[k] = safe_int(r.get(cn), 0) if cn else 0
            rows.append(row)

    # ---- Index trace files ----
    metas = index_trace_files(trace_dir)
    by_tid = defaultdict(list)
    by_tid_lid = {}
    by_tid_saddr = {}

    for m in metas:
        if m.tid is not None:
            by_tid[m.tid].append(m)
        if m.tid is not None and m.lid is not None:
            by_tid_lid[(m.tid, m.lid)] = m.path
        if m.tid is not None and m.saddr is not None:
            by_tid_saddr[(m.tid, m.saddr)] = m.path

    # ---- Enrich occurrences with trace features ----
    feat_cache = {}
    unmatched = 0

    for r in rows:
        tpath = best_match_trace(r, by_tid, by_tid_lid, by_tid_saddr)
        r["trace_path"] = str(tpath) if tpath else ""
        if not tpath:
            unmatched += 1
            r["simhash64"] = 0
            r["mn_top"] = ""
            r["trace_lines"] = 0
            continue

        if tpath not in feat_cache:
            simh, mn_top, nlines = extract_trace_features(
                Path(tpath),
                max_lines=args.max_trace_lines
            )
            feat_cache[tpath] = (simh, mn_top, nlines)

        simh, mn_top, nlines = feat_cache[tpath]
        r["simhash64"] = simh
        r["mn_top"] = mn_top
        r["trace_lines"] = nlines

    # ---- Step 1: coarse union by binned addresses (still thread-agnostic) ----
    include_func = bool(args.include_func)
    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups[make_coarse_key(r, bin_size=args.bin_size, include_func=include_func)].append(i)

    dsu = DSU(len(rows))
    for _, idxs in groups.items():
        if len(idxs) < 2:
            continue
        base = idxs[0]
        for j in idxs[1:]:
            dsu.union(base, j)

    # ---- Step 2: GLOBAL merge across bins using SimHash LSH (strong compression) ----
    if args.global_tau and args.global_tau > 0:
        global_merge(
            rows,
            dsu,
            tau=args.global_tau,
            delta=args.global_delta,
            band_bits=args.band_bits,
            max_bucket=args.max_bucket,
        )

    # ---- Build canonical clusters ----
    clusters = defaultdict(list)
    for i in range(len(rows)):
        clusters[dsu.find(i)].append(i)

    # assign canonical_id
    canon_id = 0
    occ_to_canon = {}
    canonical_records = []

    for root, idxs in clusters.items():
        canon_id += 1
        cid = canon_id
        for i in idxs:
            occ_to_canon[rows[i]["occ_id"]] = cid

        cluster_rows = [rows[i] for i in idxs]
        total_iter = sum(r["iter"] for r in cluster_rows)
        max_iter = max((r["iter"] for r in cluster_rows), default=0)
        tids = sorted({r["tid"] for r in cluster_rows if r["tid"] is not None})
        iters_by_tid = defaultdict(int)
        for r in cluster_rows:
            if r["tid"] is not None:
                iters_by_tid[r["tid"]] += r["iter"]

        rep = max(cluster_rows, key=lambda r: (r["iter"], 1 if r["trace_path"] else 0))
        # coarse key preview for debugging
        ck = make_coarse_key(rep, bin_size=args.bin_size, include_func=include_func)

        rec = {
            "canonical_id": cid,
            "img": rep["img"],
            "func": rep["func"],
            "coarse_key": str(ck),
            "total_iter": total_iter,
            "max_iter": max_iter,
            "n_occurrences": len(cluster_rows),
            "tids": ";".join(map(str, tids)),
            "iters_by_tid_json": json.dumps(dict(sorted(iters_by_tid.items())), ensure_ascii=False),
            "rep_occ_id": rep["occ_id"],
            "rep_trace_path": rep["trace_path"],
            "mn_top_rep": rep.get("mn_top", ""),
        }
        for k in ["memr","memw","stackr","stackw","xor","addsub","shlshr","mul","body_len"]:
            rec[f"{k}_sum"] = sum(r.get(k, 0) for r in cluster_rows)

        canonical_records.append(rec)

    # ---- Export ----
    occ_out = out_dir / "occurrences_enriched.csv"
    occ_fields = [
        "occ_id","tid","rank_thread","img","func","start_addr","end_addr","iter","score",
        "memr","memw","stackr","stackw","xor","addsub","shlshr","mul","body_len",
        "trace_path","trace_lines","simhash64","mn_top"
    ]
    with occ_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=occ_fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in occ_fields})

    canon_out = out_dir / "canonical_loops.csv"
    canon_fields = [
        "canonical_id","img","func","coarse_key",
        "total_iter","max_iter","n_occurrences","tids","iters_by_tid_json",
        "memr_sum","memw_sum","stackr_sum","stackw_sum","xor_sum","addsub_sum","shlshr_sum","mul_sum","body_len_sum",
        "rep_occ_id","rep_trace_path","mn_top_rep"
    ]
    with canon_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=canon_fields)
        w.writeheader()
        for r in canonical_records:
            w.writerow({k: r.get(k, "") for k in canon_fields})

    map_out = out_dir / "map_occ_to_canon.csv"
    with map_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["occ_id", "canonical_id"])
        for occ_id in range(len(rows)):
            w.writerow([occ_id, occ_to_canon.get(occ_id, "")])

    llm_out = out_dir / "llm_packets.jsonl"
    with llm_out.open("w", encoding="utf-8") as f:
        for r in canonical_records:
            snippet = read_snippet(Path(r["rep_trace_path"]), n=args.rep_snippet_lines) if r.get("rep_trace_path") else []
            pkt = {
                "canonical_id": r["canonical_id"],
                "img": r["img"],
                "func": r["func"],
                "total_iter": r["total_iter"],
                "max_iter": r["max_iter"],
                "n_occurrences": r["n_occurrences"],
                "tids": r["tids"],
                "iters_by_tid": json.loads(r["iters_by_tid_json"]) if r.get("iters_by_tid_json") else {},
                "counters_sum": {k.replace("_sum",""): r.get(k, 0) for k in [
                    "memr_sum","memw_sum","stackr_sum","stackw_sum","xor_sum","addsub_sum","shlshr_sum","mul_sum","body_len_sum"
                ]},
                "mn_top_rep": r.get("mn_top_rep", ""),
                "rep_trace_path": r.get("rep_trace_path", ""),
                "rep_trace_snippet": snippet,
            }
            f.write(json.dumps(pkt, ensure_ascii=False) + "\n")

    print(f"[OK] occurrences: {len(rows)}")
    print(f"[OK] canonical_loops: {len(canonical_records)}")
    print(f"[WARN] unmatched occurrences (no trace matched): {unmatched}")
    print(f"[OUT] {occ_out}")
    print(f"[OUT] {canon_out}")
    print(f"[OUT] {map_out}")
    print(f"[OUT] {llm_out}")

if __name__ == "__main__":
    main()

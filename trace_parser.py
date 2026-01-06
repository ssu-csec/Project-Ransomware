import struct
import argparse
import os
import sys
from collections import defaultdict, Counter

# Struct layouts (must match C++ code)
# TraceEntry: ip, regs[8], memAddr (all uint32) -> 10 * 4 = 40 bytes
# LoopHeaderEntry: magic, tid, header, backedge, rank -> 5 * 4 = 20 bytes

MAGIC_LOOP_HEAD = 0x4C4F4F50 # "LOOP"

# Auto-detection Config
NOISE_IMAGES = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "msvcrt.dll", "wow64.dll", "wow64cpu.dll", "ucrtbase.dll", "rpcrt4.dll", "sechost.dll"]
CRYPTO_IMAGES = ["bcrypt.dll", "crypt32.dll", "advapi32.dll", "ncrypt.dll", "bcryptprimitives.dll", "ncryptprov.dll", "rsaenh.dll", "dssenh.dll"]
IO_WHITELIST = ["WriteFile", "ReadFile", "CreateFile", "CloseHandle", "SetFilePointer", "GetFileSize", "NtWriteFile", "NtReadFile", "ZwWriteFile", "ZwReadFile"]

class AggregatedLoop:
    def __init__(self, header, tid):
        self.header = header
        self.tids = set()
        self.tids.add(tid)
        self.invocations = 0
        self.variants = [] # List of {'backedge': addr, 'entries': [TraceEntry], 'count': N}
    
    def add_instance(self, tid, backedge, entries):
        self.invocations += 1
        self.tids.add(tid)
        
        # Check if this variant (path) already exists
        # We define a "variant" by its backedge (simple heuristic) and length
        # A stricter check would hash the IPs.
        for v in self.variants:
            if v['backedge'] == backedge and len(v['entries']) == len(entries):
                # Potential match, check instruction sequence (IPs)
                match = True
                for i in range(len(entries)):
                    if v['entries'][i]['ip'] != entries[i]['ip']:
                        match = False
                        break
                if match:
                    v['count'] += 1
                    return

        # New variant
        self.variants.append({
            'backedge': backedge,
            'entries': entries,
            'count': 1
        })

    def get_primary_variant(self):
        # Return the variant with highest count
        if not self.variants: return None
        return max(self.variants, key=lambda x: x['count'])


class TraceParser:
    def __init__(self, meta_path, trace_path, show_all=False):
        self.meta_path = meta_path
        self.trace_path = trace_path
        self.show_all = show_all
        self.meta = {} # addr32 -> {func, img, asm, ...}
        self.aggregated_loops = {} # (header_addr) -> AggregatedLoop

    def load_meta(self):
        if not os.path.exists(self.meta_path):
            sys.stderr.write(f"[!] Meta file not found: {self.meta_path}\n")
            # Hint
            import glob
            d = os.path.dirname(self.meta_path) or '.'
            base = os.path.basename(self.meta_path)
            # assume user might miss the PID or suffix
            pat = base.replace('_meta.wcm', '*_meta.wcm').replace('.wcm', '*.wcm')
            cands = glob.glob(os.path.join(d, pat))
            if cands:
                sys.stderr.write(f"    Did you mean: {cands[0]}?\n")
            return
        
        sys.stderr.write(f"[*] Loading metadata from: {self.meta_path}\n")
        try:
            with open(self.meta_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split(';')
                    if len(parts) < 4: continue
                    try:
                        addr_str = parts[0].strip()
                        func = parts[1].strip()
                        img = parts[2].strip()
                        asm = parts[3].strip()
                        
                        # Handle potential BOM or garbage
                        if not all(c in '0123456789abcdefABCDEF' for c in addr_str):
                             # excessive cleaning
                             addr_str = "".join([c for c in addr_str if c in '0123456789abcdefABCDEF'])

                        if not addr_str: continue

                        addr = int(addr_str, 16)
                        self.meta[addr] = {
                            'func': func,
                            'img': img,
                            'asm': asm
                        }
                    except Exception as e:
                        # print(f"[!] Meta parse error line '{line}': {e}")
                        continue
            sys.stderr.write(f"[*] Loaded {len(self.meta)} static meta entries.\n")
        except Exception as e:
            sys.stderr.write(f"[!] Failed to read meta file: {e}\n")

    def parse_trace(self):
        if not os.path.exists(self.trace_path):
            sys.stderr.write(f"[!] Trace file not found: {self.trace_path}\n")
            # Hint
            import glob
            d = os.path.dirname(self.trace_path) or '.'
            base = os.path.basename(self.trace_path)
            # assume user might miss the PID
            pat = base.replace('.wct', '*.wct')
            cands = glob.glob(os.path.join(d, pat))
            if cands:
                sys.stderr.write(f"    Did you mean: {cands[0]}?\n")
            return

        sys.stderr.write(f"[*] Parsing trace file: {self.trace_path}\n")
        
        with open(self.trace_path, 'rb') as f:
            sz_trace = 40
            sz_head = 20
            
            # Temporary state for current instance
            current_tid = 0
            current_header = 0
            current_backedge = 0
            current_entries = []
            in_loop = False

            while True:
                pos = f.tell()
                chunk = f.read(4)
                if len(chunk) < 4: break
                
                val = struct.unpack('<I', chunk)[0]
                f.seek(pos) # rewind

                if val == MAGIC_LOOP_HEAD:
                    # Flush previous loop if exists
                    if in_loop and current_entries:
                        self._store_loop(current_header, current_tid, current_backedge, current_entries)
                    
                    data = f.read(sz_head)
                    if len(data) < sz_head: break
                    magic, tid, header, backedge, rank = struct.unpack('<IIIII', data)
                    
                    in_loop = True
                    current_tid = tid
                    current_header = header
                    current_backedge = backedge
                    current_entries = []
                    
                else:
                    if not in_loop:
                        # Orphan trace entry (or non-loop trace?) - skip or log warning
                        f.read(sz_trace)
                        continue

                    data = f.read(sz_trace)
                    if len(data) < sz_trace: break
                    # ip, regs[8], mem
                    elems = struct.unpack('<I8II', data)
                    entry = {
                        'ip': elems[0],
                        'regs': elems[1:9],
                        'mem': elems[9]
                    }
                    current_entries.append(entry)
            
            # Final flush
            if in_loop and current_entries:
                 self._store_loop(current_header, current_tid, current_backedge, current_entries)
                
        sys.stderr.write(f"[*] Aggregated into {len(self.aggregated_loops)} unique loops.\n")

    def _store_loop(self, header, tid, backedge, entries):
        if header not in self.aggregated_loops:
            self.aggregated_loops[header] = AggregatedLoop(header, tid)
        
        self.aggregated_loops[header].add_instance(tid, backedge, entries)

    def _fmt_reg_diff(self, e_prev, e_curr):
        # Heuristic: show registers that changed
        if not e_prev: return ""
        diffs = []
        reg_names = ["EAX","EBX","ECX","EDX","ESI","EDI","ESP","EBP"]
        for i in range(8):
            if e_prev['regs'][i] != e_curr['regs'][i]:
                diffs.append(f"{reg_names[i]}={e_curr['regs'][i]:x}")
        return " ".join(diffs)

    def _is_control_flow(self, asm):
        if not asm: return False
        opcode = asm.split()[0].lower()
        return opcode.startswith('j') or opcode.startswith('call') or opcode.startswith('ret') or opcode in ['loop', 'loope', 'loopne', 'syscall', 'sysenter', 'int']

    def _analyze_block_type(self, lines):
        # returns string describing primary activity: "Calculations", "Memory Access", "Function Calls", "Mixed"
        has_mem = False
        has_calc = False
        has_call = False
        
        for l in lines:
            # line format: "  addr: asm ... ; Mem: ..."
            if "call" in l.lower(): has_call = True
            if "Mem:" in l: has_mem = True
            if "xor" in l.lower() or "add" in l.lower() or "sub" in l.lower() or "shl" in l.lower(): has_calc = True
            
        types = []
        if has_call: types.append("Call")
        if has_mem: types.append("Mem")
        if has_calc: types.append("Calc")
        
        if not types: return "Misc"
        return "+".join(types)

    def _compress_blocks(self, blocks):
        # blocks is list of (label, instruction_lines_list)
        # We want to identify repeating sequences like [A, B, A, B] -> [A, B] x 2
        
        if not blocks: return []
        
        compressed = []
        n = len(blocks)
        i = 0
        while i < n:
            # Try to find a repeating pattern starting at i
            # Max pattern length: roughly half remaining
            best_pat = None
            best_reps = 1
            
            # Optimization: check short patterns first, now up to 64
            for pat_len in range(1, min(64, (n - i) // 2) + 1):
                pat = blocks[i : i+pat_len]
                
                # Count repetitions
                reps = 1
                curr = i + pat_len
                while curr + pat_len <= n:
                    candidate = blocks[curr : curr+pat_len]
                    # Deep compare: Only compare LABELS (index 0 of tuple)
                    # blocks[x] is (label, lines)
                    match = True
                    for k in range(pat_len):
                        if candidate[k][0] != pat[k][0]:
                            match = False
                            break
                    if match:
                        reps += 1
                        curr += pat_len
                    else:
                        break
                
                if reps > 1:
                    # Prefer longer patterns if reps are similar, or more reduction
                    # Simple metric: coverage = pat_len * reps
                    if best_pat is None or (pat_len * reps > len(best_pat) * best_reps):
                        best_pat = pat
                        best_reps = reps
            
            if best_pat:
                # Add pattern info
                # Pattern is list of blocks.
                # Collapse "lines" for display? No, keep structure.
                compressed.append({
                    'type': 'pattern',
                    'blocks': best_pat,
                    'count': best_reps
                })
                i += len(best_pat) * best_reps
            else:
                compressed.append({
                    'type': 'block',
                    'data': blocks[i]
                })
                i += 1
                
        return compressed

    def dump_llm_report(self):
        print("# Loop Analysis Report (Aggregated)")
        print("# Goal: Reconstruct Ransomware Logic (Encryption Loops)")
        print("# Output Format: High-Level Structural & Compressed Flow")
        print("#   - Shows 'Prolog', 'Main Body', 'Epilog' structure")
        print("#   - Summarizes block activities (Calc, Mem, Call)")
        print("")
        
        
        # Sort by total instructions processed (Heat = Invocations * Avg Length)
        sorted_loops = []
        for header, agg in self.aggregated_loops.items():
            primary = agg.get_primary_variant()
            if not primary: continue
            heat = agg.invocations * len(primary['entries'])
            
            # Classification
            m_head = self.meta.get(agg.header)
            if (not m_head) or (not m_head.get('img')) or (m_head.get('img') == '?'):
                 # Fallback: try first entry
                 if primary and primary['entries']:
                     m_head = self.meta.get(primary['entries'][0]['ip'], {'func':'?', 'img':'?', 'asm':'?'})
                 else:
                     m_head = {'func':'?', 'img':'?', 'asm':'?'}

            img_lower = m_head['img'].lower()
            
            is_noise = any(noise in img_lower for noise in NOISE_IMAGES)
            is_crypto = any(c in img_lower for c in CRYPTO_IMAGES)
            is_exe = ".exe" in img_lower
            
            # Check IO Whitelist (Function name based)
            func_lower = m_head.get('func', '').lower()
            is_io = any(io.lower() in func_lower for io in IO_WHITELIST)
            
            # Unmapped / Shellcode? (Important for generic ransomware)
            is_shellcode = (img_lower == '?' or img_lower == '')

            # Priority Score (Higher is better)
            # 3: Crypto DLLs, Main Exe, IO Whitelist, or Shellcode
            # 2: Other DLLs
            # 1: Noise DLLs
            priority = 2
            if is_noise: priority = 1
            if is_crypto or is_exe or is_io or is_shellcode: priority = 3
            
            sorted_loops.append((priority, heat, agg))
        
        # Sort by Priority (desc), then Heat (desc)
        sorted_loops.sort(key=lambda x: (x[0], x[1]), reverse=True)
        
        # Summary Table
        print("## Summary of Detected Loops (Priority Sorted)")
        print(f"Total Unique Loops: {len(sorted_loops)}")
        print("| Rank | Priority | Header Addr | Image | Function | Executions | Instructs |")
        print("|---|---|---|---|---|---|---|")
        
        for idx, (prio, heat, agg) in enumerate(sorted_loops):
             primary = agg.get_primary_variant()
             
             m_head = self.meta.get(agg.header)
             if (not m_head) or (not m_head.get('img')) or (m_head.get('img') == '?'):
                 # Fallback
                 if primary and primary['entries']:
                     m_head = self.meta.get(primary['entries'][0]['ip'], {'func':'?', 'img':'?', 'asm':'?'})
                 else:
                     m_head = {'func':'?', 'img':'?', 'asm':'?'}

             func_name = m_head['func'][:25] + ".." if len(m_head['func']) > 25 else m_head['func']
             img_name = m_head['img']
             
             prio_str = "High" if prio==3 else ("Low" if prio==1 else "Mid")
             
             print(f"| {idx+1} | {prio_str} | {agg.header:x} | {img_name} | {func_name} | {agg.invocations} | {len(primary['entries'])} |")
        
        print("\n" + "="*60 + "\n")

        for prio, heat, agg in sorted_loops:
            primary = agg.get_primary_variant()
            
            # Skip noise in detailed view unless it's explicitly requested (optional future flag)
            # For now, we skip Priority 1 (Noise) to keep the report clean as requested
            if prio == 1 and not self.show_all: continue
            primary = agg.get_primary_variant()
            if not primary: continue
            
            m_head = self.meta.get(agg.header)
            if (not m_head) or (not m_head.get('img')) or (m_head.get('img') == '?'):
                 # Fallback
                 if primary and primary['entries']:
                     m_head = self.meta.get(primary['entries'][0]['ip'], {'func':'?', 'img':'?', 'asm':'?'})
                 else:
                     m_head = {'func':'?', 'img':'?', 'asm':'?'}
            
            # TID Summary
            tid_list = sorted(list(agg.tids))
            tid_str = ",".join(map(str, tid_list))
            if len(tid_list) > 5: tid_str = f"{tid_list[:5]}... (Total {len(tid_list)})"

            print(f"## Detected Loop @ {agg.header:x} ({m_head['func']})")
            print(f"- **Image**: {m_head['img']}")
            print(f"- **Threads**: {tid_str}")
            print(f"- **Total Executions**: {agg.invocations}")
            
            entries = primary['entries']
            
            # 1. Group instructions into linear blocks first
            linear_blocks = []
            current_block_lines = []
            
            # Deduplication Cache: tuple(signature_lines) -> label
            # Signature = IP + ASM only (exclude Mem info)
            block_cache = {}
            next_block_id = 0
            
            # Label Statistics: label -> { 'mem_addrs': set() }
            label_stats = defaultdict(lambda: {'mem_addrs': set()})
 
            def get_block_label(lines):
                nonlocal next_block_id
                # Build signature
                sig = []
                mems = []
                for l in lines:
                    # Line format: "  addr: asm ... ; Mem: ..."
                    # Normalized Signature: ASM ONLY (Ignore Address and Mem)
                    parts = l.split(';')
                    left_part = parts[0].strip() # "addr: asm"
                    
                    # Split by first colon to remove key
                    if ':' in left_part:
                        asm_only = left_part.split(':', 1)[1].strip()
                        sig.append(asm_only)
                    else:
                        sig.append(left_part)

                    if len(parts) > 1 and "Mem:" in parts[1]:
                        try:
                            val_str = parts[1].split(":")[1].strip()
                            mems.append(int(val_str, 16))
                        except: pass
                
                t = tuple(sig)
                if t in block_cache:
                    lbl = block_cache[t]
                else:
                    lbl = f"lbl_{next_block_id:02X}"
                    block_cache[t] = lbl
                    next_block_id += 1
                
                # Update stats
                for m in mems:
                    label_stats[lbl]['mem_addrs'].add(m)
                
                return lbl
            
            for index, e in enumerate(entries):
                ip = e['ip']
                m = self.meta.get(ip, {'asm': '?', 'func': '?'})
                asm = m['asm']
                
                mem_info = ""
                if e['mem'] != 0:
                    mem_info = f"  ; Mem: {e['mem']:x}"
                
                line = f"  {ip:x}: {asm:<40}{mem_info}"
                current_block_lines.append(line)
                
                # If control flow, finish block
                if self._is_control_flow(asm) and index < len(entries) - 1:
                     lbl = get_block_label(current_block_lines)
                     linear_blocks.append((lbl, current_block_lines))
                     current_block_lines = []
            
            if current_block_lines:
                lbl = get_block_label(current_block_lines)
                linear_blocks.append((lbl, current_block_lines))
                
            # 2. Compress patterns
            compressed = self._compress_blocks(linear_blocks)

            # Analyze Structure (Prolog / Main Body / Epilog) ㅡ 
            # Heuristic: The item with largest 'count' > 1 is the Main Body.
            main_body_idx = -1
            max_reps = 0
            
            for i, item in enumerate(compressed):
                if item['type'] == 'pattern' and item['count'] > max_reps:
                    max_reps = item['count']
                    main_body_idx = i
            
            print(f"\n### High-Level Structure")
            
            if main_body_idx == -1:
                # No repeating pattern found?
                print("  [Linear Flow (No inner loops detected)]")
                for item in compressed:
                     (lbl, lines) = item['data']
                     btype = self._analyze_block_type(lines)
                     print(f"  -> {lbl} ({btype})")
            else:
                # Prolog
                if main_body_idx > 0:
                     print("  [ Prolog ]")
                     for i in range(main_body_idx):
                         item = compressed[i]
                         if item['type'] == 'block':
                             (lbl, lines) = item['data']
                             btype = self._analyze_block_type(lines)
                             print(f"     -> {lbl} ({btype})")
                         else:
                             print(f"     -> [Pattern x {item['count']}]")

                # Body
                item = compressed[main_body_idx]
                print(f"  [ Main Loop Body (Repeats {item['count']} times) ]")
                for (lbl, lines) in item['blocks']:
                    btype = self._analyze_block_type(lines)
                    print(f"     -> {lbl} ({btype})")

                # Epilog
                if main_body_idx < len(compressed) - 1:
                     print("  [ Epilog ]")
                     for i in range(main_body_idx + 1, len(compressed)):
                         item = compressed[i]
                         if item['type'] == 'block':
                             (lbl, lines) = item['data']
                             btype = self._analyze_block_type(lines)
                             print(f"     -> {lbl} ({btype})")
                         else:
                             print(f"     -> [Pattern x {item['count']}]")

            print(f"\n### Detailed Block/Instruction View")
            print("```assembly")
            
            # 3. Print
            for item in compressed:
                if item['type'] == 'pattern':
                    count = item['count']
                    pat_blocks = item['blocks']
                    
                    # Print pattern header
                    print(f"\n  ; --- REPEATING PATTERN [ x {count} ] ---(Start)")
                    for (lbl, lines) in pat_blocks:
                        # Stats string
                        stats = label_stats.get(lbl, {})
                        mem_count = len(stats.get('mem_addrs', []))
                        mem_info = ""
                        if mem_count > 0:
                            mem_info = f" (UniMem: {mem_count})"
                        
                        print(f"{lbl}{mem_info}:")
                        for l in lines: print(l)
                    print(f"  ; --- REPEATING PATTERN [ x {count} ] ---(End)")
                    
                else:
                    (lbl, lines) = item['data']
                    # Stats string
                    stats = label_stats.get(lbl, {})
                    mem_count = len(stats.get('mem_addrs', []))
                    mem_info = ""
                    if mem_count > 0:
                        mem_info = f" (UniMem: {mem_count})"

                    print(f"\n{lbl}{mem_info}:")
                    for l in lines: print(l)

            print("```")
            print("\n---\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--llm", action="store_true") # Default action for now
    parser.add_argument("--full", action="store_true") # Ignored in this specialized version
    parser.add_argument("--all", action="store_true", help="Show all loops including system noise")
    
    args = parser.parse_args()
    
    tp = TraceParser(args.meta, args.trace, args.all)
    tp.load_meta()
    tp.parse_trace()
    tp.dump_llm_report()

if __name__ == "__main__":
    main()

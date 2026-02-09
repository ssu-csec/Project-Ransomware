import struct
import re
import csv
import os
import sys
import argparse
import hashlib
from collections import defaultdict, Counter

HEX_ADDR = re.compile(r'0x[0-9a-fA-F]+')
DEC_NUM  = re.compile(r'\b\d+\b')

# size spec regularazation
SIZE_PTR = re.compile(r'\b(byte|word|dword|qword|xmmword)\s+ptr\b', re.IGNORECASE)

# Shape-preserving regexes
SEG_BRACKET_MEM = re.compile(r'\b([a-z]{2}:\[[^\]]+\])', re.I)
STACK_MEM = re.compile(r'\[(esp|ebp)([\+\-][0-9a-fx]+)?\]', re.I)
BRACKET_MEM = re.compile(r'\[([^\]]+)\]')

# stack access (ebp/esp based) - Allow <imm> from previous replacement if overlapping, 
# but we reorder to handle this before generic IMM.
STACK_MEM = re.compile(
    r'\[(?:ebp|esp)(?:\s*[\+\-]\s*(?:0x[0-9a-fA-F]+|\d+|<addr>|<imm>))?\]',
    re.IGNORECASE
)

def normalize_asm(asm: str, mem_struct: dict = None) -> str:
    s = asm.strip().strip('"').lower()

    # 1) If we have structured memory info, use it to REPLACE the memory operand
    # This is the "Index Unification" requested by user.
    # We find the bracketed part [...].
    if mem_struct:
        # Construct Abstract Token
        # mem_struct: {'base': str, 'idx': str, 'scale': str, 'disp': str}
        # e.g. base='ebx', idx='ecx', scale='4', disp='0'
        
        base = mem_struct['base'].lower()
        idx = mem_struct['idx'].lower()
        
        # SIB Scale Validation (critical for correct valid scale vs pointer confusion)
        scale_raw = int(mem_struct['scale'])
        # x86 valid scales are 1, 2, 4, 8. 
        scale_token = str(scale_raw)
        if scale_raw not in (1, 2, 4, 8):
            scale_token = "<S>" # Bucket weird scales
            scale = 1 # fallback for logic checks
        else:
            scale = scale_raw 

        disp_val = 0
        try:
             disp_val = int(mem_struct['disp'], 0)
        except: pass
        
        token = ""
        
        # Heuristic Strategy: Semantic Promotion
        # 1. Stack Access -> STACK[var_k]
        if base in ('esp', 'ebp'):
            sign = "+" if disp_val >= 0 else "-"
            token = f"STACK[var{sign}0x{abs(disp_val):x}]"

        # 2. Table/Array Access (Scale > 1) -> TABLE[idx] or TABLE(base)[idx]
        elif scale > 1 and idx:
            # If we have a constant displacement or base that looks like a table base
            # We can try TABLE(0x401000)[idx]
            # But stick to requested simple TABLE[idx] for now to ensure grouping.
            token = "TABLE[idx]"

        # 3. Buffer/Linear Access (Scale == 1, Has Index) -> BUF[pos]
        elif scale == 1 and idx:
            token = "BUF[pos]"

        # 4. Fallback: Standard Normalization
        else:
            parts = []
            if base: parts.append("BASE")
            if idx:
                # Use scale_token (which buckets weird scales as <S>)
                s_str = f"*{scale_token}" if scale_token != '1' else ""
                parts.append(f"IDX{s_str}")
            if disp_val != 0: parts.append("DISP") # or hex(disp_val)

            if not parts: token = "MEM[GLB]"
            else: token = "MEM[" + "+".join(parts) + "]"
        
        # Replace the [...] in asm with token
        s = re.sub(r'\[[^\]]+\]', token, s, count=1)
        
        # Normalize the Rest (Registers, Imms)
        # Constants
        s = re.sub(r'0x[0-9a-fA-F]+', '<imm>', s)
        s = DEC_NUM.sub('<imm>', s)
        # Size ptr
        s = SIZE_PTR.sub('ptr', s)
        
        s = re.sub(r'\s+', ' ', s).strip()
        return s

    # Fallback to Regex-based Normalization (if no meta or legacy)
    # 0) disasm expression diffs
    s = SIZE_PTR.sub('ptr', s)

    # helpers
    def _hex_repl(m):
        val_str = m.group(0)
        try:
            v = int(val_str, 16)
            return '<imm>' if v < 0x10000 else '<addr>'
        except:
            return '<addr>'

    def _seg_repl(m):
        seg = m.group(1).upper()
        return f'{seg}:SEG_MEM'
        
    def _mem_repl(m):
        content = m.group(1).lower()
        # Shape analysis
        has_base = False
        has_idx = False
        has_imm = False
        
        regs = re.findall(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b', content)
        if len(regs) == 1: has_base = True
        elif len(regs) >= 2: has_base = True; has_idx = True
        
        if re.search(r'[\+\-]\s*0x[0-9a-f]+', content) or re.search(r'[\+\-]\s*\d+', content):
            has_imm = True
            
        token = "MEM"
        
        scale_part = ""
        # Strict Scale Validation
        scale_match = re.search(r'\*(\d+)', content)
        if scale_match:
            try:
                sc = int(scale_match.group(1))
                if sc in (1, 2, 4, 8):
                    scale_part = f"*{sc}"
                else:
                    scale_part = "*<S>"
            except: 
                pass
        
        if has_base:
            if has_idx:
                token += "[BASE+IDX"
                token += scale_part
                if has_imm: token += "+IMM]"
                else: token += "]"
            else:
                token += "[BASE"
                if has_imm: token += "+IMM]"
                token += "]"
        elif has_imm: # Just imm?
             token = "MEM[GLB]"
        else:
             token = "MEM[UNK]"
             
        return token

    # 1. Specialized Memory Forms FIRST
    s = SEG_BRACKET_MEM.sub(_seg_repl, s)
    s = STACK_MEM.sub('STACK_MEM', s)
    
    # 2. General Memory (capture raw scales before DEC_NUM)
    s = BRACKET_MEM.sub(_mem_repl, s)
     
    # 3. Constants (Hex/Dec) - Split into <imm> (small) and <addr> (large)
    s = re.sub(r'0x[0-9a-fA-F]+', _hex_repl, s)
    s = DEC_NUM.sub('<imm>', s)

    # 3) Restore
    s = re.sub(r'\b(fs|gs):seg_mem\b', lambda m: f"{m.group(1).upper()}:MEM[...]", s, flags=re.I)
    s = s.replace('stack_mem', 'STACK[IDX]')
    
    s = re.sub(r'\s+', ' ', s).strip()

    # 2) Specific Memory Forms -> Temporary Placeholders
    # Segment
    def _seg_repl(m):
        seg = m.group(1).upper()
        return f'{seg}:SEG_MEM'
    s = SEG_BRACKET_MEM.sub(_seg_repl, s)
    
    # Stack
    s = STACK_MEM.sub('STACK_MEM', s)
    
    # General Memory
    def _mem_repl(m):
        content = m.group(1).lower()
        # Shape analysis
        has_base = False
        has_idx = False
        has_imm = False
        
        regs = re.findall(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b', content)
        if len(regs) == 1: has_base = True
        elif len(regs) >= 2: has_base = True; has_idx = True
        
        if re.search(r'[\+\-]\s*0x[0-9a-f]+', content) or re.search(r'[\+\-]\s*\d+', content):
            has_imm = True
            
        token = "MEM"
        # Bucketing Logic for Regex Fallback
        # If we see *<digits> inside content, check if valid scale
        # content e.g. "eax+ecx*4"
        scale_match = re.search(r'\*(\d+)', content)
        if scale_match:
            try:
                sc = int(scale_match.group(1))
                if sc not in (1, 2, 4, 8):
                     # Weird scale -> replace in content for abstraction?
                     # Actually normalize_asm returns a token, not the content.
                     # But for fallback we return generic MEM[...] structure.
                     pass 
            except: pass
        if has_base:
            if has_idx:
                token += "[BASE+IDX"
                if '*' in content: token += "*S"
                if has_imm: token += "+IMM]"
                else: token += "]"
            else:
                if has_imm: token += "[BASE+IMM]"
                else: token += "[BASE]"
        elif has_imm:
             token += "[IMM]"
        else:
             token += "[?]"
        return token

    s = BRACKET_MEM.sub(_mem_repl, s)

    # 3) Restore
    s = re.sub(r'\b(fs|gs):seg_mem\b', lambda m: f"{m.group(1).upper()}:MEM[...]", s, flags=re.I)
    s = s.replace('stack_mem', 'STACK[IDX]')
    
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def skeletonize_asm(asm: str, mem_struct: dict = None) -> str:
    # Stronger normalization for fuzzy merging (Abstracts Register allocation & Memory offsets)
    # 1. Normalize first (now includes MEM[IDX], STACK[IDX])
    s = normalize_asm(asm, mem_struct)
    
    # 2. Canonicalize Opcodes (Synonyms)
    s = re.sub(r'^inc\b', 'add', s) 
    s = re.sub(r'^dec\b', 'sub', s)
    s = re.sub(r'^jnz\b', 'jne', s)
    s = re.sub(r'^jz\b', 'je', s)
    
    # 3. Abstract Memory: already handled in normalize_asm (MEM[IDX], STACK[IDX])
    # Just generic cleanup if needed
    s = re.sub(r'\bptr\s+mem\[idx\]\b', 'MEM[IDX]', s) 
    s = re.sub(r'\bptr\s+stack\[idx\]\b', 'STACK[IDX]', s)
    
    # 4. Alpha-Renaming for Registers (Instruction-Local)
    # Map first seen reg to R0, second to R1, etc.
    # This distinguishes 'mov eax, ebx' (R0, R1) from 'mov eax, eax' (R0, R0)
    
    regs_found = []
    # All x86 registers regex
    all_regs_pat = r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|ax|bx|cx|dx|si|di|sp|bp|al|bl|cl|dl|ah|bh|ch|dh)\b'
    
    def repl_reg(match):
        r = match.group(1)
        if r not in regs_found:
            regs_found.append(r)
        idx = regs_found.index(r)
        return f"REG{idx}"
    
    s = re.sub(all_regs_pat, repl_reg, s)
    
    return s

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
        self.min_rank = 999999999 # Global Rank (First seen)
        self.variants = [] # List of {'backedge': addr, 'entries': [TraceEntry], 'count': N}
        self.score = 0.0 # Score for sorting/pruning
    
    def add_instance(self, backedge, entries, rank=None):
        self.invocations += 1
        # self.tids.add(tid) # tid is fixed per AggregatedLoop in initialization
        if rank is not None and rank < self.min_rank:
            self.min_rank = rank
        
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
                    # Update rank if this instance has a lower rank?
                    # Generally rank is unique per variant in Pin Tool if FirstSeenSeq is used.
                    # But if we treat them as same variant, maybe keep min rank?
                    if rank is not None and v.get('rank', 999999) > rank:
                         v['rank'] = rank
                    return

        # New variant
        variant = {
            'backedge': backedge,
            'entries': entries,
            'count': 1
        }
        if rank is not None:
             variant['rank'] = rank
             
        self.variants.append(variant)


    def get_primary_variant(self):
        # Return the variant with highest count
        if not self.variants: return None
        return max(self.variants, key=lambda x: x['count'])


class TraceParser:
    # ... (init and load_meta unchanged) ...
    def __init__(self, show_all=True):
        self.show_all = show_all
        self.meta = {} # addr -> {func, img, asm, ...} (Shared across PIDs, assuming no ASLR collisions)
        self.loops_by_tid = defaultdict(dict) # (pid, tid) -> header -> AggregatedLoop
        
        # CSV Data: (pid, globalSeq) -> iters
        self.loops_csv_data = {}
        # Fallback Data: (pid, header) -> iters
        self.loop_finish_counts = defaultdict(int)
        
        # IO Data: (pid, os_tid) -> [events]
        self.io_data = defaultdict(list)
        
        # Main Range
        self.main_low = 0
        self.main_high = 0

    def load_session(self, pid, trace_path, meta_path, csv_path):
        print(f"[*] Loading Session PID={pid}...")
        self.load_meta(meta_path)
        self.load_loops_csv(pid, csv_path)
        self.parse_trace(pid, trace_path)
        self.load_io_log(pid, trace_path)

    def load_meta(self, meta_path):
        if not os.path.exists(meta_path):
            return

        try:
            with open(meta_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    
                    if line.startswith('main_low='):
                        try:
                            tokens = line.split()
                            for t in tokens:
                                if t.startswith('main_low='):
                                    self.main_low = int(t.split('=')[1], 16)
                                elif t.startswith('main_high='):
                                    self.main_high = int(t.split('=')[1], 16)
                        except: pass
                        continue

                    parts = []
                    if ';' in line:
                        parts = line.split(';')
                    else:
                        parts = line.split(',')
                    
                    if len(parts) >= 2:
                        try:
                            addr_str = parts[0].strip()
                            addr_str = addr_str.replace('\ufeff', '').replace('\x00', '')
                            addr = int(addr_str, 16)
                            
                            if addr in self.meta: continue

                            func = "?"
                            img = "?"
                            asm = parts[1].strip()
                            mem_struct = None
                            
                            if len(parts) >= 4:
                                func = parts[1].strip()
                                img = parts[2].strip()
                                asm = parts[3].strip()
                                if len(parts) > 4:
                                     mem_struct_str = parts[4].strip()
                                     if '|' in mem_struct_str: 
                                         mp = mem_struct_str.split('|')
                                         if len(mp) >= 4:
                                             mem_struct = {'base': mp[0], 'idx': mp[1], 'scale': mp[2], 'disp': mp[3]}
                            else:
                                if self.main_low > 0 and self.main_low <= addr <= self.main_high:
                                    img = "hive.exe"
                                    func = f"sub_{addr:x}"

                            if '.' not in img and img.lower() in ['text', 'code', 'data']:
                                img = '.' + img

                            self.meta[addr] = {
                                'func': func,
                                'img': img,
                                'asm': asm,
                                'mem_struct': mem_struct
                            }
                            count += 1
                        except Exception:
                            continue
        except Exception as e:
            print(f"[!] Meta load error: {e}")
                    
        # print(f"[*] Loaded {count} metadata entries from {os.path.basename(meta_path)}.")

    def load_loops_csv(self, pid, csv_path):
        if not csv_path or not os.path.exists(csv_path):
            # print(f"[!] CSV path not found: {csv_path}")
            return

        # print(f"[*] Loading loops CSV from {csv_path}...")
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                count = 0
                for row in reader:
                    if not row or len(row) < 7: continue
                    try:
                        global_seq = int(row[1])
                        iters = int(row[6])
                        
                        # Key by (pid, globalSeq)
                        self.loops_csv_data[(pid, global_seq)] = iters
                        count += 1
                    except: pass
                # print(f"[*] Loaded {count} CSV rows.")
        except Exception as e:
            print(f"[!] Warning: Failed to parse CSV: {e}")

    def _trim_trace(self, entries, expected_img=None):
        """
        Trims trace entries based on Call-Depth to enforce strict scoping.
        Stops if execution returns to caller (depth < 0).
        Also stops if execution leaves the expected image module (P0 Scoping).
        """
        depth = 0
        valid_count = 0
        
        for e in entries:
            ip = e['ip']
            m = self.meta.get(ip)
            if not m:
                # Missing meta -> Unmapped? Treat as boundary breach if we expect an img
                if expected_img:
                     break # Stop trace
                valid_count += 1
                continue
            
            # P0: Image Boundary Check
            if expected_img and m.get('img') != expected_img:
                break # Moved to different module -> End of Loop Body Scope
                
            asm_lower = m['asm'].lower()
            
            # Simple heuristic for Call/Ret
            # Note: We rely on 'call' and 'ret' substrings at start of mnemonic
            # To be robust, we probably want strict mnemonic checking if possible
            if asm_lower.startswith('call'):
                depth += 1
            elif asm_lower.startswith('ret') or asm_lower.startswith('rep ret'):
                depth -= 1
            
            if depth < 0:
                # Returned to caller, stop capture here
                break
            
            valid_count += 1
            
        return entries[:valid_count]

    def _analyze_activity(self, entries):
        """
        Generates a summary string of loop activity: Mem(R/W), Call, Calc.
        (Phase 2) Also resolves Call Targets {Symbol: Count}.
        """
        mem_r = 0
        mem_w = 0
        call_count = 0
        calc_count = 0
        xor_count = 0
        call_targets = Counter()
        
        # Mnemonics for calc/crypt
        calc_ops = {'add', 'sub', 'inc', 'dec', 'mul', 'imul', 'div', 'idiv', 'shl', 'shr', 'rol', 'ror', 'and', 'or', 'xor', 'not', 'neg'}
        
        for e in entries:
            ip = e['ip']
            m = self.meta.get(ip)
            if not m: continue
            
            asm = m['asm'].lower()
            parts = asm.split(None, 1)
            mnemonic = parts[0] if parts else ""
            
            # Call
            if mnemonic == 'call':
                call_count += 1
                target = None
                ops = parts[1] if len(parts) > 1 else ""
                
                # Indirect Call? (reads memory, e.g. call dword ptr [eax])
                # We check raw trace 'mem' value if available
                if '[' in ops and e.get('mem', 0) != 0:
                     target = e['mem']
                
                # Direct Call? (call 0x...)
                if not target:
                    # Naive match for 0x...
                    # Pin asm: "call 0x1234"
                    match = re.search(r'(0x[0-9a-f]+)', ops)
                    if match:
                        try:
                            target = int(match.group(1), 16)
                        except: pass
                
                if target:
                    # Resolve symbol
                    tm = self.meta.get(target)
                    if tm:
                        sym = tm.get('func', '?')
                        # Simplify: remove args or module prefix if needed
                        # Usually "module!func". Keep it but maybe trim?
                        # Keep full name for now, nice for context.
                    else:
                        sym = f"sub_{target:x}"
                    
                    call_targets[sym] += 1

            # Calc
            if mnemonic in calc_ops:
                calc_count += 1
                if mnemonic == 'xor':
                    xor_count += 1
            
            # Mem R/W heuristic
            if '[' in asm:
                ops = parts[1] if len(parts) > 1 else ""
                op_parts = ops.split(',')
                if len(op_parts) >= 2:
                    dst = op_parts[0].strip()
                    if '[' in dst:
                        mem_w += 1
                    elif '[' in ops: # Anywhere else is source
                        mem_r += 1
                else:
                    # Single operand (inc [eax]) -> Read/Mod/Write? Treat as Write (modification)
                    if '[' in ops:
                        mem_w += 1

        summary = f"Mem(R:{mem_r}/W:{mem_w}), Call:{call_count}"
        
        if call_count > 0 and call_targets:
            # Append top 3 targets
            top = call_targets.most_common(3)
            # Format: {WriteFile:5, Open:2}
            t_str = ", ".join([f"{k}:{v}" for k,v in top])
            summary += f" {{{t_str}}}"
            
        if calc_count > 0:
            summary += f", Calc:{calc_count}"
        if xor_count > 0:
            summary += f" (XOR:{xor_count})"
            
        return summary

    def _store_loop(self, pid, header, tid, backedge, entries, rank):
        # 0. Get Header Info for Scoping
        header_img = None
        m = self.meta.get(header)
        if m: header_img = m.get('img')

        # 1. Scope Trimming (with Img Check)
        entries = self._trim_trace(entries, header_img)
        if not entries: return
        
        # Loop Aggregation Logic
        # TID Key -> (pid, tid)
        tid_key = (pid, tid)
        
        if header not in self.loops_by_tid[tid_key]:
            self.loops_by_tid[tid_key][header] = AggregatedLoop(header, tid_key)
        
        # add_instance signature fixed (removed tid)
        self.loops_by_tid[tid_key][header].add_instance(backedge, entries, rank)

    def parse_trace(self, pid, trace_path):
        self.trace_path = trace_path # Update current for error format?
        if not os.path.exists(trace_path):
            return

        print(f"[*] Parsing trace (PID={pid}): {trace_path}")
        
        current_tid = 0
        current_header = 0
        current_backedge = 0
        current_rank = 0
        current_entries = []
        in_loop = False
        
        # Check if filename implies TID/Rank (Raw Mode)
        fname = os.path.basename(trace_path)
        tid_match = re.search(r'tid(\d+)_(\d+)', fname)
        raw_mode_tid = int(tid_match.group(1)) if tid_match else 0
        raw_mode_rank = int(tid_match.group(2)) if tid_match else 0
        
        # Performance: Read line by line
        try:
            with open(self.trace_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    
                    if line.startswith('LOOP,'):
                        # LOOP,tid,header,backedge,rank,globalSeq
                        parts = line.split(',')
                        if len(parts) >= 6:
                            # Flush previous
                            if in_loop and current_entries:
                                self._store_loop(pid, current_header, current_tid, current_backedge, current_entries, current_rank)
                            
                            current_tid = int(parts[1])
                            current_header = int(parts[2], 16)
                            # Backedge is hex in our Pintool output
                            current_backedge = int(parts[3], 16)
                            
                            current_rank = int(parts[5]) # globalSeq
                            current_entries = []
                            in_loop = True
                            
                    elif line.startswith('LOOP_FINISH,'):
                        # LOOP_FINISH,header,backedge,iters
                        # Only used for iteration info, we can log it or specific store
                        parts = line.split(',')
                        if len(parts) >= 4:
                            f_header = int(parts[1], 16)
                            f_iters = int(parts[3])
                            # Store in csv data fallback?
                            # Or just ignore for now as it's redundant with CSV but good for verification
                            f_header = int(parts[1], 16)
                            f_iters = int(parts[3])
                            self.loop_finish_counts[(pid, f_header)] += f_iters

                    elif in_loop and (line.startswith('I,') or line.startswith('R,') or line.startswith('W,')):
                        # I,ip,0,regs...
                        # R,ip,mem,regs...
                        parts = line.split(',')
                        if len(parts) < 4: continue
                        
                        ip = int(parts[1], 16)
                        mem_addr = int(parts[2], 16)
                        
                        # Regs start at index 3
                        # Pintool: I/R/W, ip, mem, eax, ebx, ...
                        # Regs are hex
                        regs = []
                        for r in parts[3:]:
                            if r: 
                                try: regs.append(int(r, 16))
                                except: regs.append(0)
                        
                        entry = {
                            'ip': ip,
                            'mem': mem_addr,
                            'regs': regs
                        }
                        current_entries.append(entry)
                        
                    # RAW MODE FALLBACK: If line looks like "addr;asm;..."
                    elif ';' in line and not line.startswith('LOOP'):
                         parts = line.split(';')
                         if len(parts) >= 2:
                             # Heuristic: Raw Trace File from per-loop dump
                             try:
                                 ip_str = parts[0].strip()
                                 if '0x' in ip_str: ip = int(ip_str, 16)
                                 else: ip = int(ip_str, 16) # Assume Hex
                                 
                                 # If we haven't started a loop container, do it now
                                 if not in_loop:
                                      current_tid = raw_mode_tid
                                      current_rank = raw_mode_rank
                                      current_header = ip # First instruction = Header?
                                      current_backedge = 0 
                                      current_entries = []
                                      in_loop = True
                                 
                                 # parse specific columns? 
                                 # Format: addr;asm;regs_csv?
                                 # parts[1] is asm.
                                 asm_str = parts[1].strip()
                                 
                                 # POPULATE META IF MISSING
                                 if ip not in self.meta:
                                     img = "?"
                                     func = "?"
                                     if self.main_low > 0 and self.main_low <= ip <= self.main_high:
                                         img = "hive.exe"
                                         func = f"sub_{ip:x}"
                                     
                                     self.meta[ip] = {
                                         'func': func,
                                         'img': img,
                                         'asm': asm_str,
                                         'mem_struct': None
                                     }

                                 regs = []
                                 mem = 0
                                 if len(parts) > 2:
                                     # Regs CSV
                                     reg_parts = parts[2].split(',')
                                     # Heuristic: Find large values for regs? 
                                     # Or just zeros if we don't know the mapping.
                                     # We will store them blindly.
                                     for r in reg_parts:
                                         if r.strip():
                                             try: regs.append(int(r, 16))
                                             except: pass
                                 
                                 current_entries.append({'ip': ip, 'mem': mem, 'regs': regs})
                                 current_backedge = ip # Update backedge to current
                             except:
                                 pass
                        
            # Final flush
            if in_loop and current_entries:
                self._store_loop(pid, current_header, current_tid, current_backedge, current_entries, current_rank)

        except Exception as e:
            print(f"[!] Error parsing trace: {e}")

        total_loops = sum(len(loops) for loops in self.loops_by_tid.values())
        print(f"[*] Aggregated into {total_loops} unique loops across {len(self.loops_by_tid)} threads.")




    def _fmt_reg_diff(self, e_prev, e_curr):
        # Heuristic: show registers that changed
        if not e_prev: return ""
        diffs = []
        reg_names = ["EAX","EBX","ECX","EDX","ESI","EDI","ESP","EBP",
                     "R8","R9","R10","R11","R12","R13","R14","R15"]
        
        count = min(len(e_prev['regs']), len(e_curr['regs']), len(reg_names))
        
        for i in range(count):
            if e_prev['regs'][i] != e_curr['regs'][i]:
                diffs.append(f"{reg_names[i]}={e_curr['regs'][i]:x}")
        return " ".join(diffs)

    def _is_control_flow(self, asm):
        if not asm: return False
        opcode = asm.split()[0].lower()
        return opcode.startswith('j') or opcode.startswith('call') or opcode.startswith('ret') or opcode in ['loop', 'loope', 'loopne', 'syscall', 'sysenter', 'int']

    def _categorize_ea(self, ea, regs):
        # Heuristic to classify EA
        # regs definition: EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP
        if ea == 0: return ""
        
        esp = regs[6]
        ebp = regs[7]
        
        # Stack check (within 4KB of ESP/EBP)
        if (esp - 0x1000 <= ea <= esp + 0x1000) or (ebp - 0x1000 <= ea <= ebp + 0x1000):
            offset = (int(ea) - int(ebp)) if ebp != 0 else (int(ea) - int(esp))
            sign = "+" if offset >= 0 else "-"
            return f"STACK{sign}0x{abs(offset):x}"
            
        # Image check (simple heuristic: if we have meta for it, it's likely image code/data)
        # But data might be in .data section which we might not have exact meta for?
        # Let's rely on Image ranges if possible. We don't have ranges loaded.
        # Fallback: Check 0x400000 range or known DLLs?
        # Better: check if near EIP? No, data is far.
        
        # Just return "HEAP" or global address
        # We can perform page bucketing as suggested
        page = (ea >> 12) << 12
        return f"MEM_{page:x}"

    def _analyze_block_type(self, lines, entries=None):
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
            
            # Optimization: check short patterns first, now up to 200 (was 64)
            for pat_len in range(1, min(200, (n - i) // 2) + 1):
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

    def _get_canonical_rotation(self, sig_tuple):
        # Find lexicographically minimal rotation to handle AA-BB-CC vs BB-CC-AA
        if not sig_tuple: return sig_tuple
        n = len(sig_tuple)
        doubled = sig_tuple + sig_tuple
        best = sig_tuple
        for i in range(1, n):
            candidate = doubled[i : i+n]
            if candidate < best:
                best = candidate
        return best

    def _compress_grammar(self, blocks):
        # RePair-like iterative pair substitution for non-continuous patterns
        # blocks: list of (label, lines)
        if not blocks: return []
        
        # We work with IDs to be fast
        token_list = [b[0] for b in blocks] # just labels
        
        # Map label -> block_data
        block_map = {b[0]: b for b in blocks}
        
        rules = {} # rule_id -> (left, right)
        next_rule_id = 0
        
        MAX_PASSES = 10
        
        for _ in range(MAX_PASSES):
            # 1. Count pairs
            pairs = Counter()
            for i in range(len(token_list) - 1):
                pair = (token_list[i], token_list[i+1])
                pairs[pair] += 1
            
            if not pairs: break
            
            # Find most frequent pair
            best_pair, count = pairs.most_common(1)[0]
            if count < 2: break # No compression possible
            
            # Create new rule
            rule_name = f"SEQ_{next_rule_id:02X}"
            next_rule_id += 1
            rules[rule_name] = best_pair
            
            # Replace in token_list
            new_list = []
            i = 0
            while i < len(token_list):
                if i < len(token_list) - 1 and (token_list[i], token_list[i+1]) == best_pair:
                    new_list.append(rule_name)
                    i += 2
                else:
                    new_list.append(token_list[i])
                    i += 1
            token_list = new_list
            
        # Reconstruct output structure
        # We need to express the rules and the final sequence
        # For simplicity in report, we just return a flattened "Grammar Compressed" structure?
        # Or better: Just replace the compressed segments with a special block type.
        
        # To make it readable for LLM, we can just list the Rules used, then the Sequence.
        
        # Transform final token_list back to structure
        final_structure = []
        for t in token_list:
            if t in rules:
                # This is a rule token (SEQ_XX) - finding definition is tricky if recursive
                # For now, simplistic approach: treat as a special Pattern block
                # Recursive expansion for display?
                final_structure.append({
                    'type': 'sequence',
                    'id': t,
                    'count': 1 # It's a single token now, but represents multiple blocks
                })
            else:
                 final_structure.append({
                    'type': 'block',
                    'data': block_map.get(t, ('?', [])) # fallback
                })
        
        # In a real grammar, we'd output the definitions of SEQ_XX.
        # But for this report, reducing length is key. 
        # We will embed the rule definitions in the report header/footer or just expand them 
        # if they are short?
        
        # Better: Since _compress_blocks is used for detailed view, 
        # let's only use grammar if linear pattern compression failed to reduce significantly?
        # Or just use this as the primary method?
        # The user wants "A,B,C,A,B,D" -> "SEQ_1, C, SEQ_1, D".
        
        # Let's attach the definitions to the first token/meta?
        # For the simplified view, we'll return the token list and let the printer handle definitions.
        
        return final_structure, rules

    # I/O Log Support
    def load_io_log(self, pid, trace_path):
        # Auto-detect _io.log
        io_path = trace_path.replace('_trace.txt', '_io.log')
        if not os.path.exists(io_path):
            return

        try:
            with open(io_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    # Format: tid,apiName,handle,arg2
                    # Example: 1234,WriteFile,1a0,400
                    parts = line.split(',')
                    if len(parts) >= 3:
                        try:
                            tid = int(parts[0])
                            # Handle OS TID confusion: In Pin IO, we logged OS TID.
                            # In Trace, we have Pin TID. 
                            # If Trace TID != OS TID, we have mismatch.
                            # But if we use (pid, tid) they might align if tid is consistent.
                            # Assuming IO log tid matches Trace tid for now?
                            # Re-verify Pintool: OnIoCall uses PIN_GetTid() cast to os_tid?
                            # "UINT32 os_tid = (UINT32)PIN_GetTid();" -> Yes, it returns OS TID on Windows.
                            # In Trace: "IARG_THREAD_ID" returns PIN TID (serial).
                            # MISMATCH!
                            # Pin TID != OS TID.
                            # Trace relies on Pin TID (IARG_THREAD_ID).
                            # IO Log relies on OS TID.
                            # FIX in PARSER: Report Parser cannot map PinTID to OS TID without a mapping table.
                            # PIn Tool should have logged mapping.
                            # Or Pin Tool should have logged IO with Pin TID?
                            # Wait, "PIN_GetTid()" returns PIN-internal TID (0, 1, ...).
                            # "PIN_GetTid(): Get the tool thread identifier."
                            # So it IS Pin TID!
                            # So Trace matches IO log. Good.
                            
                            api = parts[1]
                            handle = parts[2]
                            arg2 = parts[3] if len(parts) > 3 else "0"
                            
                            # Formatted string
                            evt = f"{api}(Handle={handle}, Arg2={arg2})"
                            self.io_data[(pid, tid)].append(evt)
                        except: pass
        except Exception as e:
            print(f"[!] Warning: Failed to parse I/O log: {e}")

    def dump_llm_report(self):
        # I/O already loaded into self.io_data
        io_activity = self.io_data

        # SUSPECT THREAD ANALYSIS
        print("============================================================")
        print("SUMMARY: Suspect Threads (Loops + I/O Correlation)")
        print("============================================================")
        suspect_found = False
        sorted_keys = sorted(self.loops_by_tid.keys())
        
        for key in sorted_keys:
            # key is (pid, tid)
            pid = key[0]
            tid = key[1]
            
            loop_count = len(self.loops_by_tid[key])
            io_count = len(io_activity.get(key, []))
            
            # Criteria: Has Loops AND Has I/O
            if loop_count > 0 and io_count > 0:
                print(f"[*] PID:{pid} TID:{tid}: {loop_count} Loops found | {io_count} I/O Events")
                suspect_found = True
                
        if not suspect_found:
            print("[-] No threads found with BOTH Loops and I/O activity.")
            print("    Check: 1. Is I/O happening in a child process? (Check new multi-process support)")
            print("           2. Are keys matching? (OS TID vs Pin TID)")
        print("============================================================\n")

        # 1. GlobalSeq Validation
        all_ranks = []
        for key in self.loops_by_tid:
            pid = key[0]
            for header in self.loops_by_tid[key]:
                loop = self.loops_by_tid[key][header]
                # min_rank now holds GlobalSeq
                if loop.min_rank != float('inf'):
                    all_ranks.append(loop.min_rank)
        
        if not all_ranks:
            print("WARNING: No loops found to validate GlobalSeq.")
        else:
            zero_count = all_ranks.count(0)
            if len(all_ranks) > 0 and zero_count / len(all_ranks) > 0.95:
                print(f"CRITICAL ERROR: GlobalSeq Validation Failed! {zero_count}/{len(all_ranks)} are 0.")
                print("Check Pin Tool atomic increment logic.")
            
            unique_ranks = set(all_ranks)
            if len(unique_ranks) < 2 and len(all_ranks) > 10:
                 print(f"CRITICAL ERROR: GlobalSeq is static! Unique values: {unique_ranks}")

        # CSV Match Rate Statistics
        if self.loops_csv_data:
            matched_count = 0
            total_checked = 0
            unmatched_samples = []
            
            # Check a sample of loops against CSV
            for key in self.loops_by_tid:
                pid = key[0]
                for header, loop in self.loops_by_tid[key].items():
                    if loop.min_rank == float('inf'): continue
                    
                    csv_key = (pid, loop.min_rank)
                    total_checked += 1
                    if csv_key in self.loops_csv_data:
                        matched_count += 1
                    else:
                        if len(unmatched_samples) < 5:
                           unmatched_samples.append(f"PID:{pid} Seq:{loop.min_rank}")
                           
            if total_checked > 0:
                rate = matched_count / total_checked
                print(f"[*] CSV Match Rate: {rate*100:.1f}% ({matched_count}/{total_checked})")
                if rate < 0.1:
                    print(f"[!] CRITICAL: extremely low CSV match rate.")
                    print(f"    Unmatched Samples: {unmatched_samples}")
                    print(f"    Check if CSV PIDs match Trace PIDs.")
            
            # REMOVED: Duplicate CSV stats block which was redundant and used incorrect tid iteration.
            
        else:
            print("\n" + "!"*60)
            print("!!! ANALYSIS FAILED: Loaded 0 CSV rows (Critical pipeline failure) !!!")
            print("!!! Causes: Pintool crash, file path error, or child process detach !!!")
            print("!"*60 + "\n")

        print("# Loop Analysis Report (Aggregated)")
        print("# Goal: Reconstruct Ransomware Logic (Encryption Loops)")
        print("# Output Format: High-Level Structural & Compressed Flow")
        print("#   - Shows 'Prolog', 'Main Body', 'Epilog' structure")
        print("#   - Summarizes block activities (Calc, Mem, Call)")
        print("")
        
        # 0. Global stats
        sorted_keys = sorted(self.loops_by_tid.keys())
        print(f"# Analysis by Thread (Total Threads: {len(sorted_keys)})")
        # Format keys for display
        display_keys = [f"P{k[0]}:T{k[1]}" for k in sorted_keys]
        print(f"# Threads: {display_keys}")
        print("")

        for key in sorted_keys:
            pid = key[0]
            tid = key[1]
            
            print(f"")
            print(f"############################################################")
            print(f"# Process: {pid} | Thread ID: {tid}")
            
            # Filter loops (Separating Noise vs App)
            loops = self.loops_by_tid[key]
            sorted_headers = sorted(loops.keys(), key=lambda h: loops[h].score, reverse=True)
            
            # [FILTER] Identify Noise
            valid_headers = []
            noise_headers = []
            
            for h in sorted_headers:
                loop = loops[h]
                primary = loop.get_primary_variant()
                if not primary: continue
                
                # Check metrics
                inst_count = len(primary['entries'])
                summary = self._analyze_activity(primary['entries'])
                
                # Rule 1: Int 0x2e / Syscall (System Noise)
                is_syscall = False
                for e in primary['entries']:
                    m = self.meta.get(e['ip'])
                    if m and ('int 0x2e' in m['asm'].lower() or 'syscall' in m['asm'].lower()):
                        is_syscall = True
                        break
                        
                # Rule 2: Weak Loop (Too small & No Memory work)
                is_weak = False
                if inst_count <= 2 and "Mem(R:0/W:0)" in summary and "Call:0" in summary:
                    is_weak = True

                if (is_syscall or is_weak) and not self.show_all:
                    noise_headers.append(h)
                else:
                    valid_headers.append(h)

            print(f"# Loops Captured: {len(valid_headers)} (Filtered {len(noise_headers)} noise loops)")
            
            # Print I/O Activity for this Thread
            if key in io_activity:
                print(f"# I/O Activity ({len(io_activity[key])} events):")
                ios = io_activity[key]
                if len(ios) <= 10:
                    for io in ios: print(f"#   {io}")
                else:
                    for io in ios[:5]: print(f"#   {io}")
                    print(f"#   ... and {len(ios)-5} more events")
                    print(f"#   ... ({len(ios)-10} more) ...")
                    for io in ios[-5:]: print(f"#   {io}")
            else:
                 print(f"# No I/O Activity recorded for this thread.")

            print(f"############################################################")
            
            # 1. Semantic Consolidation (Merge loops with identical logic)
            # Signature = Tuple of Normalized ASM for the primary variant
            consolidated_groups = {} # signature_hash -> { 'loops': [agg], 'prio': max_prio, 'heat': total_heat }
            
            # Definitions for Categorization
            NOISE_IMAGES = ['kernel32', 'wow64', 'ntdll', 'msvcrt', 'rpcrt4', 'combase', 'sechost', 'gdi32', 'user32', 'imm32']
            CRYPTO_IMAGES = ['bcrypt', 'crypt', 'ssl', 'rsa', 'dss', 'sec', 'advapi']
            RUNTIME_IMAGES = ['msvcrt', 'ucrtbase', 'vcruntime', 'mfc', 'atl', 'kernelbase']

            loops_map = loops
            
            # Use Filtered List (valid_headers)
            for header in valid_headers:
                agg = loops_map[header]
                primary = agg.get_primary_variant()
                if not primary: continue
                
                # Generate Semantic Signature (Canonical Rotation)
                sig_list = []
                for e in primary['entries']:
                     m = self.meta.get(e['ip'], {'asm': '?', 'mem_struct': None})
                     sig_list.append(skeletonize_asm(m['asm'], m.get('mem_struct')))
                
                # Trace Truncation Check
                is_trunc = (len(primary['entries']) >= 50000)
                
                # Deterministic Hashing using SHA256
                # hash() is randomized in Python 3.
                
                # Canonicalize (find min rotation) - RESTORED
                if (not is_trunc) and (len(sig_list) >= 64):
                    variant_sig = (tuple(self._get_canonical_rotation(sig_list)), is_trunc)
                else:
                    variant_sig = (tuple(sig_list), is_trunc)
                
                long_sig_str = str(variant_sig[0]).encode('utf-8')
                h_val = hashlib.sha256(long_sig_str).hexdigest() # Full 64 chars for internal safety
                
                # Grouping
                if h_val not in consolidated_groups:
                    consolidated_groups[h_val] = {
                        'loops': [],
                        'prio': 0.0,
                        'heat': 0,
                        'sig': variant_sig[0],
                        'rep_agg': agg, # Initialize Representative
                        'debug_token': None, # Placeholder, set below
                        'activity': None     # Placeholder
                    }
                
                # Check priority/token of current loop to update group if needed
                # (Logic moved below calculator)
                
                group = consolidated_groups[h_val]
                group['loops'].append(agg)
                
                # DebugToken Generation (Refined)
                # Format: HeadHash|TailHash|Len|nBlocks
                skel_str = "\n".join(sig_list)
                head_chunk = "\n".join(sig_list[:128]) # Window 128
                tail_chunk = "\n".join(sig_list[-128:])
                
                head_hash = hashlib.md5(head_chunk.encode('utf-8')).hexdigest()[:8]
                tail_hash = hashlib.md5(tail_chunk.encode('utf-8')).hexdigest()[:8]
                
                # Heuristic block count: jump/call instructions
                n_blocks = 1 + sum(1 for s in sig_list if any(op in s.lower() for op in ['jmp', 'je', 'jne', 'jz', 'jnz', 'call', 'ret']))
                
                debug_token = f"{head_hash}|{tail_hash}|{len(sig_list)}|{n_blocks}"
                
                # Activity Summary (Mem/Call/Calc)
                activity_summary = self._analyze_activity(primary['entries'])

                # P2: Noise Filter for Syscalls (int 0x2e / sysenter) in short loops
                is_syscall_loop = False
                if len(sig_list) <= 3:
                    for s in sig_list:
                        if 'int 0x2e' in s or 'sysenter' in s or 'syscall' in s:
                            is_syscall_loop = True
                            break

                # Classification (calc priority)
                m_head = self.meta.get(agg.header)
                if (not m_head) or (not m_head.get('img')) or (m_head.get('img') == '?'):
                     if primary and primary['entries']:
                         m_head = self.meta.get(primary['entries'][0]['ip'], {'func':'?', 'img':'?', 'asm':'?'})
                     else:
                         m_head = {'func':'?', 'img':'?', 'asm':'?'}

                img_lower = m_head['img'].lower()
                is_noise = any(noise in img_lower for noise in NOISE_IMAGES)
                is_crypto = any(c in img_lower for c in CRYPTO_IMAGES)
                is_exe = ".exe" in img_lower
                func_lower = m_head.get('func', '').lower()
                # is_io = any(io.lower() in func_lower for io in IO_WHITELIST)
                is_shellcode = (img_lower == '?' or img_lower == '' or 'unmapped' in img_lower)

                priority = 2
                
                # Priority 3 Improvement: Name Shellcode Regions
                if is_shellcode:
                     # Bucket by 64KB page
                     # Address format: 0x12345678 -> MEM_1234
                     page_mask = (agg.header >> 16)
                     region_name = f"MEM_{page_mask:x}xxxx"
                     # Inject into image name for report clarity
                     img_lower = region_name
                     m_head['img'] = region_name # Update meta view
                     
                if is_syscall_loop: priority = 1 # Downrank syscall noise explicitly
                if is_noise: priority = 1
                if is_trunc: priority = 3 # Truncated -> Potentially Main Loop
                if is_crypto or is_exe or is_shellcode: priority = 3
                
                heat = agg.invocations * len(primary['entries'])
                
                # [CLEANUP] Redundant logic removed. 
                # Group is already initialized and agg appended at lines 1177/1192.
                # We simply update the existing 'group' variable with calculated stats.
                group = consolidated_groups[h_val]
                
                if priority > group['prio']: group['prio'] = priority
                if agg.invocations > group['rep_agg'].invocations:
                    group['rep_agg'] = agg
                    # Update representative token/activity as well
                    group['debug_token'] = debug_token
                    group['activity'] = activity_summary
                elif group['debug_token'] is None:
                     # First entry initialization
                     group['debug_token'] = debug_token
                     group['activity'] = activity_summary
                
                group['heat'] += heat

            # 2. Sort Groups
            # 2. Sort Groups for Fuzzy Merging Candidates
            sorted_groups = []
            for sig, data in consolidated_groups.items():
                sorted_groups.append(data)
                
            sorted_groups.sort(key=lambda x: (x['prio'], x['heat']), reverse=True)
            
            # [NEW] Fuzzy Merge Logic (Auto-Consolidate Similar Loops)
            # Threshold: 0.8 Jaccard Similarity on 4-grams
            
            # Helper to get ngrams
            def get_ngrams(group):
                if 'ngrams' in group: return group['ngrams']
                primary = group['rep_agg'].get_primary_variant()
                if not primary: return set()
                skel_list = []
                for e in primary['entries']:
                     m = self.meta.get(e['ip'], {'asm': '?', 'mem_struct': None})
                     skel_list.append(skeletonize_asm(m['asm'], m.get('mem_struct')))
                ngrams = set()
                if len(skel_list) < 4:
                    ngrams.add(tuple(skel_list))
                else:
                    for i in range(len(skel_list) - 3):
                        ngrams.add(tuple(skel_list[i:i+4]))
                group['ngrams'] = ngrams
                return ngrams

            final_groups = []
            merged_indices = set()
            
            for i in range(len(sorted_groups)):
                if i in merged_indices: continue
                
                base_group = sorted_groups[i]
                final_groups.append(base_group)
                base_ngrams = get_ngrams(base_group)
                
                # Check subsequent groups for merge
                for j in range(i + 1, len(sorted_groups)):
                    if j in merged_indices: continue
                    
                    candidate = sorted_groups[j]
                    
                    # Optimization: Skip if priority differs (Noise shouldn't merge with App)
                    if candidate['prio'] != base_group['prio']: continue
                    
                    # Optimization: Skip if Image differs significantly (optional)
                    # For now, allow merging if structure is identical regardless of DLL?
                    # No, strict on Header Image to avoid merging generic library code?
                    # Actually user complained about "Same logical loop".
                    # Let's enforce strict Image match for safety.
                    h1 = self.meta.get(base_group['rep_agg'].header)
                    h2 = self.meta.get(candidate['rep_agg'].header)
                    img1 = h1['img'] if h1 else '?'
                    img2 = h2['img'] if h2 else '?'
                    if img1 != img2: continue

                    # Compare
                    cand_ngrams = get_ngrams(candidate)
                    if not base_ngrams or not cand_ngrams: continue
                    
                    intersection = len(base_ngrams.intersection(cand_ngrams))
                    union = len(base_ngrams.union(cand_ngrams))
                    sim = intersection / union if union > 0 else 0
                    
                    if sim >= 0.8:
                        # MERGE!
                        # 1. Add candidate loops to base
                        base_group['loops'].extend(candidate['loops'])
                        base_group['heat'] += candidate['heat']
                        # 2. Update rep if candidate is bigger? No, keep base (higher rank)
                        # 3. Mark processed
                        merged_indices.add(j)
                        # print(f"DEBUG: Merged {candidate['rep_agg'].header:x} into {base_group['rep_agg'].header:x} (Sim: {sim:.2f})")
            
            sorted_groups = final_groups
            # Re-sort after merge
            sorted_groups.sort(key=lambda x: (x['prio'], x['heat']), reverse=True)
        
            # Summary: Categorized Views
            app_groups = []
            crypto_groups = []  # View B1
            runtime_groups = [] # View B2
            trunc_groups = []
            noise_groups = []
            
            for group in sorted_groups:
                agg = group['rep_agg']
                primary = agg.get_primary_variant()
                inst_count = len(primary['entries'])
                
                # Check Truncated
                if inst_count >= 50000:
                    trunc_groups.append(group)
                    continue
                
                # Check Priority
                prio = group['prio']
                if prio == 1:
                    noise_groups.append(group)
                    continue
                
                # Check Image Type
                m_head = self.meta.get(agg.header, {'img':'?'})
                img = m_head['img'].lower()
                
                is_crypto = any(c in img for c in CRYPTO_IMAGES)
                is_runtime = any(c in img for c in RUNTIME_IMAGES)
                is_exe = ".exe" in img
                is_shellcode = (img == '?' or img == '' or 'unmapped' in img)
                
                if is_exe or is_shellcode:
                    app_groups.append(group)
                elif is_crypto:
                    crypto_groups.append(group)
                elif is_runtime:
                    runtime_groups.append(group)
                else:
                    runtime_groups.append(group) # Fallback

            def print_table(title, g_list):
                if not g_list: return
                print(f"\n### {title}")
                print("| Rank | GlobalSeq | Header | Image | Function | Execs | Insts | Activity | DebugToken (Head|SkelLen|BodyLen) |")
                print("|---|---|---|---|---|---|---|---|---|")
                
                g_list.sort(key=lambda x: (x['prio'], x['heat']), reverse=True)
                
                for i, group in enumerate(g_list):
                     agg = group['rep_agg']
                     primary = agg.get_primary_variant()
                     m_h = self.meta.get(agg.header, {'func':'?', 'img':'?', 'asm':'?'})
                     
                     func = m_h['func'][:20] + ".." if len(m_h['func']) > 20 else m_h['func']
                     img = m_h['img']
                     invocations = sum(l.invocations for l in group['loops'])
                     
                     # Merge CSV stats
                     total_iters_csv = 0
                     has_csv = False
                     for l in group['loops']:
                         # Extract PID from tids (set of (pid, tid))
                         pid = list(l.tids)[0][0]
                         for v in l.variants:
                             rk = v.get('rank')
                             if rk is not None:
                                 if (pid, rk) in self.loops_csv_data:
                                     total_iters_csv += self.loops_csv_data[(pid, rk)]
                                     has_csv = True
                                 
                     if has_csv:
                         invocations = f"{total_iters_csv} ({invocations})"
                     else:
                         # Fallback to LOOP_FINISH counts
                         finish_iters = self.loop_finish_counts.get(agg.header, 0)
                         if finish_iters > 0:
                             invocations = f"{finish_iters} (Trace)"
                     insts = len(primary['entries'])
                     
                     # Activity: Escape pipes for Markdown
                     activity = group.get('activity', '-').replace('|', ',')
                     
                     # Global Rank
                     rank_val = getattr(agg, 'globalSeq', '?')
                     if rank_val == '?': rank_val = getattr(agg, 'min_rank', '?')
                     
                     # Debug Token Enhanced
                     m_1 = self.meta.get(primary['entries'][0]['ip'], {'asm':'?', 'mem_struct':None})
                     head_skel = skeletonize_asm(m_1['asm'], m_1.get('mem_struct'))[:32].replace('|','!').replace(' ','').replace('[','(').replace(']',')')
                     
                     # SkelLen
                     sig_len = len(primary['entries'])
                     if 'sig' in group:
                         sig_len = len(group['sig'])
                     
                     debug_tok = f"`{head_skel},{sig_len},{insts}`"
                     
                     print(f"| {i+1} | {rank_val} | {agg.header:x} | {img} | {func} | {invocations} | {insts} | {activity} | {debug_tok} |")

            print("## Summary of Detected Loops (Categorized Views)")
            
            if app_groups:
                print_table("View A: App & Unmapped Code (Primary Analysis Targets)", app_groups)
            else:
                print("\n>> No App/Unmapped loops found.")

            if crypto_groups:
                print_table("View B1: Crypto Library Operations", crypto_groups)
                
            if runtime_groups:
                print_table("View B2: Runtime/System Library Operations", runtime_groups)
            
            if trunc_groups:
                print_table("View C: Truncated / Long-Running Loops (Potential False Positives or Main Loops)", trunc_groups)
            
            if noise_groups:
                 print_table("View D: All Detected Low-Priority / System Loops (Full List)", noise_groups)

        

            





        
            print("\n" + "="*60 + "\n")
        
            # 3. Similarity Cluster Analysis (Candidate Loop Families)
            # Find groups that are structurally similar (Jaccard > 0.75 on 4-grams) but not merged
        
            print("## Candidate Similar Loop Groups (Unmerged)")
            print("Scans for high-similarity groups that semantic merging missed (Refinement Suggestions)")
            print("")
        
            # Create fingerprints for ranking groups (Skip Low Priority)
            # Fingerprint = set of 4-grams of skeletonized ASM
            group_fingerprints = []
            for idx, group in enumerate(sorted_groups):
                if group['prio'] == 1: continue # Skip noise
            
                primary = group['rep_agg'].get_primary_variant()
                if not primary: continue
            
                # Extract Skeletonized ASM List
                skel_list = []
                for e in primary['entries']:
                     m = self.meta.get(e['ip'], {'asm': '?', 'mem_struct': None})
                     skel_list.append(skeletonize_asm(m['asm'], m.get('mem_struct')))
            
                # Generate 4-grams
                ngrams = set()
                if len(skel_list) < 4:
                    ngrams.add(tuple(skel_list)) # Short loop fallback
                else:
                    for i in range(len(skel_list) - 3):
                        ngrams.add(tuple(skel_list[i:i+4]))
            
                group_fingerprints.append({
                    'idx': idx,
                    'header': group['rep_agg'].header,
                    'ngrams': ngrams,
                    'skel_len': len(skel_list)
                })
            
            # Compare Pairs (Naive O(N^2) but N is small (<100))
            similarity_found = False
        
            # Sort by Header to stabilize output
            group_fingerprints.sort(key=lambda x: x['header'])
        
            printed_pairs = set()
        
            for i in range(len(group_fingerprints)):
                for j in range(i + 1, len(group_fingerprints)):
                    g1 = group_fingerprints[i]
                    g2 = group_fingerprints[j]
                
                    # Jaccard Sim
                    set1 = g1['ngrams']
                    set2 = g2['ngrams']
                
                    if not set1 or not set2: continue
                
                    intersection = len(set1.intersection(set2))
                    union = len(set1.union(set2))
                    jaccard = intersection / union if union > 0 else 0
                
                    if jaccard >= 0.75: # High similarity threshold
                        similarity_found = True
                        # Check if already printed inverse? (loop structure prevents it)
                        print(f"- **Sim {jaccard:.2f}**: {g1['header']:x} <-> {g2['header']:x}")
                        print(f"  - Lengths: {g1['skel_len']} vs {g2['skel_len']} (blocks)")
                        # Maybe print a sample diff?
                    
            if not similarity_found:
                 print("(No additional close candidates found.)")

            print("\n" + "="*60 + "\n")

            # 4. Detailed View
            
            rank_counter = 0

            for group in sorted_groups:
                prio = group['prio']
                agg = group['rep_agg']
            
                # Skip noise in detailed view unless it's explicitly requested (optional future flag)
                # For now, we skip Priority 1 (Noise) to keep the report clean as requested
                if prio == 1 and not self.show_all: continue
                
                rank_counter += 1
            
                primary = agg.get_primary_variant()
                if not primary: continue
            
                m_head = self.meta.get(agg.header)
                if (not m_head) or (not m_head.get('img')) or (m_head.get('img') == '?'):
                     # Fallback
                     if primary and primary['entries']:
                         m_head = self.meta.get(primary['entries'][0]['ip'], {'func':'?', 'img':'?', 'asm':'?'})
                     else:
                         m_head = {'func':'?', 'img':'?', 'asm':'?'}
            
                # TID Summary (Merged)
                all_tids = set()
                for l in group['loops']:
                    all_tids.update(l.tids)
                tid_list = sorted(list(all_tids))
                tid_str = ",".join(map(str, tid_list))
                if len(tid_list) > 5: tid_str = f"{tid_list[:5]}... (Total {len(tid_list)})"

                # Executions (Merged)
                total_invocations = sum(l.invocations for l in group['loops'])
            
                # Header list
                headers = sorted([l.header for l in group['loops']])
                header_str = f"{headers[0]:x}"
                if len(headers) > 1:
                    chunk = headers[:5]
                    header_str = ", ".join([f"{h:x}" for h in chunk])
                    if len(headers) > 5: header_str += f"... (+{len(headers)-5} more)"
            
                # Use 'text' or 'asm' fence but ensure it's closed?
                # Or just indented block without triple backticks to avoid nesting issues.
                # User specifically noted broken ``` fences.
                # Let's use indented text block for safety.
                total_iters = 0
                has_csv_info = False
                
                # Check CSV stats
                if self.loops_csv_data:
                     # Sum iterations for all variants in this group
                     for loop in group['loops']: # AggregatedLoop
                         pid = list(loop.tids)[0][0]
                         for v in loop.variants:
                             rank = v.get('rank')
                             if rank is not None and (pid, rank) in self.loops_csv_data:
                                  total_iters += self.loops_csv_data[(pid, rank)]
                                  has_csv_info = True

                print("```text")
                print(f"Loop Group Rank #{rank_counter} (Merged {len(group['loops'])} loops)")
                print(f"Header: {header_str}")
                print(f"Location: {m_head['img']} ! {m_head['func']}")
                
                # Metric Display Split
                if has_csv_info:
                     print(f"Execs(Cap): {total_invocations} | Iters(Tot): {total_iters}")
                else:
                     print(f"Executions: {total_invocations} (No CSV Iters data)")
                     
                # Structure Hash (SHA256 for stability)
                struct_hash = hashlib.sha256(str(group['sig']).encode('utf-8')).hexdigest()[:16]
                print(f"Structure: {len(primary['entries'])} instructions (Skeleton Hash: {struct_hash})")
                print(f"Activity: {group.get('activity', 'N/A')}")
                print("```")
            
                # Print Structure
                # We want to print normalized body
            
                # High level summary logic
                # ...
                # 1. Compress
            
                entries = primary['entries']
                linear_blocks = []
            
                # Pre-grouping for detailed view
                current_block_lines = []
                current_block_sig = []
                current_mems = set()
            
                # We need to map Instructions -> Block Labels
                # ... (Existing Block Logic)
            
                # Deduplication Cache: tuple(normalized_sig) -> label
                block_cache = {}
                next_block_id = 0
            
                # Label Statistics: label -> { 'mem_addrs': set() }
                label_stats = defaultdict(lambda: {'mem_addrs': set()})
 
                def get_block_label(sig_list, mems):
                    nonlocal next_block_id
                    t = tuple(sig_list)
                
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
            
                current_mems = []

                for index, e in enumerate(entries):
                    ip = e['ip']
                    m = self.meta.get(ip, {'asm': '?', 'func': '?'})
                    asm = m['asm']
                
                    mem_info = ""
                    if e['mem'] != 0:
                        # Use categorize_ea
                        cat_mem = self._categorize_ea(e['mem'], e['regs'])
                        mem_info = f"  ; Mem: {e['mem']:x} ({cat_mem})"
                        current_mems.append(e['mem'])
                
                    line = f"  {ip:x}: {asm:<40}{mem_info}"
                    current_block_lines.append(line)
                    current_block_sig.append(normalize_asm(asm))
                
                    # If control flow, finish block
                    if self._is_control_flow(asm) and index < len(entries) - 1:
                         lbl = get_block_label(current_block_sig, current_mems)
                         linear_blocks.append((lbl, current_block_lines))
                         current_block_lines = []
                         current_block_sig = []
                         current_mems = []
            
                if current_block_lines:
                    lbl = get_block_label(current_block_sig, current_mems)
                    linear_blocks.append((lbl, current_block_lines))
                
                # 2. Compress patterns
                # Two-pass compression: Linear vs Grammar
                compressed_linear = self._compress_blocks(linear_blocks)
            
                # Try Grammar (RePair-like)
                compressed_grammar, rules = self._compress_grammar(linear_blocks)
            
                # Heuristic: Prefer Grammar if it provides ANY better compression than Linear
                # (ignoring rule defs size for now as they are printed once)
                len_linear = len(compressed_linear)
                len_grammar = len(compressed_grammar)
            
                final_compressed = compressed_linear
                used_grammar = False
            
                if len_grammar < len_linear: 
                    final_compressed = compressed_grammar
                    used_grammar = True
            
                # Print Rules if used
                if used_grammar and rules:
                    print("  [Grammar Rules Definitions]")
                
                    # Recursive length helper
                    def _calc_rule_len(token):
                        if token in rules:
                            l, r = rules[token]
                            return _calc_rule_len(l) + _calc_rule_len(r)
                        return 1

                    for rid, pair in rules.items():
                        expanded_len = _calc_rule_len(rid)
                        print(f"    {rid} = {pair[0]} + {pair[1]}  (ExpandLen: {expanded_len})")
                    print("")
                
                print(f"  [High-Level Structure: {len(final_compressed)} items (Orig: {len(linear_blocks)} blocks)]")
            
                for item in final_compressed:
                    if item['type'] == 'sequence':
                        # Grammar Token
                        print(f"    -> [ SEQUENCE {item['id']} ]")
                    
                    elif item['type'] == 'pattern':
                        pat_len = len(item['blocks'])
                        reps = item['count']
                        print(f"    -> REPEATING PATTERN [ x {reps} ]")
                        # Print first iteration of pattern
                        for sub_b in item['blocks']:
                             lbl = sub_b[0]
                             mem_stats = ""
                             if label_stats[lbl]['mem_addrs']:
                                 uni_mem = len(label_stats[lbl]['mem_addrs'])
                                 mem_stats = f" (UniMem: {uni_mem})"
                             print(f"       {lbl}{mem_stats}")
                             lines = sub_b[1]
                             for l in lines: print(f"         {l.strip()}")
                        print(f"       ... (Repeats {reps} times)")

                    else:
                        # Single block
                        b_data = item['data']
                        lbl = b_data[0]
                        lines = b_data[1]
                    
                        mem_stats = ""
                        if label_stats[lbl]['mem_addrs']:
                             uni_mem = len(label_stats[lbl]['mem_addrs'])
                             mem_stats = f" (UniMem: {uni_mem})"

                        print(f"    -> BLOCK {lbl}{mem_stats}")
                        for l in lines:
                            # Normalize Mem: <addr> if possible
                            # If label_stats has multiple mems, try to analyze stride
                            norm_line = l.strip()
                            mems = sorted(list(label_stats[lbl]['mem_addrs']))
                            if len(mems) > 1:
                                # Simple stride check
                                strides = [mems[i+1]-mems[i] for i in range(len(mems)-1)]
                                if len(set(strides)) == 1:
                                    stride = strides[0]
                                    base = mems[0]
                                    # Create symbolic representation
                                    # P0: STRICT SCALE CHECK
                                    if stride in (1, 2, 4, 8):
                                        if stride == 4:
                                            pat = f"[Base + idx*4] (Base={base:x})"
                                        elif stride == 1:
                                            pat = f"[Base + idx] (Base={base:x})"
                                        else:
                                            pat = f"[Base + idx*{stride}] (Base={base:x})"
                                    else:
                                        # Weird stride -> Mask it
                                        pat = f"[Base + idx*<S>]"
                                        
                                    # Replace concrete address in line with pattern
                                    # Line format: "  addr: asm ... ; Mem: <hex>"
                                    if "; Mem:" in norm_line:
                                        pre, post = norm_line.split("; Mem:", 1)
                                        norm_line = f"{pre}; Mem: {pat}"
                                else:
                                    if "; Mem:" in norm_line:
                                        pre, post = norm_line.split("; Mem:", 1)
                                        norm_line = f"{pre}; Mem: [Var: {len(mems)} addrs]"
                            
                            print(f"       {norm_line}")
            
                print("```")
                print("\n---\n")

import sys # Added import for sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--loops", help="Path to _loops.csv") # New
    parser.add_argument("--output", help="Path to output report file (e.g., report.txt)") # New
    parser.add_argument("--llm", action="store_true") # Default action for now
    parser.add_argument("--full", action="store_true") # Ignored in this specialized version
    parser.add_argument("--all", action="store_true", help="Show all loops including system noise")
    
    args = parser.parse_args()
    
    # redirect stdout if output file provided
    if args.output:
        sys.stdout = open(args.output, 'w', encoding='utf-8')

    import glob
    
    # 1. Expand Glob / Auto-detect multiple traces (e.g. Parent/Child)
    trace_files = []
    if '*' in args.trace or '?' in args.trace:
        trace_files = glob.glob(args.trace)
    elif os.path.isfile(args.trace):
        trace_files = [args.trace]
    else:
        # User provided prefix? e.g. "wc_all"
        # Try to find all patterns
        candidates = glob.glob(args.trace + "*_trace.txt")
        if candidates:
            trace_files = candidates
        else:
            # Maybe it is a full path without extension?
            if os.path.exists(args.trace + "_trace.txt"):
                 trace_files = [args.trace + "_trace.txt"]
            else:
                 print(f"[!] Could not find any trace files matching: {args.trace}")
                 return

    print(f"[*] Found {len(trace_files)} trace files to analyze: {trace_files}")

    tp = TraceParser() # No args, load explicitly later
    
    for t_path in trace_files:
        # Derive PID from filename if possible? "..._P1234_trace.txt"
        pid = 0
        p_match = re.search(r'_P(\d+)_trace\.txt$', t_path)
        if p_match:
            pid = int(p_match.group(1))
        
        # Derive other paths
        base = t_path.replace("_trace.txt", "")
        meta_path = base + "_meta.txt"
        csv_path = base + "_loops.csv"
        
        if args.meta and len(trace_files) == 1: meta_path = args.meta
        if args.loops and len(trace_files) == 1: csv_path = args.loops
        
        tp.load_session(pid, t_path, meta_path, csv_path)

    tp.dump_llm_report()
    
    if args.output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__ # Restore

if __name__ == "__main__":
    main()

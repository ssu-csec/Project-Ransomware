import struct
import re
import csv
import os
import sys
import argparse
import hashlib
import glob
from collections import defaultdict, Counter
from datetime import datetime

HEX_ADDR = re.compile(r'0x[0-9a-fA-F]+')
DEC_NUM  = re.compile(r'\b\d+\b')

SIZE_PTR = re.compile(r'\b(byte|word|dword|qword|xmmword)\s+ptr\b', re.IGNORECASE)

SEG_BRACKET_MEM = re.compile(r'\b([a-z]{2}:\[[^\]]+\])', re.I)
STACK_MEM = re.compile(r'\[(esp|ebp)([\+\-][0-9a-fx]+)?\]', re.I)
BRACKET_MEM = re.compile(r'\[([^\]]+)\]')

STACK_MEM = re.compile(
    r'\[(?:ebp|esp)(?:\s*[\+\-]\s*(?:0x[0-9a-fA-F]+|\d+|<addr>|<imm>))?\]',
    re.IGNORECASE
)

KNOWN_SYSTEM_DLLS = ["kernel32.dll", "ntdll.dll", "kernelbase.dll", "user32.dll", "msvcrt.dll", "ucrtbase.dll", "rpcrt4.dll", "combase.dll", "gdi32.dll", "shell32.dll", "cmd.exe", "wevtutil.exe", "win32u.dll", "shlwapi.dll", "ws2_32.dll", "ole32.dll", "sechost.dll", "version.dll"]
KNOWN_CRYPTO_DLLS = ["bcrypt.dll", "crypt32.dll", "advapi32.dll", "rsaenh.dll", "cryptbase.dll", "bcryptprimitives.dll", "cryptsp.dll", "ncrypt.dll", "gdi32full.dll", "msvcp_win.dll"]

def normalize_asm(asm: str, mem_struct: dict = None) -> str:
    s = asm.strip().strip('"').lower()
    if mem_struct:
        base = mem_struct['base'].lower()
        idx = mem_struct['idx'].lower()
        scale_raw = int(mem_struct['scale'])
        scale_token = str(scale_raw)
        if scale_raw not in (1, 2, 4, 8):
            scale_token = "<S>" 
            scale = 1 
        else:
            scale = scale_raw 

        disp_val = 0
        try: disp_val = int(mem_struct['disp'], 0)
        except: pass
        
        token = ""
        if base in ('esp', 'ebp'):
            sign = "+" if disp_val >= 0 else "-"
            token = f"STACK[var{sign}0x{abs(disp_val):x}]"
        elif scale > 1 and idx:
            token = "TABLE[idx]"
        elif scale == 1 and idx:
            token = "BUF[pos]"
        else:
            parts = []
            if base: parts.append("BASE")
            if idx:
                s_str = f"*{scale_token}" if scale_token != '1' else ""
                parts.append(f"IDX{s_str}")
            if disp_val != 0: parts.append("DISP") 
            if not parts: token = "MEM[GLB]"
            else: token = "MEM[" + "+".join(parts) + "]"
        
        s = re.sub(r'\[[^\]]+\]', token, s, count=1)
        s = re.sub(r'0x[0-9a-fA-F]+', '<imm>', s)
        s = DEC_NUM.sub('<imm>', s)
        s = SIZE_PTR.sub('ptr', s)
        s = re.sub(r'\s+', ' ', s).strip()
        return s

    s = SIZE_PTR.sub('ptr', s)
    def _hex_repl(m):
        val_str = m.group(0)
        try: return '<imm>' if int(val_str, 16) < 0x10000 else '<addr>'
        except: return '<addr>'

    def _seg_repl(m):
        return f'{m.group(1).upper()}:SEG_MEM'
        
    def _mem_repl(m):
        content = m.group(1).lower()
        has_base = has_idx = has_imm = False
        regs = re.findall(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b', content)
        if len(regs) == 1: has_base = True
        elif len(regs) >= 2: has_base = True; has_idx = True
        if re.search(r'[\+\-]\s*0x[0-9a-f]+', content) or re.search(r'[\+\-]\s*\d+', content):
            has_imm = True
            
        token = "MEM"
        scale_match = re.search(r'\*(\d+)', content)
        if scale_match:
            try:
                if int(scale_match.group(1)) not in (1, 2, 4, 8): pass
            except: pass
        if has_base:
            if has_idx:
                token += "[BASE+IDX"
                if '*' in content: token += "*S"
                token += "+IMM]" if has_imm else "]"
            else:
                token += "[BASE+IMM]" if has_imm else "[BASE]"
        elif has_imm: token += "[IMM]"
        else: token += "[?]"
        return token

    s = SEG_BRACKET_MEM.sub(_seg_repl, s)
    s = STACK_MEM.sub('STACK_MEM', s)
    s = BRACKET_MEM.sub(_mem_repl, s)
    s = re.sub(r'0x[0-9a-fA-F]+', _hex_repl, s)
    s = DEC_NUM.sub('<imm>', s)
    s = re.sub(r'\b(fs|gs):seg_mem\b', lambda m: f"{m.group(1).upper()}:MEM[...]", s, flags=re.I)
    s = s.replace('stack_mem', 'STACK[IDX]')
    return re.sub(r'\s+', ' ', s).strip()

def skeletonize_asm(asm: str, mem_struct: dict = None) -> str:
    s = normalize_asm(asm, mem_struct)
    s = re.sub(r'^inc\b', 'add', s)
    s = re.sub(r'^dec\b', 'sub', s)
    s = re.sub(r'^jnz\b', 'jne', s)
    s = re.sub(r'^jz\b', 'je', s)
    s = re.sub(r'\bptr\s+mem\[idx\]\b', 'MEM[IDX]', s)
    s = re.sub(r'\bptr\s+stack\[idx\]\b', 'STACK[IDX]', s)
    
    regs_found = []
    all_regs_pat = r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip|ax|bx|cx|dx|si|di|sp|bp|al|bl|cl|dl|ah|bh|ch|dh)\b'
    def repl_reg(match):
        r = match.group(1)
        if r not in regs_found: regs_found.append(r)
        return f"REG{regs_found.index(r)}"
    return re.sub(all_regs_pat, repl_reg, s)

MAGIC_LOOP_HEAD = 0x4C4F4F50 

class AggregatedLoop:
    def __init__(self, header, tid):
        self.header = header
        self.tids = set([tid])
        self.invocations = 0
        self.min_rank = 999999999
        self.variants = []
        self.score = 0.0 
        self.parent_header = 0
        self.child_headers = set()
        self.total_insts = 0

    def add_instance(self, backedge, entries, rank=None):
        self.invocations += 1
        self.total_insts += len(entries)
        if rank is not None and rank < self.min_rank:
            self.min_rank = rank
            
        for v in self.variants:
            if v['backedge'] == backedge and len(v['entries']) == len(entries):
                match = True
                for i in range(len(entries)):
                    if v['entries'][i]['ip'] != entries[i]['ip']:
                        match = False; break
                if match:
                    v['count'] += 1
                    if rank is not None and v.get('rank', 999999) > rank: v['rank'] = rank
                    return

        variant = {'backedge': backedge, 'entries': entries, 'count': 1}
        if rank is not None: variant['rank'] = rank
        self.variants.append(variant)

    def get_primary_variant(self):
        if not self.variants: return None
        return max(self.variants, key=lambda x: x['count'])

class TraceParser:
    def __init__(self, show_all=True):
        self.show_all = show_all
        self.report_dir = None
        self.meta = {} 
        self.loops_by_tid = defaultdict(dict) 
        self.loops_csv_data = {}
        self.loop_finish_counts = defaultdict(int)
        self.io_data = defaultdict(list)
        self.main_low = 0
        self.main_high = 0
        self.images = [] 
        self.unique_images = []
        self.timeline = []
        self.io_events = []
        self.global_seq = 0
        
        self.trace_path = ""
        self.first_trace_name = ""
        self.total_trace_size = 0
        self.seen_img = set() 
        self.active_stack = defaultdict(list) 

    def load_session(self, pid, trace_path, meta_path, csv_path):
        print(f"[*] Loading Session PID={pid}: {trace_path}")
        self.trace_path = trace_path
        
        if not self.first_trace_name:
            self.first_trace_name = os.path.basename(trace_path)
            
        if os.path.exists(trace_path):
            self.total_trace_size += os.path.getsize(trace_path)
            
        self.load_meta(meta_path)
        self.load_loops_csv(pid, csv_path)
        self.parse_trace(pid, trace_path)
        self.load_io_log(pid, trace_path)

        for img in self.unique_images:
            if img['name'].lower().endswith('.exe'):
                if self.main_low == 0:
                    try:
                        self.main_low = int(img['base'], 16)
                        self.main_high = int(img['end'], 16)
                    except: pass
                break

    def load_meta(self, meta_path):
        if not os.path.exists(meta_path): return
        try:
            with open(meta_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    if line.startswith('main_low='):
                        try:
                            tokens = line.split()
                            for t in tokens:
                                if t.startswith('main_low='): self.main_low = int(t.split('=')[1], 16)
                                elif t.startswith('main_high='): self.main_high = int(t.split('=')[1], 16)
                        except: pass
                        continue
                    
                    if line.startswith('EXT_META:'):
                        line = line[9:]
                        
                    # [FIX] csv.reader를 사용하여 따옴표 안의 쉼표 보호
                    if ';' in line:
                        parts = line.split(';')
                    else:
                        parts = next(csv.reader([line]))
                        
                    if len(parts) >= 2:
                        try:
                            addr = int(parts[0].strip().replace('EXT_META:', '').replace('\ufeff', '').replace('\x00', ''), 16)
                            if addr in self.meta: continue
                            func, img = "?", "?"
                            asm = parts[1].strip()
                            mem_struct = None
                            if len(parts) >= 4:
                                func = parts[1].strip()
                                img = parts[2].strip()
                                asm = parts[3].strip() # 이제 이 부분에 온전한 어셈블리가 들어감
                                if len(parts) > 4 and '|' in parts[4]:
                                    mp = parts[4].strip().split('|')
                                    if len(mp) >= 4: mem_struct = {'base': mp[0], 'idx': mp[1], 'scale': mp[2], 'disp': mp[3]}
                            else:
                                if self.main_low > 0 and self.main_low <= addr <= self.main_high:
                                    img = "hive.exe"; func = f"sub_{addr:x}"
                            if '.' not in img and img.lower() in ['text', 'code', 'data']: img = '.' + img
                            self.meta[addr] = {'func': func, 'img': img, 'asm': asm, 'mem_struct': mem_struct}
                        except: continue
        except Exception as e: print(f"[!] Meta load error: {e}")

    def load_loops_csv(self, pid, csv_path):
        if not csv_path or not os.path.exists(csv_path): return
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                for row in csv.reader(f):
                    if not row or len(row) < 7: continue
                    try: self.loops_csv_data[(pid, int(row[1]))] = int(row[6])
                    except: pass
        except Exception as e: print(f"[!] Warning: Failed to parse CSV: {e}")

    def _trim_trace(self, entries, expected_img=None):
        depth, valid_count = 0, 0
        for e in entries:
            m = self.meta.get(e['ip'])
            if not m:
                if expected_img: break
                valid_count += 1; continue
            if expected_img and m.get('img') != expected_img: break
            asm_lower = m['asm'].lower()
            if asm_lower.startswith('call'): depth += 1
            elif asm_lower.startswith('ret') or asm_lower.startswith('rep ret'): depth -= 1
            if depth < 0: break
            valid_count += 1
        return entries[:valid_count]

    def _analyze_activity(self, entries):
        mem_r, mem_w, call_count, calc_count, xor_count = 0, 0, 0, 0, 0
        call_targets = Counter()
        calc_ops = {'add', 'sub', 'inc', 'dec', 'mul', 'imul', 'div', 'idiv', 'shl', 'shr', 'rol', 'ror', 'and', 'or', 'xor', 'not', 'neg'}
        
        for e in entries:
            m = self.meta.get(e['ip'])
            if not m: continue
            asm = m['asm'].lower()
            parts = asm.split(None, 1)
            mnemonic = parts[0] if parts else ""
            
            if mnemonic == 'call':
                call_count += 1
                target, ops = None, parts[1] if len(parts) > 1 else ""
                if '[' in ops and e.get('mem', 0) != 0: target = e['mem']
                if not target:
                    match = re.search(r'(0x[0-9a-f]+)', ops)
                    if match:
                        try: target = int(match.group(1), 16)
                        except: pass
                if target:
                    sym = self.meta.get(target, {}).get('func', f"sub_{target:x}")
                    call_targets[sym] += 1
            
            if mnemonic in calc_ops:
                calc_count += 1
                if mnemonic == 'xor': xor_count += 1
                
            if '[' in asm:
                ops = parts[1] if len(parts) > 1 else ""
                op_parts = ops.split(',')
                if len(op_parts) >= 2:
                    if '[' in op_parts[0]: mem_w += 1
                    elif '[' in ops: mem_r += 1
                else:
                    if '[' in ops: mem_w += 1

        summary = f"Mem(R:{mem_r}/W:{mem_w}), Call:{call_count}"
        if call_count > 0 and call_targets:
            summary += f" {{{', '.join([f'{k}:{v}' for k,v in call_targets.most_common(3)])}}}"
        if calc_count > 0: summary += f", Calc:{calc_count}"
        if xor_count > 0: summary += f" (XOR:{xor_count})"
        return summary

    def _store_loop(self, pid, header, tid, backedge, entries, rank):
        header_img = self.meta.get(header, {}).get('img')
        entries = self._trim_trace(entries, header_img)
        if not entries: return
        tid_key = (pid, tid)
        if header not in self.loops_by_tid[tid_key]:
            self.loops_by_tid[tid_key][header] = AggregatedLoop(header, tid_key)
        self.loops_by_tid[tid_key][header].add_instance(backedge, entries, rank)

    def parse_trace(self, pid, trace_path):
        current_tid, current_header, current_backedge, current_rank = 0, 0, 0, 0
        current_entries = []
        in_loop = False

        try:
            with open(trace_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    
                    if line.startswith('EXT_IMG:'):
                        p = line[8:].split(',')
                        if len(p) >= 3:
                            name = os.path.basename(p[0])
                            self.images.append({'name': name, 'path': p[0], 'base': p[1], 'end': p[2]})
                            if name.lower() not in self.seen_img:
                                self.unique_images.append({'name': name, 'path': p[0], 'base': p[1], 'end': p[2]})
                                self.seen_img.add(name.lower())
                        continue

                    # [FIX] csv.reader를 사용하여 따옴표 안의 쉼표 보호
                    elif line.startswith('EXT_META:'):
                        raw = line[9:]
                        try:
                            parts = next(csv.reader([raw]))
                            if len(parts) >= 4:
                                addr = int(parts[0], 16)
                                func = parts[1].strip()
                                img = parts[2].strip()
                                asm = parts[3].strip()
                                mem_struct = None
                                if len(parts) > 4 and '|' in parts[4]:
                                    mp = parts[4].strip().split('|')
                                    if len(mp) >= 4: mem_struct = {'base': mp[0], 'idx': mp[1], 'scale': mp[2], 'disp': mp[3]}
                                if addr not in self.meta:
                                    self.meta[addr] = {'func': func, 'img': img, 'asm': asm, 'mem_struct': mem_struct}
                        except: pass
                        continue
                        
                    elif line.startswith('EXT_CSV:'):
                        raw = line[8:]
                        parts = raw.split(',')
                        if len(parts) >= 10:
                            try:
                                t_pid = pid
                                g_seq = int(parts[1])
                                iters = int(parts[6])
                                self.loops_csv_data[(t_pid, g_seq)] = iters
                            except: pass
                        continue

                    elif line.startswith('LOOP,') or line.startswith('LOOP_ENTER,'):
                        parts = line.split(',')
                        if len(parts) >= 5:
                            if in_loop and current_entries:
                                self._store_loop(pid, current_header, current_tid, current_backedge, current_entries, current_rank)
                            
                            current_tid = int(parts[1])
                            current_header = int(parts[2], 16)
                            current_backedge = int(parts[3], 16)
                            
                            current_rank = 0
                            if len(parts) >= 6:
                                try: current_rank = int(parts[5], 16) if 'x' in parts[5] else int(parts[5])
                                except: pass
                            
                            tid_stack = self.active_stack[current_tid]
                            parent_header = tid_stack[-1] if tid_stack else 0
                            tid_stack.append(current_header)
                            depth = len(tid_stack) - 1
                            
                            tid_key = (pid, current_tid)
                            if current_header not in self.loops_by_tid[tid_key]:
                                self.loops_by_tid[tid_key][current_header] = AggregatedLoop(current_header, tid_key)
                            
                            self.loops_by_tid[tid_key][current_header].parent_header = parent_header
                            if parent_header and parent_header in self.loops_by_tid[tid_key]:
                                self.loops_by_tid[tid_key][parent_header].child_headers.add(current_header)

                            self.global_seq += 1
                            m = self.meta.get(current_header, {'func': 'unknown', 'img': '?'})
                            self.timeline.append({
                                'seq': self.global_seq,
                                'tid': current_tid,
                                'depth': depth,
                                'parent': parent_header,
                                'header': current_header,
                                'type': 'compute',
                                'summary': m['img'] + "!" + m['func']
                            })

                            current_entries = []
                            in_loop = True
                            
                    elif line.startswith('LOOP_FINISH,'):
                        parts = line.split(',')
                        if len(parts) >= 4:
                            try:
                                f_header = int(parts[2], 16) if len(parts) > 2 else int(parts[1], 16)
                                self.loop_finish_counts[(pid, f_header)] += int(parts[-1])
                                
                                tid_stack = self.active_stack[current_tid]
                                if tid_stack:
                                    tid_stack.pop()
                            except: pass
                            
                    elif in_loop and line.startswith(('I,','R,','W,')):
                        parts = line.split(',')
                        if len(parts) >= 3:
                            try:
                                ip, mem_addr = int(parts[1], 16), int(parts[2], 16)
                                regs = [int(r, 16) for r in parts[3:] if r]
                                current_entries.append({'ip': ip, 'mem': mem_addr, 'regs': regs})
                            except: pass

                    elif line.startswith('IO:'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            t_tid = int(parts[0][3:]) if parts[0][3:] else current_tid
                            api_name, handle = parts[1], parts[2] if len(parts)>2 else "0"
                            arg2 = parts[3] if len(parts) > 3 else "0"
                            evt = f"{api_name}(Handle={handle}, Arg2={arg2})"
                            self.io_data[(pid, t_tid)].append(evt)
                            self.io_events.append({'tid': t_tid, 'api': api_name, 'evt': evt})
                            self.global_seq += 1
                            self.timeline.append({'seq': self.global_seq, 'tid': t_tid, 'depth': 0, 'parent': 0, 'header': 0, 'type': 'io', 'summary': evt})

            if in_loop and current_entries:
                self._store_loop(pid, current_header, current_tid, current_backedge, current_entries, current_rank)
        except Exception as e: print(f"[!] Error parsing trace: {e}")

    def _is_control_flow(self, asm):
        if not asm: return False
        opcode = asm.split()[0].lower()
        return opcode.startswith('j') or opcode.startswith('call') or opcode.startswith('ret') or opcode in ['loop', 'loope', 'loopne', 'syscall', 'sysenter', 'int']

    def _categorize_ea(self, ea, regs):
        if ea == 0 or not regs or len(regs) < 8: return "MEM"
        try:
            esp, ebp = regs[6], regs[7]
            if (esp - 0x1000 <= ea <= esp + 0x1000) or (ebp - 0x1000 <= ea <= ebp + 0x1000):
                offset = (int(ea) - int(ebp)) if ebp != 0 else (int(ea) - int(esp))
                return f"STACK{'+' if offset >= 0 else '-'}0x{abs(offset):x}"
        except: pass
        return f"MEM_{(ea >> 12) << 12:x}"

    def _compress_blocks(self, blocks):
        if not blocks: return []
        compressed = []
        n, i = len(blocks), 0
        while i < n:
            best_pat, best_reps = None, 1
            for pat_len in range(1, min(200, (n - i) // 2) + 1):
                pat = blocks[i : i+pat_len]
                reps, curr = 1, i + pat_len
                while curr + pat_len <= n:
                    if all(blocks[curr+k][0] == pat[k][0] for k in range(pat_len)):
                        reps += 1; curr += pat_len
                    else: break
                if reps > 1 and (not best_pat or (pat_len * reps > len(best_pat) * best_reps)):
                    best_pat, best_reps = pat, reps
            if best_pat:
                compressed.append({'type': 'pattern', 'blocks': best_pat, 'count': best_reps})
                i += len(best_pat) * best_reps
            else:
                compressed.append({'type': 'block', 'data': blocks[i]})
                i += 1
        return compressed

    def _get_canonical_rotation(self, sig_tuple):
        if not sig_tuple: return sig_tuple
        n = len(sig_tuple)
        doubled = sig_tuple + sig_tuple
        best = sig_tuple
        for i in range(1, n):
            if doubled[i : i+n] < best: best = doubled[i : i+n]
        return best

    def _compress_grammar(self, blocks):
        if not blocks: return []
        token_list = [b[0] for b in blocks]
        block_map = {b[0]: b for b in blocks}
        rules = {}
        next_rule_id = 0
        for _ in range(10):
            pairs = Counter()
            for i in range(len(token_list) - 1): pairs[(token_list[i], token_list[i+1])] += 1
            if not pairs: break
            best_pair, count = pairs.most_common(1)[0]
            if count < 2: break
            rule_name = f"SEQ_{next_rule_id:02X}"; next_rule_id += 1
            rules[rule_name] = best_pair
            new_list, i = [], 0
            while i < len(token_list):
                if i < len(token_list) - 1 and (token_list[i], token_list[i+1]) == best_pair:
                    new_list.append(rule_name); i += 2
                else: new_list.append(token_list[i]); i += 1
            token_list = new_list
        final_structure = []
        for t in token_list:
            if t in rules: final_structure.append({'type': 'sequence', 'id': t, 'count': 1})
            else: final_structure.append({'type': 'block', 'data': block_map.get(t, ('?', []))})
        return final_structure, rules

    def load_io_log(self, pid, trace_path):
        if not trace_path.endswith('_trace.txt'):
            return

        io_path = trace_path.replace('_trace.txt', '_io.log')
        if not os.path.exists(io_path) or io_path == trace_path: return
        try:
            with open(io_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        tid, api, handle = int(parts[0]), parts[1], parts[2]
                        arg2 = parts[3] if len(parts) > 3 else "0"
                        self.io_data[(pid, tid)].append(f"{api}(Handle={handle}, Arg2={arg2})")
                        self.io_events.append({'tid': tid, 'api': api, 'evt': f"{api}(Handle={handle}, Arg2={arg2})"})
        except Exception as e: print(f"[!] Warning: Failed to parse I/O log: {e}")

    def dump_llm_report(self):
        if not self.report_dir: return

        for header, meta_info in self.meta.items():
            if meta_info['img'] == '?':
                for img_info in self.unique_images:
                    try:
                        b = int(img_info['base'], 16)
                        e = int(img_info['end'], 16)
                        if b <= header <= e:
                            meta_info['img'] = img_info['name']
                            break
                    except: pass

        loops_dir = os.path.join(self.report_dir, "loops")
        time_dir = os.path.join(self.report_dir, "timeline")
        os.makedirs(loops_dir, exist_ok=True)
        os.makedirs(time_dir, exist_ok=True)

        f_summary = open(os.path.join(self.report_dir, "summary.md"), "w", encoding="utf-8")
        def out(msg=""): 
            print(str(msg).encode(sys.stdout.encoding or 'cp949', errors='replace').decode(sys.stdout.encoding or 'cp949'))
            if f_summary: f_summary.write(str(msg) + "\n")

        consolidated_groups = {}
        unified_loops_by_header = {}

        for key in self.loops_by_tid:
            pid, tid = key[0], key[1]
            loops = self.loops_by_tid[key]
            for header, agg in loops.items():
                primary = agg.get_primary_variant()
                if not primary: continue
                
                if self.meta.get(header, {}).get('img') == '?':
                    page_mask = (header >> 16)
                    self.meta[header]['img'] = f"MEM_{page_mask:x}xxxx"

                if header not in unified_loops_by_header:
                    new_agg = AggregatedLoop(header, (pid, tid))
                    new_agg.min_rank = agg.min_rank
                    new_agg.total_insts = agg.total_insts
                    new_agg.invocations = agg.invocations
                    new_agg.parent_header = agg.parent_header
                    new_agg.child_headers.update(agg.child_headers)
                    new_agg.variants = list(agg.variants) 
                    unified_loops_by_header[header] = new_agg
                else:
                    ex_agg = unified_loops_by_header[header]
                    ex_agg.invocations += agg.invocations
                    ex_agg.tids.update(agg.tids)
                    ex_agg.child_headers.update(agg.child_headers)
                    if agg.min_rank < ex_agg.min_rank:
                        ex_agg.min_rank = agg.min_rank

        all_ranking_loops = [] 
        for header, agg in unified_loops_by_header.items():
            primary = agg.get_primary_variant()
            if not primary: continue
            
            act_str = self._analyze_activity(primary['entries'])
            xor_m = re.search(r'XOR:(\d+)', act_str)
            w_m = re.search(r'W:(\d+)', act_str)
            agg.xor_val = int(xor_m.group(1)) if xor_m else 0
            agg.mem_w_val = int(w_m.group(1)) if w_m else 0
            agg.act_str = act_str
            agg.inst_count = len(primary['entries'])
            all_ranking_loops.append(agg)

            sig_list = [skeletonize_asm(self.meta.get(e['ip'], {'asm':'nop'})['asm']) for e in primary['entries']]
            is_trunc = (len(primary['entries']) >= 50000)
            if (not is_trunc) and (len(sig_list) >= 64): variant_sig = (tuple(self._get_canonical_rotation(sig_list)), is_trunc)
            else: variant_sig = (tuple(sig_list), is_trunc)
            h_val = hashlib.sha256(str(variant_sig[0]).encode('utf-8')).hexdigest()
            
            if h_val not in consolidated_groups:
                consolidated_groups[h_val] = {'loops': [], 'prio': 2, 'heat': 0, 'sig': variant_sig[0], 'rep_agg': agg, 'activity': act_str}
            consolidated_groups[h_val]['loops'].append(agg)

        out("# Ransomware Dynamic Analysis Summary\n")
        out(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        file_size_kb = self.total_trace_size // 1024
        trace_name = self.first_trace_name
        if len(self.images) > 0 and trace_name: out(f"**Trace:** `{trace_name}` (and others) ({file_size_kb:,} KB)  ")
        else: out(f"**Trace:** `{trace_name}` ({file_size_kb:,} KB)  ")
            
        out(f"**Tool:** Intel Pin 3.31 + RansomwarePintool (only_main mode)  \n")
        out("---\n")

        out("## 1. Executive Summary\n")
        total_l = len(unified_loops_by_header)
        out(f"- **{total_l} unique loops** captured from the executable")
        out(f"- **{len(self.io_events)} I/O API calls** observed (file system hooks)")
        out(f"- **{len(self.unique_images)} DLLs** loaded")
        total_execs = sum(l.invocations for l in unified_loops_by_header.values())
        out(f"- **{total_execs} loop invocations** total across all threads\n")
        
        target_exe = next((img['path'] for img in self.unique_images if img['name'].lower().endswith('.exe')), "Unknown Target")
        out(f"**Target:** `{target_exe}`  ")
        out(f"**Code range:** `0x{self.main_low:x}` - `0x{self.main_high:x}`\n")
        out("---\n")

        out("## 2. Loaded DLL Inventory\n\n### Known System/API Modules")
        out("| # | DLL | Base | End | Inferred Role |")
        out("|---|-----|------|-----|---------------|")
        unknown_dlls = []
        idx = 1
        for img in self.unique_images:
            name, base, end = img['name'], img['base'], img['end']
            n_lower = name.lower()
            if any(k in n_lower for k in KNOWN_SYSTEM_DLLS + KNOWN_CRYPTO_DLLS):
                if any(c in n_lower for c in KNOWN_CRYPTO_DLLS): role = "🔴 Behavioral Crypto — Cryptographic primitives"
                elif "kernel" in n_lower: role = "Windows API core: process/thread/memory/file management"
                elif "user" in n_lower or "gdi" in n_lower: role = "GUI/window management"
                elif "msvc" in n_lower or "ucrt" in n_lower: role = "C/C++ runtime (malloc/free/sprintf)"
                else: role = "System library"
                out(f"| {idx} | `{name}` | `{base}` | `{end}` | {role} |")
                idx += 1
            else:
                unknown_dlls.append(img)
        
        if unknown_dlls:
            out("\n### ⚠️ Unmapped / Dynamic Modules (Needs LLM Analysis)")
            out("> **LLM Instruction:** The following modules are loaded but not part of standard system definitions. Please analyze their names or associated routines to infer if they are custom drop files, injected payloads, or unconventional libraries used by the ransomware.\n")
            out("| # | DLL | Base | End | Potential Role |")
            out("|---|-----|------|-----|----------------|")
            for i, img in enumerate(unknown_dlls):
                out(f"| {i+1} | `{img['name']}` | `{img['base']}` | `{img['end']}` | Unknown — see address range |")
            with open(os.path.join(self.report_dir, "unknown_dlls.md"), "w", encoding="utf-8") as uf:
                uf.write("# Unknown DLL Analysis Target\n")
                for img in unknown_dlls: uf.write(f"- `{img['name']}` (Base: {img['base']}, End: {img['end']})\n")
        out("\n---\n")

        out("## 3. Loop Hierarchy Tree\n")
        out("> **LLM Note:** 들여쓰기 깊이 = 루프 중첩 레벨. `EXT_CHILD_LOOP` 기반 휴리스틱 트리.")
        out("> 상세 명령어는 `loops/` 디렉토리 내의 개별 파일을 확인하세요.\n")
        out("```")
        def _recursive_print(loops_map, header, prefix, is_last, depth, visited):
            if header in visited: return
            visited.add(header)
            loop = loops_map.get(header)
            if not loop: return
            m = self.meta.get(header, {'img':'?', 'func':'?'})
            img_name = m['img'].split('\\')[-1].lower() if '\\' in m['img'] else m['img'].lower()
            offset_str = ""
            for img_info in self.unique_images:
                if img_info['name'].lower() == img_name:
                    try:
                        base_addr = int(img_info['base'], 16)
                        offset = header - base_addr
                        if offset >= 0: offset_str = f"+0x{offset:x}"
                    except: pass
                    break
            connector = "└── " if is_last else "├── "
            if depth == 0: connector = ""
            out(f"{prefix}{connector}0x{header:x} (`{img_name}`{offset_str})  [rank={loop.min_rank}, inst={loop.total_insts}, depth={depth}]")
            children = sorted(list(loop.child_headers))
            for i, child in enumerate(children):
                is_last_child = (i == len(children) - 1)
                new_prefix = prefix + ("    " if is_last else "│   ") if depth > 0 else ""
                _recursive_print(loops_map, child, new_prefix, is_last_child, depth + 1, visited)
                
        visited_tree = set()
        all_roots = [h for h, l in unified_loops_by_header.items() if l.parent_header == 0]
        all_roots.sort(key=lambda h: unified_loops_by_header[h].min_rank)
        
        for r in all_roots:
            _recursive_print(unified_loops_by_header, r, "", False, 0, visited_tree)
            
        out("```\n\n---\n")

        out("## 4. Measured I/O Activity\n")
        out(f"**Total hooks fired:** {len(self.io_events)}\n")
        out("| API | Calls | Assessment |")
        out("|-----|-------|------------|")
        api_names = [e['api'] for e in self.io_events]
        io_counts = Counter(api_names)
        for api, count in io_counts.most_common():
            if "WriteFile" in api: risk = "⚠️ HIGH — bulk writes (encryption output)"
            elif "NtWrite" in api: risk = "⚠️ HIGH — native write (encryption/ransom note)"
            elif "CreateFile" in api or "Open" in api: risk = "Opens/creates files — potential encryption targets"
            else: risk = "Normal I/O Activity"
            out(f"| `{api}` | {count} | {risk} |")
        out("\n---\n")

        out("## 5. Execution Timeline Index\n")
        out(f"Total {len(self.timeline)} events recorded.\nTimeline is split into chunks in [`timeline/`](./timeline/).\n")
        out("| Chunk | Sequence Range | File Link |")
        out("|-------|----------------|-----------|")
        
        chunk_size = 500
        total_chunks = (len(self.timeline) + chunk_size - 1) // chunk_size
        
        def print_chunk_row(c_idx):
            start_seq = c_idx * chunk_size
            range_end = min(start_seq + chunk_size - 1, len(self.timeline) - 1)
            fname = f"part{c_idx}.md"
            out(f"| Part {c_idx} | {start_seq} - {range_end} | [view](./timeline/{fname}) |")
            
            if time_dir:
                with open(os.path.join(time_dir, fname), "w", encoding="utf-8") as tf:
                    tf.write(f"# Execution Timeline - Part {c_idx}\n\n| Seq | TID | Depth | Parent | Header | Type | Summary |\n|---|---|---|---|---|---|---|\n")
                    for event in self.timeline[start_seq : start_seq+chunk_size]:
                        if event['type'] == 'compute':
                            m_head = self.meta.get(event['header'], {'img':'?'})
                            img_name = m_head['img'].split('\\')[-1].lower() if '\\' in m_head['img'] else m_head['img'].lower()
                            off_str = ""
                            for img_info in self.unique_images:
                                if img_info['name'].lower() == img_name:
                                    try:
                                        b_addr = int(img_info['base'], 16)
                                        off = event['header'] - b_addr
                                        if off >= 0: off_str = f"+0x{off:x}"
                                    except: pass
                                    break
                            head = f"`0x{event['header']:x} ({img_name}{off_str})`"
                        else: head = "-"
                        summary = f"`{event.get('summary','')}`"
                        parent = f"`0x{event.get('parent',0):x}`" if event.get('parent') else "*(root)*"
                        tf.write(f"| {event['seq']} | T{event['tid']} | {event.get('depth',0)} | {parent} | {head} | {event['type']} | {summary} |\n")

        if total_chunks <= 30:
            for i in range(total_chunks): print_chunk_row(i)
        else:
            for i in range(20): print_chunk_row(i)
            out(f"| ... | ... ({total_chunks - 30} chunks hidden) | ... |")
            for i in range(total_chunks - 10, total_chunks): print_chunk_row(i)

        out("\n---\n")

        out("## 6. Captured Loop Bodies Index\n")
        out("| ID | RVA Header | Insts | Iters | Activity | File Link |")
        out("|----|------------|-------|-------|----------|-----------|")
        
        sorted_ranking = sorted(all_ranking_loops, key=lambda x: x.min_rank)
        
        MAX_LOOPS_PRINT = 100 
        for i, l in enumerate(sorted_ranking[:MAX_LOOPS_PRINT]): 
            m = self.meta.get(l.header, {'img':'?'})
            iters_str = str(l.invocations) if l.invocations > 0 else "*(unknown)*"
            img_name = m['img'].split('\\')[-1].lower() if '\\' in m['img'] else m['img'].lower()
            offset_str = ""
            for img_info in self.unique_images:
                if img_info['name'].lower() == img_name:
                    try:
                        base_addr = int(img_info['base'], 16)
                        offset = l.header - base_addr
                        if offset >= 0: offset_str = f"+0x{offset:x}"
                    except: pass
                    break
            rva_display = f"`0x{l.header:x}` (`{img_name}`{offset_str})"
            out(f"| {i+1} | {rva_display} | {l.inst_count} | {iters_str} | {l.act_str} | [view](./loops/loop_0x{l.header:x}.md) |")
        
        if len(sorted_ranking) > MAX_LOOPS_PRINT:
            out(f"| ... | ... ({len(sorted_ranking) - MAX_LOOPS_PRINT} loops hidden) | ... | ... | ... | ... |")
            
        out("\n---\n")

        out("## 7. Analysis Instructions for LLM\n")
        out("Please analyze this dynamic execution trace and answer:\n")
        out("### A. Encryption Algorithm")
        out("- Identify patterns: `XOR` chains, `MOVAPS`/`PXOR` (AES-NI), bit rotation, S-box")
        
        unique_dll_names = sorted(list(set([img['name'].lower() for img in self.unique_images if img['name'].lower().endswith('.dll')])))
        loaded_dlls_str = ", ".join([f"`{n}`" for n in unique_dll_names])
        out(f"- Note {loaded_dlls_str} are loaded (Section 2)\n")
        
        out("### B. Loop Hierarchy Analysis")
        out("---\n")
        out("*Generated by `trace_parser.py` — Ransomware Analysis Pintool Project*")

        f_summary.close()

        import json
        
        # [NEW] Export api_events.json
        api_events = []
        api_category = {
            "ReadFile": "file_io", "WriteFile": "file_io", "CreateFileW": "file_io", "CreateFileA": "file_io", "SetFilePointer": "file_io",
            "CryptEncrypt": "crypto", "CryptDecrypt": "crypto", "CryptAcquireContextW": "crypto", "CryptGenKey": "crypto",
            "FindFirstFileW": "fs_enum", "FindNextFileW": "fs_enum", "CryptExportKey": "crypto", "CryptImportKey": "crypto"
        }
        for item in self.timeline:
            if item['type'] == 'io':
                m = re.match(r'([A-Za-z0-9_]+)\((.*)\)', item.get('summary', ''))
                api_name = m.group(1) if m else item.get('summary', 'unknown')
                args_str = m.group(2) if m else ""
                
                arg_summary = {}
                for p in args_str.split(', '):
                    if '=' in p:
                        k, v = p.split('=', 1)
                        if k == 'Handle': arg_summary['handle_like'] = v
                        else: arg_summary[k] = v
                        
                api_events.append({
                    "event_idx": item['seq'],
                    "timeline_idx": item['seq'],
                    "tid": item['tid'],
                    "api": api_name,
                    "module": "unknown", 
                    "qualified_api": api_name,
                    "caller": "0", 
                    "args": { "raw": args_str },
                    "arg_summary": arg_summary,
                    "category": api_category.get(api_name, "other"),
                    "source_log": "timeline"
                })
        
        try:
            with open(os.path.join(self.report_dir, "api_events.json"), "w", encoding="utf-8") as f:
                json.dump({"version": 1, "events": api_events}, f, indent=2)
        except Exception as e:
            print(f"[!] Error writing api_events JSON: {e}")

        targets = []
        loop_to_tid_seq = {}
        for item in self.timeline:
            if item['type'] == 'compute':
                h = item['header']
                if h not in loop_to_tid_seq:
                    loop_to_tid_seq[h] = (item['tid'], item['seq'])

        for header, agg in unified_loops_by_header.items():
            primary = agg.get_primary_variant()
            if not primary: continue
            
            tid, seq = loop_to_tid_seq.get(header, (0, 0))
            
            # Crypto Suspect
            if agg.xor_val >= 3 or agg.mem_w_val >= 5:
                targets.append({
                    "address": f"0x{header:x}",
                    "reason": "loop_suspect_crypto",
                    "module": self.meta.get(header, {}).get('img', 'unknown'),
                    "loop_id": f"loop_{header:x}",
                    "tid": tid,
                    "timeline_idx": seq
                })
            
            # Indirect calls unresolved
            for e in primary['entries']:
                m = self.meta.get(e['ip'], {})
                asm = m.get('asm', '').lower()
                if asm.startswith('call ') or asm.startswith('jmp '):
                    if 'eax' in asm or 'ebx' in asm or 'ecx' in asm or 'edx' in asm or 'esi' in asm or 'edi' in asm or '[' in asm:
                        targets.append({
                            "address": f"0x{e['ip']:x}",
                            "reason": "indirect_branch_unresolved",
                            "module": m.get('img', 'unknown'),
                            "loop_id": f"loop_{header:x}",
                            "tid": tid,
                            "timeline_idx": seq
                        })

        target_json_path = os.path.join(self.report_dir, "target_cfg_blocks.json")
        try:
            with open(target_json_path, "w", encoding="utf-8") as tj:
                json.dump({"targets": targets}, tj, indent=2)
        except Exception as e:
            print(f"[!] Error writing targets JSON: {e}")

        written_clusters = set()
        for h_val, group in consolidated_groups.items():
            try:
                agg = group['rep_agg']
                cluster_filename = f"cluster_{h_val[:16]}.md"
                if cluster_filename not in written_clusters:
                    with open(os.path.join(loops_dir, cluster_filename), "w", encoding="utf-8", errors='replace') as f_c:
                        m = self.meta.get(agg.header, {})
                        c_img = m.get('img', '?')
                        c_func = m.get('func', '?')
                        img_name = c_img.split('\\')[-1].lower() if '\\' in c_img else c_img.lower()
                        offset_str = ""
                        for img_info in self.unique_images:
                            if img_info['name'].lower() == img_name:
                                try:
                                    base_addr = int(img_info['base'], 16)
                                    offset = agg.header - base_addr
                                    if offset >= 0: offset_str = f"+0x{offset:x}"
                                except: pass
                                break
                                
                        f_c.write(f"# Semantic Loop Cluster: {h_val[:16]}\n\n")
                        f_c.write(f"- **Representative Header:** `0x{agg.header:x} (`{img_name}`{offset_str})` -> `{c_img}` ! `{c_func}`\n")
                        f_c.write(f"- **Total Instances:** {len(group['loops'])}\n")
                        total_iters_cluster = sum(l.invocations for l in group['loops'])
                        f_c.write(f"- **Total Iterations across instances:** {total_iters_cluster if total_iters_cluster > 0 else '*(unknown)*'}\n")
                        f_c.write(f"- **Representative Activity:** {agg.act_str}\n")
                        f_c.write(f"- **Instructions:** {agg.inst_count}\n\n")
                        f_c.write("## 1. Loop Instances\n| Threads | Rank/Seq | RVA Header | Location | Local Iters |\n|--------|----------|------------|----------|-------------|\n")
                        for cl in group['loops']:
                            c_img_inst = self.meta.get(cl.header, {}).get('img', '?')
                            c_img_name = c_img_inst.split('\\')[-1].lower() if '\\' in c_img_inst else c_img_inst.lower()
                            c_offset_str = ""
                            for img_info in self.unique_images:
                                if img_info['name'].lower() == c_img_name:
                                    try:
                                        c_base = int(img_info['base'], 16)
                                        c_off = cl.header - c_base
                                        if c_off >= 0: c_offset_str = f"+0x{c_off:x}"
                                    except: pass
                                    break
                            t_str = ",".join([f"T{t[1]}" for t in cl.tids])
                            if len(cl.tids) > 3: t_str = f"T{list(cl.tids)[0][1]}... ({len(cl.tids)} threads)"
                            f_c.write(f"| {t_str} | {cl.min_rank} | `0x{cl.header:x} (`{c_img_name}`{c_offset_str})` | `{c_img_inst}!{self.meta.get(cl.header, {}).get('func', '?')}` | {cl.invocations if cl.invocations>0 else '*(unknown)*'} |\n")
                        
                        f_c.write("\n## 2. Representative Instruction trace\n\n```\n")
                        f_c.write(f"{'#':<4} {'T':<2} {'ADDR':<40} {'SYMBOL':<70} {'MEM_EA':<15} {'ASM'}\n")
                        f_c.write("-" * 160 + "\n")
                        primary_entries = agg.get_primary_variant()['entries']
                        for i, e in enumerate(primary_entries):
                            m_e = self.meta.get(e['ip'], {})
                            e_img = m_e.get('img', '?')
                            e_func = m_e.get('func', '?')
                            e_asm = m_e.get('asm', '?')
                            e_img_name = e_img.split('\\')[-1].lower() if '\\' in e_img else e_img.lower()
                            e_off_str = ""
                            for img_info in self.unique_images:
                                if img_info['name'].lower() == e_img_name:
                                    try:
                                        e_base = int(img_info['base'], 16)
                                        e_off = e['ip'] - e_base
                                        if e_off >= 0: e_off_str = f"+0x{e_off:x}"
                                    except: pass
                                    break
                            addr_str = f"0x{e['ip']:x} (`{e_img_name}`{e_off_str})"
                            sym_str = f"{e_img}!{e_func}"
                            mem_str = f"0x{e['mem']:x}" if e.get('mem', 0) != 0 else ""
                            f_c.write(f"{i+1:<4} {'I':<2} {addr_str:<40} {sym_str:<70} {mem_str:<15} {e_asm}\n")
                        f_c.write("```\n")
                    written_clusters.add(cluster_filename)
    
                for cl_loop in group['loops']:
                    loop_filename = f"loop_0x{cl_loop.header:x}.md"
                    cl_primary = cl_loop.get_primary_variant()
                    if not cl_primary: continue
                    with open(os.path.join(loops_dir, loop_filename), "w", encoding="utf-8", errors='replace') as f_l:
                        f_l.write(f"# Loop Analysis: 0x{cl_loop.header:x}\n")
                        f_l.write(f"## Metadata\n- **Module**: {self.meta.get(cl_loop.header, {}).get('img', '?')}\n")
                        f_l.write(f"- **Cluster**: [{cluster_filename}](./{cluster_filename})\n\n")
                        f_l.write("## Decompressed Assembly Structure\n")
                        
                        entries = cl_primary['entries']
                        linear_blocks, current_block_lines, current_block_sig, current_mems = [], [], [], []
                        block_cache, next_block_id = {}, 0
                        
                        # Fix nested default dict access in label_stats inside loops
                        class LabelStatDict:
                            def __init__(self): self.d = {}
                            def get_mem(self, k):
                                if k not in self.d: self.d[k] = set()
                                return self.d[k]
                                
                        label_stats = LabelStatDict()
    
                        def get_block_label(sig_list, mems):
                            nonlocal next_block_id
                            t = tuple(sig_list)
                            if t in block_cache: lbl = block_cache[t]
                            else:
                                lbl = f"lbl_{next_block_id:02X}"; block_cache[t] = lbl; next_block_id += 1
                            for m in mems: label_stats.get_mem(lbl).add(m)
                            return lbl
    
                        for index, e in enumerate(entries):
                            ip = e['ip']
                            m_e2 = self.meta.get(ip, {})
                            c_asm2 = m_e2.get('asm', '?')
                            mem_info = f" ; Mem: {e['mem']:x} ({self._categorize_ea(e['mem'], e.get('regs',[]))})" if e.get('mem',0) != 0 else ""
                            if e.get('mem',0) != 0: current_mems.append(e['mem'])
                            current_block_lines.append(f"  {ip:x}: {c_asm2:<40}{mem_info}")
                            current_block_sig.append(normalize_asm(c_asm2))
                            if self._is_control_flow(c_asm2) and index < len(entries) - 1:
                                linear_blocks.append((get_block_label(current_block_sig, current_mems), current_block_lines))
                                current_block_lines, current_block_sig, current_mems = [], [], []
                        if current_block_lines:
                            linear_blocks.append((get_block_label(current_block_sig, current_mems), current_block_lines))
    
                        compressed_linear = self._compress_blocks(linear_blocks)
                        compressed_grammar, rules = self._compress_grammar(linear_blocks)
                        final_compressed = compressed_grammar if len(compressed_grammar) < len(compressed_linear) else compressed_linear
                        
                        if len(compressed_grammar) < len(compressed_linear) and rules:
                            f_l.write("  [Grammar Rules Definitions]\n")
                            def _calc_rule_len(token): return _calc_rule_len(rules[token][0]) + _calc_rule_len(rules[token][1]) if token in rules else 1
                            for rid, pair in rules.items(): f_l.write(f"    {rid} = {pair[0]} + {pair[1]}  (ExpandLen: {_calc_rule_len(rid)})\n")
                            f_l.write("\n")
                        
                        f_l.write(f"  [High-Level Structure: {len(final_compressed)} items]\n```asm\n")
                        for item in final_compressed:
                            if item['type'] == 'sequence': f_l.write(f"    -> [ SEQUENCE {item['id']} ]\n")
                            elif item['type'] == 'pattern':
                                f_l.write(f"    -> REPEATING PATTERN [ x {item['count']} ]\n")
                                for sub_b in item['blocks']:
                                    # Block list is a normal list of lists
                                    b_lbl = sub_b[0]
                                    uni = len(label_stats.get_mem(b_lbl))
                                    f_l.write(f"       {b_lbl}{' (UniMem: '+str(uni)+')' if uni else ''}\n")
                                f_l.write(f"       ... (Repeats {item['count']} times)\n")
                            else:
                                b_data = item['data']
                                lbl, lines = b_data[0], b_data[1]
                                uni = len(label_stats.get_mem(lbl))
                                f_l.write(f"    -> BLOCK {lbl}{' (UniMem: '+str(uni)+')' if uni else ''}\n")
                                for l in lines:
                                    norm_line = l.strip()
                                    mems = sorted(list(label_stats.get_mem(lbl)))
                                    if len(mems) > 1:
                                        strides = [mems[i+1]-mems[i] for i in range(len(mems)-1)]
                                        if len(set(strides)) == 1:
                                            stride = strides[0]
                                            pat = f"[Base + idx*{stride}] (Base={mems[0]:x})" if stride in (1,2,4,8) else f"[Base + idx*<S>]"
                                            if "; Mem:" in norm_line: norm_line = f"{norm_line.split('; Mem:')[0]}; Mem: {pat}"
                                        else:
                                            if "; Mem:" in norm_line: norm_line = f"{norm_line.split('; Mem:')[0]}; Mem: [Var: {len(mems)} addrs]"
                                    f_l.write(f"       {norm_line}\n")
                        f_l.write("```\n")
            except Exception as e:
                import traceback
                print(f"[!] 클러스터 {h_val[:16]} 작성 중 예외 발생: {e}")
                traceback.print_exc()
                continue

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True)
    parser.add_argument("--meta", required=False, help="Legacy meta path (now embedded in trace)")
    parser.add_argument("--loops", help="Path to _loops.csv")
    parser.add_argument("--output", help="Path to output report file")
    parser.add_argument("--report", required=True, help="Directory for the multi-file report")
    parser.add_argument("--llm", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()

    if args.output:
        sys.stdout = open(args.output, 'w', encoding='utf-8')

    tp = TraceParser()
    tp.report_dir = args.report
    os.makedirs(tp.report_dir, exist_ok=True)
    
    trace_files = glob.glob(args.trace)
    for t_path in trace_files:
        pid = 0
        # New pattern: trace_SESSION_PID_SEQ.done or legacy _P[PID]_
        p_match = re.search(r'trace_\d{8}_\d{6}_(\d+)_', t_path)
        if not p_match:
            p_match = re.search(r'trace_.*_(\d+)_\d+\.(?:tmp|done)', t_path)
        if p_match:
            pid = int(p_match.group(1))
        else:
            p_match2 = re.search(r'_P(\d+)', t_path)
            if p_match2: pid = int(p_match2.group(1))
        
        base = t_path.replace("_trace.txt", "").replace(".done", "").replace(".tmp", "")
        meta_path = args.meta if args.meta else base + "_meta.txt"
        csv_path = args.loops if args.loops else base + "_loops.csv"
        
        tp.load_session(pid, t_path, meta_path, csv_path)

    tp.dump_llm_report()
    
    if args.output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

if __name__ == "__main__":
    main()
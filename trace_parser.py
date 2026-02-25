"""
Ransomware Trace Parser + LLM Report Generator
================================================
Usage:
    # Auto-detect all wc_all_P*_trace.txt in current dir:
    python trace_parser.py

    # Explicit trace file + Markdown report:
    python trace_parser.py --trace wc_all_P2680_x86_trace.txt --report report.md

    # Legacy detailed text output to stdout:
    python trace_parser.py --trace wc_all_P2680_x86_trace.txt --llm [--all] [--output out.txt]
"""

import struct
import re
import csv
import os
import sys
import glob
import argparse
import hashlib
import datetime
from collections import defaultdict, Counter

# ─────────────────────────────────────────────────────────────────
# ASM Normalization
# ─────────────────────────────────────────────────────────────────

HEX_ADDR = re.compile(r'0x[0-9a-fA-F]+')
DEC_NUM  = re.compile(r'\b\d+\b')
SIZE_PTR = re.compile(r'\b(byte|word|dword|qword|xmmword)\s+ptr\b', re.IGNORECASE)
SEG_BRACKET_MEM = re.compile(r'\b([a-z]{2}:\[[^\]]+\])', re.I)
STACK_MEM = re.compile(
    r'\[(?:ebp|esp)(?:\s*[\+\-]\s*(?:0x[0-9a-fA-F]+|\d+|<addr>|<imm>))?\]',
    re.IGNORECASE
)
BRACKET_MEM = re.compile(r'\[([^\]]+)\]')


def normalize_asm(asm: str, mem_struct: dict = None) -> str:
    s = asm.strip().strip('"').lower()

    if mem_struct:
        base = mem_struct['base'].lower()
        idx  = mem_struct['idx'].lower()
        scale_raw = int(mem_struct['scale'])
        scale_token = str(scale_raw)
        if scale_raw not in (1, 2, 4, 8):
            scale_token = "<S>"
            scale = 1
        else:
            scale = scale_raw
        disp_val = 0
        try:
            disp_val = int(mem_struct['disp'], 0)
        except Exception:
            pass

        if base in ('esp', 'ebp'):
            sign  = "+" if disp_val >= 0 else "-"
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
            token = "MEM[GLB]" if not parts else "MEM[" + "+".join(parts) + "]"

        s = re.sub(r'\[[^\]]+\]', token, s, count=1)
        s = re.sub(r'0x[0-9a-fA-F]+', '<imm>', s)
        s = DEC_NUM.sub('<imm>', s)
        s = SIZE_PTR.sub('ptr', s)
        return re.sub(r'\s+', ' ', s).strip()

    # Regex-based fallback normalization
    s = SIZE_PTR.sub('ptr', s)

    def _seg_repl(m):
        return f'{m.group(1).upper()}:SEG_MEM'

    def _mem_repl(m):
        content = m.group(1).lower()
        regs = re.findall(r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b', content)
        has_base = len(regs) >= 1
        has_idx  = len(regs) >= 2
        has_imm  = bool(re.search(r'[\+\-]\s*(?:0x[0-9a-f]+|\d+)', content))

        scale_part = ""
        sm = re.search(r'\*(\d+)', content)
        if sm:
            sc = int(sm.group(1))
            scale_part = f"*{sc}" if sc in (1, 2, 4, 8) else "*<S>"

        if has_base:
            if has_idx:
                token = "MEM[BASE+IDX" + scale_part + ("+IMM]" if has_imm else "]")
            else:
                token = "MEM[BASE+IMM]" if has_imm else "MEM[BASE]"
        elif has_imm:
            token = "MEM[IMM]"
        else:
            token = "MEM[?]"
        return token

    s = SEG_BRACKET_MEM.sub(_seg_repl, s)
    s = STACK_MEM.sub('STACK_MEM', s)
    s = BRACKET_MEM.sub(_mem_repl, s)

    def _hex_repl(m):
        try:
            v = int(m.group(0), 16)
            return '<imm>' if v < 0x10000 else '<addr>'
        except Exception:
            return '<addr>'

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
    s = re.sub(r'^jz\b',  'je',  s)
    s = re.sub(r'\bptr\s+mem\[idx\]\b', 'MEM[IDX]', s)
    s = re.sub(r'\bptr\s+stack\[idx\]\b', 'STACK[IDX]', s)

    regs_found = []
    all_regs_pat = (r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|eip'
                    r'|ax|bx|cx|dx|si|di|sp|bp'
                    r'|al|bl|cl|dl|ah|bh|ch|dh)\b')

    def repl_reg(match):
        r = match.group(1)
        if r not in regs_found:
            regs_found.append(r)
        return f"REG{regs_found.index(r)}"

    return re.sub(all_regs_pat, repl_reg, s)


# ─────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────

# Common Windows DLL role descriptions (for context in reports)
DEFAULT_DLL_ROLES = {
    'kernel32.dll':          'Windows API core: process/thread/memory/file management',
    'kernelbase.dll':        'Low-level kernel bridge (file, registry, heap)',
    'ntdll.dll':             'Native NT API: syscall wrappers, loader, heap',
    'user32.dll':            'GUI/window management',
    'advapi32.dll':          'Registry, security, service control, crypto',
    'bcrypt.dll':            '🔴 CNG cryptographic primitives (AES, RSA, SHA, RNG)',
    'ncrypt.dll':            '🔴 Key storage and asymmetric crypto (CNG)',
    'crypt32.dll':           '🔴 Certificate/PKCS/CMS operations',
    'rsaenh.dll':            '🔴 Legacy RSA/RC4/DES CryptoAPI provider',
    'cryptbase.dll':         '🔴 Base CNG provider (AES-ECB etc.)',
    'bcryptprimitives.dll':  '🔴 Core AES/SHA implementations',
    'msvcrt.dll':            'C runtime (malloc/free/sprintf/memcpy)',
    'ucrtbase.dll':          'Universal CRT (string/math/stdio)',
    'msvcp_win.dll':         'C++ STL runtime',
    'rpcrt4.dll':            'RPC/COM transport',
    'sechost.dll':           'Service control manager client',
    'gdi32.dll':             'GDI graphics primitives',
    'gdi32full.dll':         'Extended GDI',
    'win32u.dll':            'Win32 kernel user-mode entry points',
    'ws2_32.dll':            'Winsock 2 (TCP/UDP sockets)',
    'wininet.dll':           'HTTP/FTP/HTTPS client',
    'shlwapi.dll':           'Shell utility functions',
    'shell32.dll':           'Explorer shell integration',
    'ole32.dll':             'COM/OLE runtime',
    'combase.dll':           'COM core runtime',
    'ntasn1.dll':            'ASN.1 encoding/decoding',
    'cryptnet.dll':          'Certificate revocation/network crypto',
}

# DLL patterns for automatic role inference if tag is missing
PATTERN_CRYPTO = ['bcrypt', 'crypt', 'ssl', 'rsa', 'dss', 'ncrypt', 'advapi', 'encode', 'decode', 'hash', 'cipher']
PATTERN_NOISE  = ['ntdll', 'kernel32', 'kernelbase', 'wow64', 'msvcrt', 'rpcrt4', 
                  'combase', 'sechost', 'gdi32', 'user32', 'imm32', 'ucrtbase']

# Function name keywords that trigger CRYPTO role for the owner DLL
CRYPTO_FUNC_KEYWORDS = ['encrypt', 'decrypt', 'crypt', 'hash', 'cipher', 'aes', 'rsa', 
                        'rng', 'random', 'cert', 'sign', 'keystream', 'pkcs']

IO_ASSESSMENTS = {
    'CreateFileW':  'Opens/creates files — potential encryption targets',
    'CreateFileA':  'Opens/creates files (ANSI) — potential encryption targets',
    'WriteFile':    '⚠️ HIGH — bulk writes (encryption output)',
    'NtWriteFile':  '⚠️ HIGH — native write (encryption/ransom note)',
    'ReadFile':     'Reads plaintext file content before encryption',
    'NtReadFile':   'Native read — reading file data',
    'CloseHandle':  'File handle cleanup',
}


# ─────────────────────────────────────────────────────────────────
# AggregatedLoop
# ─────────────────────────────────────────────────────────────────

class AggregatedLoop:
    def __init__(self, header, tid):
        self.header = header
        self.tids = {tid}
        self.invocations = 0
        self.min_rank = 999_999_999
        self.variants  = []
        self.score     = 0.0
        self.children  = set()
        self.real_iters = 0 # B파트: Pintool LOOP_FINISH 기준 전체 반복 횟수 [NEW]

    def add_instance(self, backedge, entries, rank=None):
        self.invocations += 1
        if rank is not None and rank < self.min_rank:
            self.min_rank = rank
        for v in self.variants:
            if v['backedge'] == backedge and len(v['entries']) == len(entries):
                match = all(
                    e1.get('type') == e2.get('type') and
                    (e1.get('api') == e2.get('api') if e1.get('type') == 'io'
                     else e1.get('ip', 0) == e2.get('ip', 0))
                    for e1, e2 in zip(v['entries'], entries)
                )
                if match:
                    v['count'] += 1
                    if rank is not None and v.get('rank', 999_999) > rank:
                        v['rank'] = rank
                    return
        variant = {'backedge': backedge, 'entries': entries, 'count': 1}
        if rank is not None:
            variant['rank'] = rank
        self.variants.append(variant)

    def get_primary_variant(self):
        if not self.variants:
            return None
        return max(self.variants, key=lambda x: x['count'])


# ─────────────────────────────────────────────────────────────────
# TraceParser
# ─────────────────────────────────────────────────────────────────

class TraceParser:
    def __init__(self, show_all=True):
        self.show_all       = show_all
        self.meta           = {}              # addr -> {func, img, asm, mem_struct}
        self.loops_by_tid   = defaultdict(dict)  # (pid, tid) -> header -> AggregatedLoop
        self.loops_csv_data = {}             # (pid, globalSeq) -> iters
        self.loop_children  = defaultdict(set)  # int -> set[int]
        # B파트: Pintool에서 명시적으로 보내는 계층 데이터 [NEW]
        self.loop_parents_explicit = {} # header -> parent_header
        self.loop_depths_explicit  = {} # header -> depth
        self.loop_finish_counts = defaultdict(int)
        self.io_data        = defaultdict(list)  # (pid, tid) -> [events str]
        self.images         = []             # [{name, base, end, basename, tag}]
        self.timeline       = []
        self.main_low       = 0
        self.main_high      = 0
        # Raw IO for Markdown report
        self._raw_io_calls  = []             # [{api, handle, arg2}]
        # 루프 계층: header -> set of child headers (EXT_CHILD_LOOP 기반)

    # ── Session loading ──────────────────────────────────────────

    def load_session(self, pid, trace_path, meta_path=None, csv_path=None):
        print(f"[*] Loading session (PID={pid}): {os.path.basename(trace_path)}")
        if meta_path and os.path.exists(meta_path):
            self.load_meta(meta_path)
        self.parse_trace(pid, trace_path)

    def load_meta(self, meta_path):
        if not os.path.exists(meta_path):
            return
        try:
            with open(meta_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('main_low='):
                        for t in line.split():
                            if t.startswith('main_low='):
                                try: self.main_low = int(t.split('=')[1], 16)
                                except: pass
                            elif t.startswith('main_high='):
                                try: self.main_high = int(t.split('=')[1], 16)
                                except: pass
                        continue
                    parts = line.split(';') if ';' in line else line.split(',')
                    if len(parts) < 2:
                        continue
                    try:
                        addr_str = parts[0].strip().replace('\ufeff','').replace('\x00','')
                        addr = int(addr_str, 16)
                        if addr in self.meta:
                            continue
                        func = img = '?'
                        asm = parts[1].strip()
                        mem_struct = None
                        if len(parts) >= 4:
                            func = parts[1].strip()
                            img  = parts[2].strip()
                            asm  = parts[3].strip()
                            if len(parts) > 4:
                                mp = parts[4].strip().split('|')
                                if len(mp) >= 4:
                                    mem_struct = {'base': mp[0], 'idx': mp[1],
                                                  'scale': mp[2], 'disp': mp[3]}
                        if '.' not in img and img.lower() in ['text', 'code', 'data']:
                            img = '.' + img
                        self.meta[addr] = {'func': func, 'img': img,
                                           'asm': asm, 'mem_struct': mem_struct}
                    except Exception:
                        continue
        except Exception as e:
            print(f"[!] Meta load error: {e}")

    # ── Internals ────────────────────────────────────────────────

    def _trim_trace(self, entries, expected_img=None):
        depth = valid_count = 0
        for e in entries:
            if e.get('type') in ('io', 'img'):
                valid_count += 1
                continue
            ip = e.get('ip', 0)
            if ip == 0:
                continue
            m = self.meta.get(ip)
            if not m:
                if expected_img: break
                valid_count += 1
                continue
            if expected_img and m.get('img') != expected_img:
                break
            asm_lower = m['asm'].lower()
            if asm_lower.startswith('call'):   depth += 1
            elif asm_lower.startswith('ret'):  depth -= 1
            if depth < 0: break
            valid_count += 1
        return entries[:valid_count]

    def _analyze_activity(self, entries):
        mem_r = mem_w = call_count = calc_count = xor_count = 0
        call_targets = Counter()
        calc_ops = {'add','sub','inc','dec','mul','imul','div','idiv',
                    'shl','shr','rol','ror','and','or','xor','not','neg'}
        for e in entries:
            if e.get('type') == 'io':
                # IO 이벤트는 API 호출로 카운트
                call_count += 1
                sym = f"IO_{e.get('api')}"
                call_targets[sym] += 1
                continue

            # 1. 트레이스 레벨 통계 (ASM 유무와 상관없이 정확)
            if 'ip' in e:
                # 핀툴 기록 상의 메모리 접근 타입 확인
                etype = e.get('type', 'I')
                if etype == 'R': mem_r += 1
                elif etype == 'W': mem_w += 1
            
            # 2. 메타데이터 기반 상세 분석 (ASM이 있는 경우만)
            m = self.meta.get(e.get('ip', 0))
            if not m:
                # 메타데이터가 없는 경우, 단순 IP 실행 횟수를 Calc에 임시 합산할지 고려 가능하나
                # 여기선 메모리 R/W 통계가 이미 위에서 잡히므로 생략
                continue

            asm   = m['asm'].lower()
            parts = asm.split(None, 1)
            mnem  = parts[0] if parts else ''
            ops   = parts[1] if len(parts) > 1 else ''

            if mnem == 'call':
                call_count += 1
                target = None
                if '[' in ops and e.get('mem', 0) != 0:
                    target = e['mem']
                if not target:
                    match = re.search(r'(0x[0-9a-f]+)', ops)
                    if match:
                        try: target = int(match.group(1), 16)
                        except: pass
                if target:
                    tm = self.meta.get(target)
                    sym = tm.get('func', '?') if tm else f"sub_{target:x}"
                    call_targets[sym] += 1
            elif mnem in calc_ops:
                calc_count += 1
                if mnem == 'xor': xor_count += 1
            
            # ASM 기반 R/W 카운트는 정적 패턴 분석용 (중복 방지를 위해 etype이 없을 때만 사용하거나 병합)
            # 여기서는 위에서 e['type'] 기반으로 이미 셌으므로 추가하지 않음
        
        summary = f"Mem(R:{mem_r}/W:{mem_w}), Call:{call_count}"
        if call_count > 0 and call_targets:
            t_str = ", ".join(f"{k}:{v}" for k, v in call_targets.most_common(3))
            summary += f" {{{t_str}}}"
        if calc_count > 0:
            summary += f", Calc:{calc_count}"
        if xor_count > 0:
            summary += f" (XOR:{xor_count})"
        return summary

    def _store_loop(self, pid, header, tid, backedge, entries, rank, children=None):
        m = self.meta.get(header)
        header_img = m.get('img') if m else None
        entries = self._trim_trace(entries, header_img)
        if not entries:
            return
        tid_key = (pid, tid)
        if header not in self.loops_by_tid[tid_key]:
            self.loops_by_tid[tid_key][header] = AggregatedLoop(header, tid_key)
        if children:
            self.loops_by_tid[tid_key][header].children.update(children)
            # 글로벌 계층 맵에도 반영
            self.loop_children[header].update(children)
        has_io = any(e.get('type') == 'io' for e in entries)
        if has_io:
            entries = [e for e in entries if e.get('type') == 'io']
        agg = self.loops_by_tid[tid_key][header]
        agg.add_instance(backedge, entries, rank)
        
        # B파트: Pintool LOOP_FINISH 기준 실제 반복 횟수 업데이트
        if (pid, header) in self.loop_finish_counts:
            agg.real_iters = self.loop_finish_counts[(pid, header)]
            
        self.timeline.append({
            'rank':     rank if rank is not None else 0,
            'header':   header,
            'tid':      tid_key,
            'type':     'io' if has_io else 'compute',
            'entries':  entries,
            'children': list(children) if children else [],
        })

    def _parse_ext_meta(self, content):
        try:
            row = next(csv.reader([content]))
            if len(row) < 4: return
            addr = int(row[0], 16)
            func = row[1]
            img_name = row[2]
            asm  = row[3]
            mem_struct = None
            if len(row) > 4 and row[4]:
                mp = row[4].split('|')
                if len(mp) >= 4:
                    mem_struct = {'base': mp[0], 'idx': mp[1],
                                  'scale': mp[2], 'disp': mp[3]}
            self.meta[addr] = {'func': func, 'img': img_name,
                               'asm': asm, 'mem_struct': mem_struct}
            
            # 동적 역할 판별: 함수 이름에 암호화 관련 키워드가 있으면 해당 이미지 태그 격상
            f_low = func.lower()
            if any(k in f_low for k in CRYPTO_FUNC_KEYWORDS):
                bname = os.path.basename(img_name).lower()
                for img in self.images:
                    if img['basename'] == bname:
                        if img['tag'] != 'CRYPTO':
                            img['tag'] = 'CRYPTO'
                            # 갱신된 태그에 따라 역할 설명 업데이트
                            if '🔴' not in img['role']:
                                img['role'] = f"🔴 Behavioral Crypto — {img['role']}"
                        break
        except Exception:
            pass

    def _parse_child_loop(self, content):
        try:
            return int(content.strip(), 16)
        except Exception:
            return None

    def _parse_ext_img(self, content):
        try:
            parts = content.split(',')
            if len(parts) < 3: return
            name  = parts[0]
            base  = int(parts[1], 16)
            end   = int(parts[2], 16)
            bname = os.path.basename(name).lower()
            
            # 1. 태그 결정 (Pintool 제공 태그 우선)
            tag = ''
            if len(parts) >= 4 and 'CRYPTO' in parts[3]:
                tag = 'CRYPTO'
            else:
                # 패턴 기반 추론
                if any(p in bname for p in PATTERN_CRYPTO):
                    tag = 'CRYPTO'
                elif any(p in bname for p in PATTERN_NOISE):
                    tag = 'NOISE'
            
            # 2. 역할 설명 (알려진 리스트 + 정적인 정보)
            inferred_role = DEFAULT_DLL_ROLES.get(bname, 'Unknown — see address range')
            if tag == 'CRYPTO' and '🔴' not in inferred_role:
                inferred_role = f"🔴 Potential Crypto Activity — {inferred_role}"

            entry = {'name': name, 'base': base, 'end': end,
                     'basename': bname, 'tag': tag, 'role': inferred_role}
            
            # Avoid duplicates
            if not any(i['base'] == base for i in self.images):
                self.images.append(entry)
        except Exception:
            pass

    # ── Core parser ──────────────────────────────────────────────

    def parse_trace(self, pid, trace_path):
        if not os.path.exists(trace_path):
            print(f"[!] Trace not found: {trace_path}")
            return
        current_tid = current_header = current_backedge = current_rank = 0
        current_entries  = []
        current_children = set()
        in_loop = False

        try:
            with open(trace_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    if line.startswith('EXT_META:'):
                        self._parse_ext_meta(line[9:])
                    elif line.startswith('EXT_CSV:'):
                        try:
                            row = next(csv.reader([line[8:]]))
                            gseq  = int(row[1])
                            iters = int(row[6])
                            self.loops_csv_data[(pid, gseq)] = iters
                        except Exception:
                            pass
                    elif line.startswith('EXT_IMG:'):
                        self._parse_ext_img(line[8:])
                    elif line.startswith('EXT_MARKER:'):
                        pass
                    elif line.startswith('EXT_CHILD_LOOP,'):
                        child = self._parse_child_loop(line[15:])
                        if in_loop and child is not None:
                            current_children.add(child)
                    elif line.startswith('IO:'):
                        rest  = line[3:]
                        parts = rest.split(',')
                        if len(parts) >= 3:
                            tid_io = int(parts[0]) if parts[0].isdigit() else 0
                            api    = parts[1]
                            handle = parts[2]
                            arg2   = parts[3] if len(parts) > 3 else '0'
                            self.io_data[(pid, tid_io)].append(
                                f"{api}(Handle={handle}, Arg2={arg2})")
                            self._raw_io_calls.append({'api': api,
                                                       'handle': handle, 'arg2': arg2})
                            if in_loop:
                                try:
                                    current_entries.append({
                                        'type':   'io',
                                        'api':    api,
                                        'handle': int(handle, 16),
                                        'arg2':   int(arg2, 16),
                                    })
                                except Exception:
                                    pass
                    elif line.startswith('LOOP,') or line.startswith('LOOP_ENTER,'):
                        is_enter = line.startswith('LOOP_ENTER,')
                        parts = line.split(',')
                        
                        if in_loop and current_entries:
                            self._store_loop(pid, current_header, current_tid,
                                             current_backedge, current_entries,
                                             current_rank, current_children)
                        
                        if is_enter:
                            if len(parts) >= 8:
                                current_tid      = int(parts[1])
                                current_header   = int(parts[2], 16)
                                current_backedge = int(parts[3], 16)
                                current_rank     = int(parts[4])
                                
                                parent_h         = int(parts[6], 16)
                                depth_val        = int(parts[7])
                                
                                if parent_h != 0:
                                    self.loop_parents_explicit[current_header] = parent_h
                                    self.loop_children[parent_h].add(current_header)
                                self.loop_depths_explicit[current_header] = depth_val
                        else:
                            if len(parts) >= 6:
                                current_tid      = int(parts[1])
                                current_header   = int(parts[2], 16)
                                current_backedge = int(parts[3], 16)
                                current_rank     = int(parts[5])
                        
                        current_entries  = []
                        current_children = set()
                        in_loop          = True

                    elif line.startswith('LOOP_FINISH,'):
                        parts = line.split(',')
                        if len(parts) >= 5:
                            self.loop_finish_counts[(pid, int(parts[2], 16))] = int(parts[4])
                        if in_loop:
                            self._store_loop(pid, current_header, current_tid,
                                             current_backedge, current_entries,
                                             current_rank, current_children)
                            in_loop = False
                            current_entries = []
                            current_children = set()
                    elif in_loop and line[:2] in ('I,', 'R,', 'W,'):
                        parts = line.split(',')
                        if len(parts) < 4: continue
                        ip       = int(parts[1], 16)
                        mem_addr = int(parts[2], 16)
                        regs = []
                        for r in parts[3:]:
                            try: regs.append(int(r, 16))
                            except: regs.append(0)
                        current_entries.append({'ip': ip, 'mem': mem_addr, 'regs': regs})

            if in_loop and current_entries:
                self._store_loop(pid, current_header, current_tid,
                                 current_backedge, current_entries,
                                 current_rank, current_children)

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[!] Error parsing trace: {e}")

        total = sum(len(v) for v in self.loops_by_tid.values())
        print(f"    Loops: {total} unique | IO calls: {len(self._raw_io_calls):,}"
              f" | Images: {len(self.images)}")

    # ── 루프 계층 트리 빌더 ─────────────────────────────────────────

    def build_loop_tree(self):
        """EXT_CHILD_LOOP 및 LOOP_ENTER 데이터로 부모-자식 맵, depth를 계산.
        Pintool의 명시적 데이터(LOOP_ENTER)를 휴리스틱(EXT_CHILD_LOOP)보다 우선함.
        """
        children = self.loop_children          # header -> set[child_header]

        # 전체 알려진 헤더 집합
        all_headers = set(children.keys())
        for v in children.values():
            all_headers.update(v)
        for tid_dict in self.loops_by_tid.values():
            all_headers.update(tid_dict.keys())
        all_headers.update(self.loop_parents_explicit.keys())
        all_headers.update(self.loop_parents_explicit.values())
        if 0 in all_headers: all_headers.remove(0)

        # child -> parent 역맵 (명시적 데이터 우선)
        parent_map = {}   # child_header -> parent_header
        # 1. LOOP_ENTER 기반 명시적 부모
        for ch, ph in self.loop_parents_explicit.items():
            if ph != 0:
                parent_map[ch] = ph
        
        # 2. EXT_CHILD_LOOP 기반 휴리스틱 부모 (명시적 데이터 없는 경우만)
        for parent_h, child_set in children.items():
            for ch in child_set:
                if ch not in parent_map:
                    parent_map[ch] = parent_h

        # 부모 없는 루프 = 루트 노드
        roots = sorted(h for h in all_headers if h not in parent_map)

        # BFS로 depth 계산 (명시적 depth도 참고하지만 계층 일관성을 위해 BFS 우선)
        from collections import deque
        depth_map = {}
        queue = deque()
        for r in roots:
            depth_map[r] = 0
            queue.append(r)
        
        while queue:
            h = queue.popleft()
            # 이 노드의 자식들을 찾음
            # children 집합 + 명시적 역관계 데이터 합침
            child_set = set(children.get(h, []))
            for ch_explicit, ph_explicit in self.loop_parents_explicit.items():
                if ph_explicit == h:
                    child_set.add(ch_explicit)

            for ch in sorted(child_set):
                if ch not in depth_map:
                    depth_map[ch] = depth_map[h] + 1
                    queue.append(ch)
        
        # BFS 미도달(순환 등) 처리 - 명시적 depth가 있다면 사용
        for h in all_headers:
            if h not in depth_map:
                if h in self.loop_depths_explicit:
                    depth_map[h] = self.loop_depths_explicit[h]
                else:
                    depth_map[h] = -1

        return roots, depth_map, parent_map, all_headers

    def _get_rva_str(self, addr):
        """주소를 '0xADDR (IMAGE+OFFSET)' 형식으로 변환. 모듈 밖이면 [Dynamic] 표시."""
        if not addr: return "0x0"
        for img in self.images:
            if img['base'] <= addr <= img['end']:
                offset = addr - img['base']
                return f"0x{addr:x} (`{img['basename']}`+0x{offset:x})"
        
        # 어떤 로드된 모듈에도 속하지 않는 경우 (힙, 스택, JIT 영역 등)
        return f"0x{addr:x} [!Dynamic/Unpacked!]"

    def _get_image_basename(self, addr):
        """주소가 속한 이미지의 basename만 반환."""
        if not addr: return "?"
        for img in self.images:
            if img['base'] <= addr <= img['end']:
                return img['basename']
        return "?"

    def _get_loop_status(self, header, rank):
        """미캡처 루프의 원인을 판별하여 상태 문자열 반환."""
        if rank is not None:
            return f"rank={rank}"
        
        # 1. EXE 또는 흥미로운 DLL인지 확인
        interesting = False
        img_info = None
        for img in self.images:
            if img['base'] <= header <= img['end']:
                img_info = img
                if '.exe' in img['basename'].lower() or img['tag'] == 'CRYPTO':
                    interesting = True
                break
        
        # 2. 시스템 노이즈 필터링 여부
        if img_info and img_info['tag'] == 'NOISE' and not self.show_all:
            return "status=DLL_Filtered"

        has_executed = any(evt['header'] == header for evt in self.timeline)
        if not has_executed:
            return "status=Not_Executed"
            
        return "status=Skipped_by_Pin"

    def _render_loop_tree(self, node, children, depth_map, parent_map,
                          rank_map, inst_map, img_map,
                          prefix='', is_last=True, visited=None):
        """재귀적으로 트리 라인들을 반환. visited로 순환 참조 방지."""
        if visited is None:
            visited = set()
        
        addr_s = self._get_rva_str(node)
        if node in visited:
            connector = '└── ' if is_last else '├── '
            line_prefix = prefix + connector if prefix else ''
            return [f"{line_prefix}{addr_s}  [⚠ 순환 참조 — 생략]"]
        visited = visited | {node}

        if prefix:
            connector = '└── ' if is_last else '├── '
            line_prefix = prefix + connector
        else:
            line_prefix = ''

        rank  = rank_map.get(node)
        insts = inst_map.get(node)
        depth = depth_map.get(node, '?')
        
        status_s = self._get_loop_status(node, rank)
        insts_s  = f"inst={insts}" if insts is not None else "inst=?"

        result = [f"{line_prefix}{addr_s}  [{status_s}, {insts_s}, depth={depth}]"]

        child_list = sorted(children.get(node, []))
        
        # [Optimization] Limit Not_Executed children to prevent massive reports
        executed = []
        not_exec = []
        for ch in child_list:
            if rank_map.get(ch) is not None or any(evt['header'] == ch for evt in self.timeline):
                executed.append(ch)
            else:
                not_exec.append(ch)
        
        MAX_UNEXEC = 10
        display_list = executed + not_exec[:MAX_UNEXEC]
        hidden_count = len(not_exec) - MAX_UNEXEC
        
        # Sort display list by address
        display_list.sort()

        for i, ch in enumerate(display_list):
            is_last_ch = (i == len(display_list) - 1 and hidden_count <= 0)
            if prefix == '' and not display_list:
                child_prefix = ''
            elif prefix == '':
                child_prefix = '    ' if i == len(display_list)-1 and hidden_count <= 0 else '│   '
                # Wait, the logic for connector needs to be careful.
                # Let's simplify and use the original logic but applied to display_list.
            
            # Using original style for simplicity in replacement
            is_last_item = (i == len(display_list) - 1 and hidden_count <= 0)
            if prefix == '':
                cp = '    ' if is_last_item else '│   '
            else:
                cp = prefix + ('    ' if is_last_item else '│   ')
            
            result.extend(self._render_loop_tree(
                ch, children, depth_map, parent_map,
                rank_map, inst_map, img_map,
                cp, is_last_item, visited))
        
        if hidden_count > 0:
            connector = '└── '
            result.append(f"{prefix}{connector}... ({hidden_count} more Not_Executed loops hidden)")
            
        return result

    # ── Helpers for detailed output ───────────────────────────────

    def _is_control_flow(self, asm):
        if not asm: return False
        op = asm.split()[0].lower()
        return (op.startswith('j') or op in ('call', 'ret', 'loop',
                'loope', 'loopne', 'syscall', 'sysenter', 'int'))

    def _categorize_ea(self, ea, regs):
        if ea == 0: return ""
        esp = regs[6] if len(regs) > 6 else 0
        ebp = regs[7] if len(regs) > 7 else 0
        if (esp - 0x1000 <= ea <= esp + 0x1000) or (ebp - 0x1000 <= ea <= ebp + 0x1000):
            offset = (int(ea) - int(ebp)) if ebp != 0 else (int(ea) - int(esp))
            sign = "+" if offset >= 0 else "-"
            return f"STACK{sign}0x{abs(offset):x}"
        page = (ea >> 12) << 12
        return f"MEM_{page:x}"

    def _get_canonical_rotation(self, sig_tuple):
        if not sig_tuple: return sig_tuple
        n = len(sig_tuple)
        doubled = sig_tuple + sig_tuple
        best = sig_tuple
        for i in range(1, n):
            candidate = doubled[i:i+n]
            if candidate < best:
                best = candidate
        return best

    def _compress_blocks(self, blocks):
        if not blocks: return []
        compressed = []
        n = len(blocks)
        i = 0
        while i < n:
            best_pat  = None
            best_reps = 1
            for pat_len in range(1, min(200, (n - i) // 2) + 1):
                pat = blocks[i:i+pat_len]
                reps = 1
                curr = i + pat_len
                while curr + pat_len <= n:
                    if all(blocks[curr+k][0] == pat[k][0] for k in range(pat_len)):
                        reps += 1
                        curr += pat_len
                    else:
                        break
                if reps > 1 and (best_pat is None or pat_len * reps > len(best_pat) * best_reps):
                    best_pat  = pat
                    best_reps = reps
            if best_pat:
                compressed.append({'type': 'pattern', 'blocks': best_pat, 'count': best_reps})
                i += len(best_pat) * best_reps
            else:
                compressed.append({'type': 'block', 'data': blocks[i]})
                i += 1
        return compressed

    # ── Chronological log ────────────────────────────────────────

    def _print_chronological_log(self):
        print("=" * 60)
        print("# Chronological Behavior Log")
        print("=" * 60)
        if not self.timeline:
            print("  (No events)")
            return
        sorted_events = sorted(self.timeline, key=lambda x: x['rank'])
        grouped = []
        cur = None
        for evt in sorted_events:
            if cur is None:
                cur = dict(evt)
                cur.update({'count': 1, 'start_seq': evt['rank'], 'end_seq': evt['rank']})
            elif evt['header'] == cur['header'] and evt['type'] == cur['type']:
                cur['count'] += 1
                cur['end_seq'] = evt['rank']
                cur['children'].extend(evt['children'])
            else:
                grouped.append(cur)
                cur = dict(evt)
                cur.update({'count': 1, 'start_seq': evt['rank'], 'end_seq': evt['rank']})
        if cur:
            grouped.append(cur)

        for evt in grouped:
            tid_fmt = f"P{evt['tid'][0]}:T{evt['tid'][1]}"
            seq_fmt = (str(evt['start_seq']) if evt['count'] == 1
                       else f"{evt['start_seq']}-{evt['end_seq']}")
            m = self.meta.get(evt['header'], {'img': '?', 'func': '?'})
            children_str = ""
            if evt['children']:
                uc = sorted(set(evt['children']))
                children_str = " | Children: " + ", ".join(f"{c:x}" for c in uc)
            print(f"[{seq_fmt}] {tid_fmt} Loop @ {evt['header']:x}"
                  f" ({m['img']}!{m['func']}) x{evt['count']}{children_str}")
            if evt['type'] == 'io':
                apis = [e.get('api') for e in evt['entries'] if e.get('type') == 'io']
                if apis:
                    api_str = ", ".join(apis)
                    if len(api_str) > 150:
                        print(f"    API: {api_str[:120]} ... {api_str[-30:]}")
                    else:
                        print(f"    API: {api_str}")
            else:
                entries = evt['entries']
                mem_accesses = {f"0x{e['mem']:x}" for e in entries
                                if 'mem' in e and e['mem'] != 0}
                if mem_accesses:
                    sample = list(mem_accesses)[:3]
                    extra  = len(mem_accesses) - 3
                    print(f"    Bufs: {sample}" + (f" (+{extra})" if extra > 0 else ""))
                asm_lines = []
                for e in entries:
                    if 'ip' in e:
                        me = self.meta.get(e['ip'], {'asm': '?'})
                        asm_lines.append(f"{e['ip']:x}: {me['asm']}")
                if len(asm_lines) > 10:
                    for l in asm_lines[:3]:  print(f"    {l}")
                    print(f"    ... [{len(asm_lines)-6} hidden] ...")
                    for l in asm_lines[-3:]: print(f"    {l}")
                else:
                    for l in asm_lines: print(f"    {l}")
            print()

    # ── Text report (legacy stdout) ───────────────────────────────

    def dump_llm_report(self):
        io_activity = self.io_data
        print("=" * 60)
        print("SUMMARY: Suspect Threads")
        print("=" * 60)
        sorted_keys = sorted(self.loops_by_tid.keys())
        suspect_found = False
        for key in sorted_keys:
            lc = len(self.loops_by_tid[key])
            ic = len(io_activity.get(key, []))
            if lc > 0 and ic > 0:
                print(f"[*] PID:{key[0]} TID:{key[1]}: {lc} Loops | {ic} I/O events")
                suspect_found = True
        if not suspect_found:
            print("[-] No threads with BOTH loops and I/O.")
        print()

        if not self.loops_csv_data:
            print("!" * 60)
            print("!!! No CSV iteration data (Pintool may not have written _loops.csv) !!!")
            print("!" * 60 + "\n")

        self._print_chronological_log()

        for key in sorted_keys:
            pid, tid = key
            print(f"\n{'#'*60}")
            print(f"# Process: {pid} | Thread: {tid}")
            loops      = self.loops_by_tid[key]
            all_hdrs   = sorted(loops.keys(), key=lambda h: loops[h].score, reverse=True)
            valid_hdrs = []
            noise_hdrs = []
            for h in all_hdrs:
                agg  = loops[h]
                prim = agg.get_primary_variant()
                if not prim: continue
                summary = self._analyze_activity(prim['entries'])
                is_syscall = any(
                    self.meta.get(e['ip'], {}).get('asm','') and
                    ('int 0x2e' in self.meta[e['ip']]['asm'].lower() or
                     'syscall' in self.meta[e['ip']]['asm'].lower())
                    for e in prim['entries'] if 'ip' in e
                )
                is_weak = len(prim['entries']) <= 2 and 'Mem(R:0/W:0)' in summary
                if (is_syscall or is_weak) and not self.show_all:
                    noise_hdrs.append(h)
                else:
                    valid_hdrs.append(h)

            print(f"# Loops: {len(valid_hdrs)} (filtered {len(noise_hdrs)} noise)")
            io_evts = io_activity.get(key, [])
            if io_evts:
                print(f"# I/O ({len(io_evts)} events):")
                for io in io_evts[:5]:  print(f"#   {io}")
                if len(io_evts) > 5:
                    print(f"#   ... {len(io_evts)-5} more")
            print('#' * 60)

            consolidated = {}
            for header in valid_hdrs:
                agg  = loops[header]
                prim = agg.get_primary_variant()
                if not prim: continue
                sig_list = []
                for e in prim['entries']:
                    if e.get('type') == 'io':
                        sig_list.append(f"IO_{e.get('api')}")
                    elif 'ip' in e:
                        m = self.meta.get(e['ip'], {'asm': '?', 'mem_struct': None})
                        sig_list.append(skeletonize_asm(m['asm'], m.get('mem_struct')))
                is_trunc = len(prim['entries']) >= 50000
                if not is_trunc and len(sig_list) >= 64:
                    vsig = (tuple(self._get_canonical_rotation(tuple(sig_list))), is_trunc)
                else:
                    vsig = (tuple(sig_list), is_trunc)
                h_val = hashlib.sha256(str(vsig[0]).encode()).hexdigest()
                activity = self._analyze_activity(prim['entries'])
                # 이미지 태그 기반 우선순위 결정
                img_tag = '?'
                for img in self.images:
                    if img['base'] <= agg.header <= img['end']:
                        img_tag = img['tag']
                        img_low = img['basename']
                        break
                else:
                    img_low = m_head['img'].lower()

                is_noise  = (img_tag == 'NOISE')
                is_crypto = (img_tag == 'CRYPTO')
                is_exe    = '.exe' in img_low
                prio = 1 if is_noise else (3 if (is_trunc or is_crypto or is_exe) else 2)
                heat = agg.invocations * len(prim['entries'])
                if h_val not in consolidated:
                    consolidated[h_val] = {'loops':[],'prio':0,'heat':0,
                                           'sig':vsig[0],'rep_agg':agg,'activity':activity}
                g = consolidated[h_val]
                g['loops'].append(agg)
                g['heat'] += heat
                if prio > g['prio']:   g['prio'] = prio
                if agg.invocations > g['rep_agg'].invocations:
                    g['rep_agg'] = agg
                    g['activity'] = activity

            sorted_groups = sorted(consolidated.values(),
                                   key=lambda x: (x['prio'], x['heat']), reverse=True)
            rank_counter = 0
            for group in sorted_groups:
                if group['prio'] == 1 and not self.show_all: continue
                rank_counter += 1
                agg  = group['rep_agg']
                prim = agg.get_primary_variant()
                if not prim: continue
                m_head = self.meta.get(agg.header, {'func':'?','img':'?','asm':'?'})
                total_invoc = sum(l.invocations for l in group['loops'])
                struct_hash = hashlib.sha256(str(group['sig']).encode()).hexdigest()[:16]
                print("```text")
                print(f"Loop #{rank_counter} | Header: {agg.header:x}")
                print(f"Location: {m_head['img']} ! {m_head['func']}")
                print(f"Executions: {total_invoc} | Instructions: {len(prim['entries'])}")
                print(f"Structure Hash: {struct_hash}")
                print(f"Activity: {group['activity']}")
                print("```")

                entries = prim['entries']
                linear_blocks  = []
                cur_lines = []
                cur_sig   = []
                cur_mems  = []
                block_cache    = {}
                next_block_id  = 0
                label_stats    = defaultdict(lambda: {'mem_addrs': set()})

                def get_block_label(sig, mems):
                    nonlocal next_block_id
                    t = tuple(sig)
                    if t not in block_cache:
                        block_cache[t] = f"lbl_{next_block_id:02X}"
                        next_block_id += 1
                    lbl = block_cache[t]
                    for mem in mems:
                        label_stats[lbl]['mem_addrs'].add(mem)
                    return lbl

                for idx, e in enumerate(entries):
                    if e.get('type') == 'io':
                        line = f"  [IO] {e.get('api')} (Handle:{e.get('handle'):x})"
                        cur_lines.append(line)
                        cur_sig.append(f"IO_{e.get('api')}")
                        continue
                    ip  = e.get('ip', 0)
                    m   = self.meta.get(ip, {'asm':'?','func':'?'})
                    asm = m['asm']
                    mem_info = ""
                    if e['mem'] != 0:
                        cat = self._categorize_ea(e['mem'], e['regs'])
                        mem_info = f"  ; Mem:{e['mem']:x} ({cat})"
                        cur_mems.append(e['mem'])
                    cur_lines.append(f"  {ip:x}: {asm:<40}{mem_info}")
                    cur_sig.append(normalize_asm(asm))
                    if self._is_control_flow(asm) and idx < len(entries) - 1:
                        lbl = get_block_label(cur_sig, cur_mems)
                        linear_blocks.append((lbl, cur_lines))
                        cur_lines = []
                        cur_sig   = []
                        cur_mems  = []

                if cur_lines:
                    lbl = get_block_label(cur_sig, cur_mems)
                    linear_blocks.append((lbl, cur_lines))

                compressed = self._compress_blocks(linear_blocks)
                print(f"  [Structure: {len(compressed)} items from {len(linear_blocks)} blocks]")
                for item in compressed:
                    if item['type'] == 'pattern':
                        reps = item['count']
                        print(f"    -> REPEATING [x{reps}]")
                        for sub_b in item['blocks']:
                            lbl   = sub_b[0]
                            ms    = label_stats[lbl]['mem_addrs']
                            mstat = f" (UniMem:{len(ms)})" if ms else ""
                            print(f"       {lbl}{mstat}")
                            for l in sub_b[1]: print(f"         {l.strip()}")
                        print(f"       ... Repeats {reps}x")
                    else:
                        b = item['data']
                        lbl   = b[0]
                        lines = b[1]
                        ms    = label_stats[lbl]['mem_addrs']
                        mstat = f" (UniMem:{len(ms)})" if ms else ""
                        print(f"    -> BLOCK {lbl}{mstat}")
                        if len(lines) > 20:
                            for l in lines[:5]:  print(f"       {l.strip()}")
                            print(f"       ... [{len(lines)-10} hidden] ...")
                            for l in lines[-5:]: print(f"       {l.strip()}")
                        else:
                            for l in lines: print(f"       {l.strip()}")
                print("\n---\n")

    # ── Markdown LLM report ───────────────────────────────────────

    def write_markdown_report(self, trace_path, out_path):
        """Generate an LLM-ready Markdown report as a directory package."""
        # out_path가 .md 파일이면 폴더 이름으로 전환 (예: report_xxx.md -> report_xxx_dir)
        if out_path.endswith('.md'):
            base_dir = out_path[:-3] + "_dir"
        else:
            base_dir = out_path + "_dir"
        
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
            
        # 하위 디렉토리 생성
        timeline_dir = os.path.join(base_dir, "timeline")
        loops_dir    = os.path.join(base_dir, "loops")
        for d in [timeline_dir, loops_dir]:
            if not os.path.exists(d): os.makedirs(d)

        io_api_counts = Counter(c['api'] for c in self._raw_io_calls)
        total_io      = len(self._raw_io_calls)
        all_loops     = []
        for key in self.loops_by_tid:
            for header, agg in self.loops_by_tid[key].items():
                prim = agg.get_primary_variant()
                if prim:
                    all_loops.append((agg, prim, key))
        all_loops.sort(key=lambda x: x[0].min_rank)

        ts           = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        trace_name   = os.path.basename(trace_path)
        file_size_kb = os.path.getsize(trace_path) // 1024

        # 1. Summary Writer
        summary_lines = []
        S = summary_lines.append
        S('# Ransomware Dynamic Analysis Summary')
        S('')
        S(f'**Generated:** {ts}  ')
        S(f'**Trace:** `{trace_name}` ({file_size_kb:,} KB)  ')
        S(f'**Tool:** Intel Pin 3.31 + RansomwarePintool (only_main mode)  ')
        S('')
        S('---')
        S('')
        S('## 1. Executive Summary')
        S('')
        S(f'- **{len(all_loops)} loops** captured from the main executable')
        S(f'- **{total_io:,} I/O API calls** observed (file system hooks)')
        S(f'- **{len(self.images)} DLLs** loaded')
        S(f'- **{len(self.timeline)} loop invocations** total in timeline')
        main_exe = next((i for i in self.images if '.exe' in i['basename']), None)
        if main_exe:
            S('')
            S(f'**Target:** `{main_exe["name"]}`  ')
            S(f'**Code range:** `0x{main_exe["base"]:08X}` – `0x{main_exe["end"]:08X}`')
        S('')
        S('---')
        S('')

        # 2. Loaded DLL Inventory
        S('## 2. Loaded DLL Inventory')
        S('')
        
        known_dlls = []
        unknown_dlls = []
        for img in self.images:
            if 'Unknown' in img.get('role', 'Unknown'):
                unknown_dlls.append(img)
            else:
                known_dlls.append(img)
        
        S('### Known System/API Modules')
        S('| # | DLL | Base | End | Inferred Role |')
        S('|---|-----|------|-----|---------------|')
        for i, img in enumerate(known_dlls, 1):
            role = img.get('role', '')
            S(f'| {i} | `{img["basename"]}` | `0x{img["base"]:08X}` | `0x{img["end"]:08X}` | {role} |')
        S('')
        
        if unknown_dlls:
            S('### ⚠️ Unmapped / Dynamic Modules (Needs LLM Analysis)')
            S('> **LLM Instruction:** The following modules are loaded but not part of standard system definitions. Please analyze their names or associated routines to infer if they are custom drop files, injected payloads, or unconventional libraries used by the ransomware.')
            S('')
            S('| # | DLL | Base | End | Potential Role |')
            S('|---|-----|------|-----|----------------|')
            for i, img in enumerate(unknown_dlls, 1):
                role = img.get('role', 'Unknown')
                S(f'| {i} | `{img["basename"]}` | `0x{img["base"]:08X}` | `0x{img["end"]:08X}` | {role} |')
            S('')
            
            # Export unknown DLLs list as a separate text file
            with open(os.path.join(base_dir, "unmapped_modules.json"), 'w', encoding='utf-8') as ud:
                import json
                json.dump(unknown_dlls, ud, indent=4)

        S('---')
        S('')

        # 3. Hierarchy Tree
        roots, depth_map, parent_map, all_h = self.build_loop_tree()
        rank_map = {}; inst_map = {}; img_map = {}
        for agg, prim, tid_key in all_loops:
            h = agg.header; rank_map[h] = agg.min_rank
            inst_map[h] = len(prim['entries']); m_h = self.meta.get(h, {})
            # 이미지 명칭 보완
            img = m_h.get('img', '?')
            if img == '?': img = self._get_image_basename(h)
            img_map[h] = img

        S('## 3. Loop Hierarchy Tree')
        S('')
        S('> **LLM Note:** 들여쓰기 깊이 = 루프 중첩 레벨. `EXT_CHILD_LOOP` 기반 휴리스틱 트리.')
        S('> 상세 명령어는 `loops/` 디렉토리 내의 개별 파일을 확인하세요.')
        S('')
        if roots:
            S('```')
            for ri, root in enumerate(roots):
                is_last_root = (ri == len(roots) - 1)
                tree_lines = self._render_loop_tree(
                    root, self.loop_children, depth_map, parent_map,
                    rank_map, inst_map, img_map,
                    prefix='', is_last=is_last_root)
                for tl in tree_lines: S(tl)
            S('```')
        S('')
        S('---')
        S('')

        # 4. IO
        S('## 4. Measured I/O Activity')
        S('')
        S(f'**Total hooks fired:** {total_io:,}')
        S('')
        if io_api_counts:
            S('| API | Calls | Assessment |')
            S('|-----|-------|------------|')
            for api, cnt in io_api_counts.most_common():
                assess = IO_ASSESSMENTS.get(api, '—')
                S(f'| `{api}` | {cnt:,} | {assess} |')
        S('')
        wr = io_api_counts.get('WriteFile',0) + io_api_counts.get('NtWriteFile',0)
        rd = io_api_counts.get('ReadFile',0) + io_api_counts.get('NtReadFile',0)
        if rd > 0:
            S(f'> Write({wr:,}) / Read({rd:,}) = {wr/rd:.1f}x — '
              + ('ransomware encryption pattern.' if wr/rd > 3 else 'normal ratio.'))
        S('')
        S('---')
        S('')

        # 5. Timeline Index
        S('## 5. Execution Timeline Index')
        S('')
        S(f'Total {len(self.timeline)} events recorded.')
        S(f'Timeline is split into chunks in [`timeline/`](./timeline/).')
        S('')
        S('| Chunk | Sequence Range | File Link |')
        S('|-------|----------------|-----------|')
        CHUNK_SIZE = 5000
        for i in range(0, len(self.timeline), CHUNK_SIZE):
            part_no = i // CHUNK_SIZE
            end_seq = min(i + CHUNK_SIZE - 1, len(self.timeline) - 1)
            S(f"| Part {part_no} | {i} - {end_seq} | [view](./timeline/part{part_no}.md) |")
        S('')
        S('---')
        S('')

        # 6. Loop Bodies Index
        S('## 6. Captured Loop Bodies Index')
        S('')
        S('| ID | RVA Header | Insts | Iters | Activity | File Link |')
        S('|----|------------|-------|-------|----------|-----------|')
        for loop_i, (agg, prim, tid_key) in enumerate(all_loops, 1):
            activity = self._analyze_activity(prim['entries'])
            iters_s  = f"{agg.real_iters:,}" if agg.real_iters > 0 else "*(unknown)*"
            addr_s   = self._get_rva_str(agg.header)
            fname    = f"loop_0x{agg.header:x}.md"
            S(f"| {loop_i} | {addr_s} | {len(prim['entries'])} | {iters_s} | {activity} | [view](./loops/{fname}) |")
        S('')
        S('---')
        S('')

        # 7. LLM Instructions
        S('## 7. Analysis Instructions for LLM')
        S('')
        S('Please analyze this dynamic execution trace and answer:')
        S('')
        S('### A. Encryption Algorithm')
        S('- Identify patterns: `XOR` chains, `MOVAPS`/`PXOR` (AES-NI), bit rotation, S-box')
        crypto_dlls = [i['basename'] for i in self.images if i['tag'] == 'CRYPTO']
        if crypto_dlls:
            dll_str = ", ".join(f"`{d}`" for d in crypto_dlls)
            S(f'- Note {dll_str} are loaded (Section 2)')
        S('')
        S('### B. Loop Hierarchy Analysis')
        S('- Section 2의 계층 트리를 보고 최외곽 루프(depth=0)가 무엇을 제어하는지 파악')
        S('- 내부 루프(depth≥1)의 명령열을 보고 암호화/키 스케줄링/파일 처리 여부 판단')
        S('')
        S('---')
        S('')
        S('*Generated by `trace_parser.py` — Ransomware Analysis Pintool Project*')

        with open(os.path.join(base_dir, "summary.md"), 'w', encoding='utf-8') as f:
            f.write('\n'.join(summary_lines))

        # ─── Writing Timeline Chunks ───
        sorted_tl = sorted(self.timeline, key=lambda x: x['rank'])
        total_timeline_recorded = 0
        for i in range(0, len(sorted_tl), CHUNK_SIZE):
            chunk = sorted_tl[i:i+CHUNK_SIZE]
            part_no = i // CHUNK_SIZE
            part_path = os.path.join(timeline_dir, f"part{part_no}.md")
            with open(part_path, 'w', encoding='utf-8') as f:
                f.write(f"# Execution Timeline - Part {part_no}\n\n")
                f.write("| Seq | TID | Depth | Parent | Header | Type | Summary |\n")
                f.write("|-----|-----|-------|--------|--------|------|---------|\n")
                for evt in chunk:
                    tid_s  = f"P{evt['tid'][0]}:T{evt['tid'][1]}"
                    m      = self.meta.get(evt['header'], {'img': '?', 'func': '?'})
                    
                    img_name = m.get('img', '?')
                    if img_name == '?': img_name = self._get_image_basename(evt['header'])
                    func_name = m.get('func', '?')
                    
                    summ   = f"{img_name}!{func_name}"[:40]
                    depth_v  = depth_map.get(evt['header'], '?')
                    parent_h = parent_map.get(evt['header'], 0)
                    par_s    = f'`{self._get_rva_str(parent_h)}`' if parent_h else '*(root)*'
                    f.write(f"| {evt['rank']} | {tid_s} | {depth_v} | {par_s} "
                            f"| `{self._get_rva_str(evt['header'])}` | {evt['type']} | {summ} |\n")
                    total_timeline_recorded += 1

        # ─── Writing Loop Bodies ───
        total_loop_insts_recorded = 0
        REG_NAMES = ['EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP']
        for loop_i, (agg, prim, tid_key) in enumerate(all_loops, 1):
            fname = f"loop_0x{agg.header:x}.md"
            lpath = os.path.join(loops_dir, fname)
            m_head = self.meta.get(agg.header, {'img': '?', 'func': '?'})
            activity = self._analyze_activity(prim['entries'])
            
            with open(lpath, 'w', encoding='utf-8') as f:
                f.write(f"# Loop Body: {self._get_rva_str(agg.header)}\n\n")
                f.write(f"- **Thread:** P{tid_key[0]}:T{tid_key[1]} | **Rank:** {agg.min_rank} | **Invocations:** {agg.invocations}\n")
                f.write(f"- **Location:** `{m_head['img']}` ! `{m_head['func']}`\n")
                iters_s = f"{agg.real_iters:,}" if agg.real_iters > 0 else "*(unknown)*"
                f.write(f"- **Instructions:** {len(prim['entries'])} | **Total Iterations:** {iters_s} | **Activity:** {activity}\n\n")
                f.write("```\n")
                f.write(f"{'#':<4} {'T':<2} {'ADDR':<32} {'SYMBOL':<25} {'MEM_EA':<12} {'ASM':<35} {'REGS (EAX...EBP)'}\n")
                f.write('-' * 150 + "\n")
                for j, e in enumerate(prim['entries'], 1):
                    if e.get('type') == 'io':
                        f.write(f'{j:<4} IO {"":32} {"":25} {"":12} {e.get("api",""):<35}\n')
                        continue
                    
                    ip       = e.get('ip', 0)
                    mem_ea   = e.get('mem', 0)
                    me       = self.meta.get(ip, {'asm': '', 'func': '?', 'img': '?'})
                    
                    # 심볼 및 이미지 정보 보완
                    img_name = me.get('img', '?')
                    if img_name == '?':
                        img_name = self._get_image_basename(ip)
                    
                    sym_func = me.get('func', '?')
                    sym_str  = f"{img_name}!{sym_func}"[:24]
                    
                    # ASM 및 CALL 타겟 해석
                    asm_str  = (me.get('asm') or '')
                    if asm_str.lower().startswith('call'):
                        # call target 해석 시도
                        target = None
                        asm_parts = asm_str.split(None, 1)
                        ops = asm_parts[1] if len(asm_parts) > 1 else ''
                        if '[' in ops and mem_ea != 0:
                            target = mem_ea
                        if not target:
                            match = re.search(r'(0x[0-9a-f]+)', ops.lower())
                            if match:
                                try: target = int(match.group(1), 16)
                                except: pass
                        
                        if target:
                            tm = self.meta.get(target)
                            if tm:
                                t_img = tm.get('img', '?')
                                if t_img == '?': t_img = self._get_image_basename(target)
                                asm_str += f"  ; target:{t_img}!{tm.get('func','?')}"
                            else:
                                t_img = self._get_image_basename(target)
                                asm_str += f"  ; target:{t_img}!sub_{target:x}"
                    
                    asm_trunc = asm_str[:34]
                    regs      = e.get('regs', [])
                    regs_str  = ','.join(f'{r:x}' for r in regs[:8])
                    mem_str   = f'0x{mem_ea:x}' if mem_ea else ''
                    
                    f.write(f'{j:<4} {"I":<2} {self._get_rva_str(ip):<32} {sym_str:<25} {mem_str:<12} {asm_trunc:<35} {regs_str}\n')
                    total_loop_insts_recorded += 1
                f.write("```\n")

        # ─── Verification ───
        v_path = os.path.join(base_dir, "verification.txt")
        with open(v_path, 'w', encoding='utf-8') as f:
            f.write(f"Verification Report for {trace_name}\n")
            f.write("=" * 40 + "\n")
            f.write(f"Total loop invariants expected: {len(all_loops)}\n")
            f.write(f"Total timeline events expected: {len(self.timeline)}\n")
            f.write(f"Total timeline events recorded: {total_timeline_recorded}\n")
            
            error_found = False
            if total_timeline_recorded == len(self.timeline):
                f.write("Timeline Status: PASS (Match)\n")
            else:
                f.write("Timeline Status: FAIL (Mismatch)\n")
                error_found = True
            
            f.write(f"Total instructions recorded (body length sum): {total_loop_insts_recorded}\n")
            
            # 실제 실행된 총 명령어 수 추정 (반복 횟수 고려)
            total_executed = 0
            for agg, prim, _ in all_loops:
                iters = agg.real_iters if agg.real_iters > 0 else 1
                total_executed += len(prim['entries']) * iters
            f.write(f"Total estimated executed instructions: {total_executed:,}\n")

            f.write("\nSummary Status: " + ("PASS" if not error_found else "FAIL") + "\n")

        print(f"[+] Multi-file report package: {base_dir}")
        return len(all_loops), total_io


# ─────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Ransomware Trace Parser + LLM Report Generator')
    parser.add_argument('--trace',  help='Trace file or prefix (glob supported). '
                        'Auto-detects wc_all_P*trace*.txt if omitted.')
    parser.add_argument('--meta',   help='Optional meta file (legacy)')
    parser.add_argument('--loops',  help='Optional _loops.csv')
    parser.add_argument('--output', help='Save text report to file')
    parser.add_argument('--report', help='Save Markdown LLM report to file '
                        '(default: report_<trace_stem>.md)')
    parser.add_argument('--llm',    action='store_true',
                        help='Print detailed text analysis to stdout')
    parser.add_argument('--all',    action='store_true',
                        help='Include system noise loops in output')
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Resolve trace files
    if args.trace:
        if '*' in args.trace or '?' in args.trace:
            trace_files = sorted(glob.glob(args.trace))
        elif os.path.isfile(args.trace):
            trace_files = [args.trace]
        else:
            trace_files = sorted(glob.glob(args.trace + '*_trace.txt'))
            if not trace_files and os.path.exists(args.trace + '_trace.txt'):
                trace_files = [args.trace + '_trace.txt']
    else:
        trace_files = sorted(glob.glob(os.path.join(base_dir, 'wc_all_P*trace*.txt')))

    if not trace_files:
        print('[!] No trace files found.')
        print('    Specify --trace <file> or place wc_all_P*trace*.txt here.')
        sys.exit(1)

    print(f'[*] Found {len(trace_files)} trace file(s):')
    for tf in trace_files:
        print(f'    {os.path.basename(tf)} ({os.path.getsize(tf)//1024:,} KB)')

    # Redirect stdout for --output
    if args.output:
        sys.stdout = open(args.output, 'w', encoding='utf-8')

    tp = TraceParser(show_all=args.all)

    for t_path in trace_files:
        t_path = os.path.abspath(t_path)
        pid    = 0
        m      = re.search(r'_P(\d+)_trace\.txt$', t_path)
        if m:
            pid = int(m.group(1))
        base_stem   = t_path.replace('_trace.txt', '')
        meta_path   = base_stem + '_meta.txt'
        csv_path    = base_stem + '_loops.csv'
        if args.meta  and len(trace_files) == 1: meta_path = args.meta
        if args.loops and len(trace_files) == 1: csv_path  = args.loops
        tp.load_session(pid, t_path, meta_path, csv_path)

    # Text analysis
    if args.llm or args.output:
        tp.dump_llm_report()

    # Markdown report
    report_path = args.report
    if not report_path:
        # Auto-generate one report per trace (or combined if multiple)
        for t_path in trace_files:
            t_path     = os.path.abspath(t_path)
            stem       = os.path.basename(t_path).replace('.txt', '')
            rpt        = os.path.join(base_dir, f'report_{stem}.md')
            loops_n, io_n = tp.write_markdown_report(t_path, rpt)
            print(f'    Loops: {loops_n}, IO: {io_n:,}')
    else:
        # Single combined report using first trace file as reference
        loops_n, io_n = tp.write_markdown_report(trace_files[0], report_path)
        print(f'    Loops: {loops_n}, IO: {io_n:,}')

    if args.output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

    print('[DONE]')


if __name__ == '__main__':
    main()

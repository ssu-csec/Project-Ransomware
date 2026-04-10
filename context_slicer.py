"""
context_slicer.py - Binary Context Slicer for All Loop Addresses (Redesigned v2)
==================================================================================
loops.json의 모든 루프 header 주소를 기준으로 덤프에서 바이너리 슬라이스를 추출.

입력:
  loops.json      — trace_parser.py가 생성한 루프 파싱 결과
  dump_dir        — memory_map.json + *.bin 덤프 파일이 있는 폴더

출력:
  loop_contexts.json — 각 루프에 대한 디스어셈블리 컨텍스트

사용법:
  python context_slicer.py \\
    --loops loops.json \\
    --dump-dir loot/dump_000 \\
    --out loop_contexts.json \\
    [--pre-bytes 512] [--post-bytes 2048] [--arch 32]

  # 단일 주소 디버그 모드
  python context_slicer.py \\
    --dump-dir loot/dump_000 \\
    --address 0x401000
"""

import os
import sys
import json
import argparse
import struct
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    CAPSTONE_OK = True
except ImportError:
    CAPSTONE_OK = False
    print("[WARN] capstone 미설치. 디스어셈블리 불가. pip install capstone", file=sys.stderr)

# ─────────────────────────────────────────────────────────────────
# 덤프 파일 탐색 유틸리티
# ─────────────────────────────────────────────────────────────────

DUMP_EXTS = {'.bin', '.sys_dump'}

def load_memory_map(dump_dir: str) -> list:
    """memory_map.json 로드. 없으면 빈 리스트."""
    for fname in ('memory_map.json', 'memory_map.sys_dump'):
        path = os.path.join(dump_dir, fname)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                print(f"[*] memory_map 로드: {path} ({len(data)}개 리전)", file=sys.stderr)
                return data
            except Exception as e:
                print(f"[!] memory_map 로드 실패: {e}", file=sys.stderr)
    print(f"[WARN] memory_map.json 없음: {dump_dir}", file=sys.stderr)
    return []

def find_dump_file(dump_dir: str, base_addr: int) -> str:
    """base_addr에 해당하는 덤프 파일 경로 탐색."""
    base_str = hex(base_addr)   # "0x400000"
    base_str_noprefix = f"{base_addr:x}"  # "400000"
    for fname in os.listdir(dump_dir):
        ext = os.path.splitext(fname)[1].lower()
        if ext not in DUMP_EXTS:
            continue
        flower = fname.lower()
        if base_str in flower or base_str_noprefix in flower:
            return os.path.join(dump_dir, fname)
    return None

def find_region(memory_map: list, target_addr: int) -> dict:
    """target_addr가 속한 메모리 리전 반환."""
    for reg in memory_map:
        base = int(reg['base'], 16) if isinstance(reg['base'], str) else reg['base']
        size = reg.get('size', 0)
        if base <= target_addr < base + size:
            return reg
    return None

# ─────────────────────────────────────────────────────────────────
# 디스어셈블러
# ─────────────────────────────────────────────────────────────────

class BinaryDisassembler:
    def __init__(self, arch_bits: int = 32, indirect_data: dict = None, images: list = None):
        if not CAPSTONE_OK:
            self.md = None
            return
        mode = CS_MODE_32 if arch_bits == 32 else CS_MODE_64
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.detail = True  # 오퍼랜드 분석 활성화
        self.indirect_data = indirect_data or {}
        self.images = images or []

    def extract_cfg_blocks(self, data: bytes, vaddr_start: int, target_addr: int, max_hops: int = 2, max_blocks: int = 50) -> dict:
        """지정된 타겟에서부터 분기 기준 Basic Block을 파싱 (Hop 제한)."""
        if self.md is None: return {}
        
        blocks = {}
        queue = [(target_addr, 0)] # (address, hop_distance)
        visited = set()
        
        while queue and len(blocks) < max_blocks:
            curr_addr, hop = queue.pop(0)
            if curr_addr in visited: continue
            visited.add(curr_addr)
            
            off = curr_addr - vaddr_start
            if off < 0 or off >= len(data): continue
            
            block_insns = []
            next_addrs = []
            
            for insn in self.md.disasm(data[off:], curr_addr):
                block_insns.append({
                    'addr': hex(insn.address),
                    'bytes': insn.bytes.hex(),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str
                })
                
                mn = insn.mnemonic
                if mn.startswith('j') or mn.startswith('call') or mn.startswith('ret'):
                    if mn in ('jmp', 'call'):
                        if insn.operands and insn.operands[0].type == X86_OP_IMM:
                            target_va = insn.operands[0].imm
                            next_addrs.append(target_va)
                    elif mn.startswith('j'): # conditional jump
                        if insn.operands and insn.operands[0].type == X86_OP_IMM:
                            target_va = insn.operands[0].imm
                            next_addrs.append(target_va)
                            next_addrs.append(insn.address + insn.size) # fallthrough
                    break # Block end
            
            blocks[hex(curr_addr)] = {
                'start': hex(curr_addr),
                'instructions': block_insns,
                'hop': hop,
                'next': [hex(na) for na in next_addrs]
            }
            
            if hop < max_hops:
                for na in next_addrs:
                    if na not in visited:
                        queue.append((na, hop + 1))
                        
        return blocks

# ─────────────────────────────────────────────────────────────────
# ContextSlicer
# ─────────────────────────────────────────────────────────────────

class ContextSlicer:
    def __init__(self, dump_dir: str, indirect_calls_path: str = None,
                 arch_bits: int = 32, images: list = None):
        self.dump_dir    = dump_dir
        self.memory_map  = load_memory_map(dump_dir)
        self.cache       = {}
        self.images      = images or []
        
        # 간접 호출 데이터 로드
        indirect_data = {}
        if indirect_calls_path and os.path.exists(indirect_calls_path):
            try:
                with open(indirect_calls_path, 'r', encoding='utf-8') as f:
                    indirect_data = json.load(f)
                print(f"[*] indirect_calls 로드: {indirect_calls_path}", file=sys.stderr)
            except Exception as e:
                print(f"[!] indirect_calls 로드 실패: {e}", file=sys.stderr)

        self.disasm = BinaryDisassembler(arch_bits, indirect_data, self.images)
        self._region_cache: dict = {}  # base_addr → (data, vaddr_start)

    def _load_region_data(self, base_addr: int) -> tuple:
        """리전 바이너리 데이터를 캐시에서 반환 (없으면 파일 읽기)."""
        if base_addr in self._region_cache:
            return self._region_cache[base_addr]
        dump_path = find_dump_file(self.dump_dir, base_addr)
        if not dump_path:
            return None, 0
        try:
            with open(dump_path, 'rb') as f:
                data = f.read()
            self._region_cache[base_addr] = (data, base_addr)
            return data, base_addr
        except Exception as e:
            print(f"[!] 덤프 읽기 실패 {dump_path}: {e}", file=sys.stderr)
            return None, 0

    def slice_address_blocks(self, target_addr: int, max_hops: int = 2, max_blocks: int = 50) -> dict:
        """단일 주소에 대한 블록 CFG 생성."""
        region = find_region(self.memory_map, target_addr)
        if not region:
            return {
                'target': hex(target_addr),
                'error':  f'주소 {hex(target_addr)}가 memory_map에 없음',
            }

        base = int(region['base'], 16) if isinstance(region['base'], str) else region['base']
        data, vaddr_start = self._load_region_data(base)
        if data is None:
            return {
                'target':      hex(target_addr),
                'error':       f'덤프 파일 없음 (base={hex(base)})',
            }

        blocks = self.disasm.extract_cfg_blocks(data, vaddr_start, target_addr, max_hops, max_blocks)

        return {
            'target':              hex(target_addr),
            'blocks':              blocks,
            'region_base':         region.get('base', '?'),
            'region_protect':      region.get('protect', '?'),
            'region_type':         region.get('type', '?')
        }

    def slice_all_targets(self, targets_json_path: str, max_hops=2, max_blocks=50) -> list:
        """target_cfg_blocks.json의 타겟 주소들을 CFG 블록으로 슬라이싱."""
        if not os.path.exists(targets_json_path):
            print(f"[!] targets JSON 없음: {targets_json_path}", file=sys.stderr)
            return []

        with open(targets_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        targets = data.get('targets', [])
        print(f"[*] {len(targets)}개 타겟 CFG 블록 슬라이싱 시작 ...", file=sys.stderr)

        results = []
        success = 0
        for i, t in enumerate(targets):
            header = int(t['address'], 16)
            ctx = self.slice_address_blocks(header, max_hops, max_blocks)
            ctx.update({
                'reason': t.get('reason', 'unknown'),
                'module': t.get('module', 'unknown'),
                'loop_id': t.get('loop_id', 'unknown')
            })

            results.append(ctx)
            if 'error' not in ctx:
                success += 1

            if (i + 1) % 20 == 0:
                print(f"    진행: {i+1}/{len(targets)} ...", file=sys.stderr)

        print(f"[*] 슬라이싱 완료: {success}/{len(targets)} 성공", file=sys.stderr)
        return results

# ─────────────────────────────────────────────────────────────────
# CLI 진입점
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract CFG Contexts for Target Blocks")
    parser.add_argument('--dump-dir',   default=r"C:\Users\user\Downloads\Build\dump_workspace",
                        help='메모리 덤프 디렉토리 경로')
    parser.add_argument('--indirect-calls', default='indirect_calls.json',
                        help='간접 호출 (ICall) 매핑 정보 파일 (옵션)')
    parser.add_argument('--target-json', default='target_cfg_blocks.json',
                        help='입력받을 타겟 블록 주소 (trace_parser.py 출력물)')
    parser.add_argument('--address',    type=str, default=None,
                        help='(디버그용) 단일 주소 헥스값, 예: 0x401000')
    parser.add_argument('--max-hops', type=int, default=2,
                        help='타겟 이후 따라갈 최대 점프 깊이 (기본: 2)')
    parser.add_argument('--max-blocks', type=int, default=50,
                        help='추출할 최대 블록 수 (기본: 50)')
    parser.add_argument('--arch',       type=int, default=32, choices=[32, 64],
                        help='디스어셈블리 아키텍처 (기본: 32)')
    args = parser.parse_args()

    if not CAPSTONE_OK:
        print("[ERROR] capstone 미설치. pip install capstone 후 재실행", file=sys.stderr)
        sys.exit(1)

    slicer = ContextSlicer(args.dump_dir, args.indirect_calls, args.arch)

    def safe_print(msg):
        try:
            print(msg)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((str(msg) + '\n').encode(sys.stdout.encoding or 'utf-8', errors='replace'))
            sys.stdout.flush()

    if args.address:
        # 단일 주소 디버그 모드
        try:
            addr = int(args.address, 16)
        except ValueError:
            safe_print(f"[!] 주소 형식 오류: {args.address}")
            sys.exit(1)
        result = slicer.slice_address(addr, args.pre_bytes, args.post_bytes)
        safe_print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.target_json:
        # 타겟 블록 모드
        results = slicer.slice_all_targets(args.target_json, args.max_hops, args.max_blocks)
        safe_print(json.dumps(results, indent=2, ensure_ascii=False))

    else:
        print("[!] --target-json 또는 --address 중 하나를 지정하세요.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

from postprocess_chains import run_semantic_postprocessing, append_analysis_comments_to_c_line
import json
import re
import os
import argparse
from collections import defaultdict, Counter


def infer_motif(instructions, block_addr, edges, region_protect=''):
    has_shift = any(True for i in instructions if i.get('mnemonic') in ['shl', 'shr', 'sar', 'ror', 'rol'])
    has_and = any(True for i in instructions if i.get('mnemonic') == 'and')
    has_table_lookup = any(True for i in instructions if '*' in i.get('op_str', '') and ('+' in i.get('op_str', '') or '-' in i.get('op_str', '')))
    has_xor = any(True for i in instructions if i.get('mnemonic') == 'xor')
    has_rep = any(True for i in instructions if i.get('mnemonic', '').startswith('rep'))
    has_call = any(True for i in instructions if i.get('mnemonic') == 'call')
    has_ret = any(True for i in instructions if i.get('mnemonic') == 'ret')
    
    # Check if shellcode address
    if 'EXECUTE' in region_protect and 'WRITE' in region_protect:
        return "unmapped / shellcode execution"
    
    if has_table_lookup and has_xor:
        return "table-driven byte transform (crypto/checksum)"
    elif has_table_lookup and not has_xor and not has_shift:
        return "table init / state lookup"
    elif has_shift and has_and:
        return "symbol decode / bitstream length setup"
    elif has_call:
        return "external-dispatch / import thunk"
    elif has_ret or len(instructions) <= 2:
        return "state save / error-exit"
    elif has_rep or (not has_shift and not has_xor and not has_table_lookup and len(instructions) < 10):
        return "output copy / state flush"
    else:
        return "dispatcher / state machine"

def get_cond_string(mnem, op):
    return f"{mnem} {op}"

def extract_table_base(op_str):
    m = re.search(r'\[.*? \+ (0x[0-9a-fA-F]+)\]', op_str)
    if m:
        return m.group(1)
    return "unknown"

def semantic_condition(cmp_inst, jump_mnem):
    # Try to convert cmp eax, ecx + jae -> eax >= ecx
    if not cmp_inst:
        return jump_mnem
    op = cmp_inst.get('op_str', '')
    parts = op.split(', ')
    if len(parts) != 2:
        return f"{jump_mnem} (based on {cmp_inst.get('mnemonic')} {op})"
    
    left, right = parts[0], parts[1]
    
    mapping = {
        'je': '==', 'jz': '==',
        'jne': '!=', 'jnz': '!=',
        'ja': '>', 'jg': '>',
        'jae': '>=', 'jge': '>=',
        'jb': '<', 'jl': '<',
        'jbe': '<=', 'jle': '<='
    }
    
    op_sym = mapping.get(jump_mnem)
    if op_sym and cmp_inst.get('mnemonic') == 'cmp':
        return f"if ({left} {op_sym} {right})"
    elif cmp_inst.get('mnemonic') == 'test':
        if jump_mnem in ['je', 'jz']:
            return f"if (({left} & {right}) == 0)"
        else:
            return f"if (({left} & {right}) != 0)"
    
    return f"if (condition_{jump_mnem})"

# =====================================================================
# Phase 2: Dynamic Match Reconciliation
# =====================================================================

def index_events_by_tid(api_events):
    d = defaultdict(list)
    for e in api_events: d[e.get('tid', 0)].append(e)
    return d

def is_candidate_callsite(inst):
    mnem = inst.get('mnemonic', '')
    if mnem not in ('call', 'jmp'): return False
    if inst.get('resolved_symbol'): return False
    
    op = inst.get('op_str', '')
    resolved_module = inst.get('resolved_module')
    
    c_type = inst.get('call_type', 'unknown')
    if "[" in op or not op.startswith("0x"): c_type = "indirect"
    else: c_type = "direct"
    inst['call_type'] = c_type
    
    if c_type == "indirect": return True
    if c_type == "direct" and resolved_module in ("IMAGE", "MAPPED"): return True
    if mnem == 'jmp' and "[" in op: return True
    return False

def get_nearby_events(events_by_tid, tid, timeline_idx, window=8):
    events = events_by_tid.get(tid, [])
    result = []
    for ev in events:
        dist = ev.get("timeline_idx", 0) - timeline_idx
        if -1 <= dist <= window: result.append(ev)
    return result

def score_event_match(inst, ev, context_hint):
    score = 0
    reasons = ["same_tid"]
    score += 3
    dist = ev.get("timeline_idx", 0) - inst.get("timeline_idx", 0)
    if dist == 0:
        score += 5
        reasons.append("same_timeline_idx")
    elif 1 <= dist <= 2:
        score += 4
        reasons.append("nearest_event_after_call")
    elif -1 <= dist <= 5:
        score += 2
        reasons.append("nearby_event")
        
    if inst.get("call_type") == "direct" and inst.get("resolved_module") in ("IMAGE", "MAPPED"):
        score += 2
        reasons.append("internal_wrapper_candidate")
        
    return score, reasons

def score_to_confidence(score):
    if score >= 12: return "high"
    if score >= 8: return "medium"
    if score >= 4: return "low"
    return "none"

def dict_hash(d): return tuple(sorted((d or {}).items()))

def match_callsite(inst, tid, events_by_tid, wrapper_cache):
    timeline_idx = inst.get("timeline_idx", 0)
    wrapper_addr = inst.get("resolved_target")
    if wrapper_addr:
        cache_match = wrapper_cache.get(wrapper_addr)
        if cache_match:
            return {
                "qualified_api": cache_match["qualified_api"],
                "confidence": cache_match["confidence"],
                "reason": ["wrapper_cache_hit"]
            }
            
    candidates = get_nearby_events(events_by_tid, tid, timeline_idx, window=8)
    scored = []
    for ev in candidates:
        s, r = score_event_match(inst, ev, {})
        if s > 0: scored.append((s, r, ev))
        
    if not scored: return None
    
    scored.sort(key=lambda x: (-x[0], abs(x[2].get("timeline_idx",0) - timeline_idx)))
    best_score, reasons, best_ev = scored[0]
    
    return {
        "qualified_api": best_ev.get("api", "unknown"),
        "confidence": score_to_confidence(best_score),
        "reason": reasons,
        "matched_event_idx": best_ev.get("event_idx")
    }

def update_wrapper_cache(inst, match, wrapper_cache):
    if match["confidence"] not in ("high", "medium"): return
    if inst.get("call_type") != "direct": return
    wrapper_addr = inst.get("resolved_target")
    if not wrapper_addr: return
    if inst.get("resolved_module") not in ("IMAGE", "MAPPED"): return
    
    entry = wrapper_cache.get(wrapper_addr)
    if not entry:
        wrapper_cache[wrapper_addr] = {
            "qualified_api": match["qualified_api"],
            "api": match.get("api", ""),
            "confidence": "medium",
            "evidence_count": 1
        }
    else:
        if entry["qualified_api"] == match["qualified_api"]:
            entry["evidence_count"] += 1
            if entry["evidence_count"] >= 3:
                entry["confidence"] = "high"
        else:
            entry["confidence"] = "low"

def generate_pseudo_c(slices_file, api_events_file, out_file):
    with open(slices_file, 'r', encoding='utf-8', errors='ignore') as f:
        slices = json.load(f)
        
    global_blocks = {}
    
    # Pass 1: Global Collection
    for item in slices:
        if 'error' in item:
            continue
        loop_id = item.get('loop_id', item.get('target', 'unknown'))
        tid = item.get('tid', 0)
        timeline_idx = item.get('timeline_idx', 0)
        blocks = item.get('blocks', {})
        for addr, bdata in blocks.items():
            if addr not in global_blocks:
                for inst in bdata.get('instructions', []):
                    inst['tid'] = tid
                    inst['timeline_idx'] = timeline_idx
                bdata['source_loops'] = [loop_id]
                bdata['region_protect'] = item.get('region_protect', '')
                global_blocks[addr] = bdata
            else:
                if loop_id not in global_blocks[addr]['source_loops']:
                    global_blocks[addr]['source_loops'].append(loop_id)

    # Pass 1.5: Canonical Sub-block detection
    sorted_addrs = sorted(global_blocks.keys(), key=lambda x: int(x, 16))
    end_inst_map = defaultdict(list)
    for addr in sorted_addrs:
        insts = global_blocks[addr].get('instructions', [])
        if insts:
            end_inst_map[insts[-1].get('addr')].append(addr)

    for i, addr in enumerate(sorted_addrs):
        b = global_blocks[addr]
        b['canonical_parent'] = None
        insts = b.get('instructions', [])
        if not insts: continue
        
        possible_parents = end_inst_map[insts[-1].get('addr')]
        for p_addr in possible_parents:
            if p_addr == addr: continue
            p_insts = global_blocks[p_addr].get('instructions', [])
            if len(p_insts) > len(insts):
                p_suffix = [inst.get('addr') for inst in p_insts[-len(insts):]]
                b_suffix = [inst.get('addr') for inst in insts]
                if p_suffix == b_suffix:
                    b['canonical_parent'] = p_addr
                    break

    # Attach motifs after collection
    for addr, b in global_blocks.items():
        b['motif'] = infer_motif(b.get('instructions', []), addr, b.get('edges', []), b.get('region_protect', ''))

    # Pass 2: Reconcile Dynamic API Matches
    api_events = []
    if os.path.exists(api_events_file):
        with open(api_events_file, 'r', encoding='utf-8') as f:
            api_data = json.load(f)
            api_events = api_data.get('events', [])
            
    events_by_tid = index_events_by_tid(api_events)
    wrapper_cache = {}
    
    for addr in sorted_addrs:
        b = global_blocks[addr]
        for inst in b.get('instructions', []):
            if is_candidate_callsite(inst):
                tid = inst.get('tid', 0)
                match = match_callsite(inst, tid, events_by_tid, wrapper_cache)
                if match:
                    inst['dynamic_match'] = match
                    update_wrapper_cache(inst, match, wrapper_cache)
                else:
                    inst['dynamic_match'] = {
                        "qualified_api": "no_dynamic_match",
                        "confidence": "none",
                        "reason": ["no_match"]
                    }

    wrapper_semantics, wrapper_chains = run_semantic_postprocessing(global_blocks)
    
    wrapper_out_file = out_file.replace("pseudo_c_timeline.c", "wrapper_semantics.json")
    with open(wrapper_out_file, "w", encoding="utf-8") as f:
        json.dump(wrapper_semantics, f, indent=2, ensure_ascii=False)
        
    chain_out_file = out_file.replace("pseudo_c_timeline.c", "wrapper_chains.json")
    with open(chain_out_file, "w", encoding="utf-8") as f:
        json.dump(wrapper_chains, f, indent=2, ensure_ascii=False)

    out = []
    out.append("// ============================================================================")
    out.append("// Ransomware Dynamic Timeline Pseudo-C (Analysis-Grade IR)")
    out.append("// Features: Perfect Branch Metadata, Call Context, Canonical Blocks, Dynamic API Matches")
    out.append("// ============================================================================\n")
    
    for addr in sorted_addrs:
        b = global_blocks[addr]
        src_loops = ", ".join(b['source_loops'])
        motif = b['motif']
        parent = b['canonical_parent']
        
        edges = b.get('edges', [])
        cond_edge = None
        unc_edge = None
        call_edge = None
        
        for edge in edges:
            if edge.get('type') == 'JUMP_COND':
                cond_edge = edge.get('target')
            elif edge.get('type') == 'JUMP_UNC':
                unc_edge = edge.get('target')
            elif edge.get('type') == 'CALL':
                call_edge = edge.get('target')
                
        instructions = b.get('instructions', [])
        
        # Analyze last cmp/test
        last_cmp = None
        jump_inst = None
        for inst in instructions:
            mnem = inst.get('mnemonic', '')
            if mnem in ['cmp', 'test']:
                last_cmp = inst
            elif mnem.startswith('j') and mnem != 'jmp':
                jump_inst = inst
            elif mnem == 'jmp':
                if not unc_edge and not "[" in inst.get('op_str', ''):
                    unc_edge = inst.get('op_str')
        
        if jump_inst and not cond_edge:
            cond_edge = jump_inst.get('op_str')
            
        branch_str = last_cmp['mnemonic'] + ' ' + last_cmp['op_str'] if last_cmp else "none"
        if jump_inst:
            branch_str = semantic_condition(last_cmp, jump_inst.get('mnemonic'))
        taken_str = cond_edge if cond_edge else "none"
        
        # Fallthrough inference
        if unc_edge:
            fallthrough_str = unc_edge
        elif jump_inst and len(instructions) > 0:
            last_inst = instructions[-1]
            last_idx_addr = int(last_inst.get('addr', '0'), 16)
            inst_bytes = last_inst.get('bytes', '')
            byte_len = len(inst_bytes) // 2 if isinstance(inst_bytes, str) else len(inst_bytes)
            fallthrough_str = hex(last_idx_addr + byte_len)
        else:
            fallthrough_str = "none"

        out.append(f"\n// ----------------------------------------------------------------------------")
        out.append(f"// Basic Block: {addr}")
        if parent:
            out.append(f"// Canonical Parent: {parent} (Shared Sub-block)")
        out.append(f"// Source Loops: {src_loops}")
        out.append(f"// Inferred Motif: {motif}")
        out.append(f"// Branch: {branch_str}")
        out.append(f"// Taken: {taken_str}")
        out.append(f"// Fallthrough: {fallthrough_str}")
        confidence = "medium" if motif not in ["external-dispatch / import thunk", "state save / error-exit"] else "high"
        out.append(f"// Confidence: {confidence}")
        out.append(f"// ----------------------------------------------------------------------------")
        out.append(f"loc_{addr.replace('0x', '')}:")
        
        recent_pushes = []
        
        for inst in instructions:
            i_addr = inst.get('addr')
            mnem = inst.get('mnemonic', '')
            op = inst.get('op_str', '')
            
            c_line = f"{mnem} {op};"
            
            if mnem in ['cmp', 'test']:
                c_line = f"// {mnem} {op}"
            elif mnem == "push":
                recent_pushes.append(op)
                if len(recent_pushes) > 6:
                    recent_pushes.pop(0)
                c_line = f"// push {op}"
            elif mnem == "call":
                args_str = ", ".join(reversed(recent_pushes))
                confidence = "stack_full + reg_inferred" if len(recent_pushes) > 0 else "partial_with_inference"
                c_type = inst.get('call_type', "direct")
                
                res_target = inst.get('resolved_target')
                res_mod = inst.get('resolved_module')
                
                if res_target and res_mod:
                    func_name = f"{res_mod}!{res_target}"
                    c_line = f"call_func({func_name}, args=[{args_str}]); // call_type={c_type}"
                elif op.startswith("0x"):
                    c_line = f"sub_{op.replace('0x', '')}(args=[{args_str}]); // call_type={c_type}"
                else:
                    c_line = f"call_func({op}, args=[{args_str}]); // call_type={c_type}"
                    
                c_line = append_analysis_comments_to_c_line(c_line, inst, wrapper_semantics)
                recent_pushes = []
            elif mnem == "jmp" and "[" in op:
                base = extract_table_base(op)
                res_target = inst.get('resolved_target')
                res_mod = inst.get('resolved_module')
                if res_target and res_mod:
                    c_line = f"// static_iat_jump: true, resolved_module: {res_mod}, resolved_target: {res_target}\n    goto {res_mod}!{res_target};"
                else:
                    c_line = f"// indirect_jump: true, base_table: {base}, target: {op}\n    goto {op};"
                    
                c_line = append_analysis_comments_to_c_line(c_line, inst, wrapper_semantics)
            elif mnem.startswith('j') and mnem != 'jmp':
                # Semantic branch condition
                sem_cond = semantic_condition(last_cmp, mnem)
                c_line = f"{sem_cond} goto loc_{op.replace('0x', '')};"
            elif mnem == 'jmp':
                c_line = f"goto loc_{op.replace('0x', '')};"
            else:
                parts = op.split(', ', 1)
                if len(parts) == 2:
                    if mnem == "mov": c_line = f"{parts[0]} = {parts[1]};"
                    elif mnem == "xor": c_line = f"{parts[0]} ^= {parts[1]};"
                    elif mnem == "add": c_line = f"{parts[0]} += {parts[1]};"
                    elif mnem == "sub": c_line = f"{parts[0]} -= {parts[1]};"
                    elif mnem == "shl": c_line = f"{parts[0]} <<= {parts[1]};"
                    elif mnem == "shr": c_line = f"{parts[0]} >>= {parts[1]};"
                    elif mnem == "and": c_line = f"{parts[0]} &= {parts[1]};"
                    elif mnem == "or": c_line = f"{parts[0]} |= {parts[1]};"
            
            c_line = c_line.replace('dword ptr ', '').replace('byte ptr ', '')
            
            if not c_line.startswith('// indirect_jump'):
                out.append(f"    {c_line:<60} // {i_addr}")
            else:
                out.append(f"    {c_line}")

        if call_edge and call_edge not in global_blocks:
            out.append(f"    // edge_type: external_call, target: {call_edge}")
            out.append(f"    // analysis: skipped_known_system")

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(out))
    print(f"[*] Generated Analysis-Grade IR pseudo-C at: {out_file}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--slices", default=r"c:\Users\user\Desktop\Ransom_Analysis_folder\Report\context_slices.json")
    parser.add_argument("--api-events", default=r"c:\Users\user\Desktop\Ransom_Analysis_folder\Report\api_events.json")
    parser.add_argument("--out", default=r"c:\Users\user\Desktop\Ransom_Analysis_folder\Report\pseudo_c_timeline.c")
    args = parser.parse_args()
    generate_pseudo_c(args.slices, args.api_events, args.out)

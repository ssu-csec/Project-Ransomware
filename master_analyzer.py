"""
master_analyzer.py - Integrated Analysis Pipeline Trigger
Runs: trace_parser.py -> auto_postprocessor.py (Context Slicing) -> DLL Report
"""
import os
import sys
import subprocess
import glob
import datetime

def log_msg(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Integrated Ransomware Analysis Pipeline")
    parser.add_argument("--loot", default="loot", help="Folder containing collected traces and dumps")
    parser.add_argument("--top", type=int, default=10, help="Number of loops to slice")
    args = parser.parse_args()

    loot_dir = os.path.abspath(args.loot)
    if not os.path.exists(loot_dir):
        print(f"[!] Loot directory not found: {loot_dir}")
        return

    # 1. Trace Parsing & DLL Prompt Generation
    log_msg("Step 1: Parsing traces and conducting DLL inventory analysis...")
    # NOTE: Now includes .tmp.live for real-time nested loop analysis
    parser_cmd = [
        sys.executable, "trace_parser.py",
        "--trace-dir", loot_dir,
        "--out-json", os.path.join(loot_dir, "loops.json"),
        "--out-prompt", os.path.join(loot_dir, "loops_prompt.txt")
    ]
    # We don't use --no-tmp by default now to capture the .live progress
    try:
        subprocess.run(parser_cmd, check=True)
    except subprocess.CalledProcessError as e:
        log_msg(f"Parser failed: {e}")
        return

    # 1.1 Show DLL Analysis
    prompt_path = os.path.join(loot_dir, "loops_prompt.txt")
    if os.path.exists(prompt_path):
        log_msg("--- DLL Analysis Summary ---")
        with open(prompt_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            show = False
            for line in lines:
                if "[ LOADED IMAGES" in line or "[ MISSING EXPECTED DLLs" in line:
                    show = True
                if "[ I/O ACTIVITY" in line:
                    show = False
                if show:
                    # Safe print for terminal
                    sys.stdout.buffer.write(line.rstrip().encode(sys.stdout.encoding or 'utf-8', errors='replace'))
                    sys.stdout.buffer.write(b'\n')
        sys.stdout.flush()
        log_msg("----------------------------")

    # 2. Binary Context Slicing (using dump_000)
    log_msg("Step 2: Performing binary context slicing for top loops...")
    loops_json = os.path.join(loot_dir, "loops.json")
    # Identify dump folder (usually dump_000 or search for any dump_ prefixed folder)
    dump_folders = [d for d in os.listdir(loot_dir) if os.path.isdir(os.path.join(loot_dir, d)) and d.startswith("dump_")]
    if not dump_folders:
        log_msg("[!] No dump folders found in loot directory. Skipping slicing.")
        return

    dump_dir = os.path.join(loot_dir, dump_folders[0]) # Use the first one
    contexts_json = os.path.join(loot_dir, "loop_contexts.json")
    
    cmd_slicer = [
        sys.executable, "context_slicer.py",
        "--loops", loops_json,
        "--dump-dir", dump_dir,
        "--out", contexts_json,
        "--arch", "64" # Defaulting to 64 for now, can be parameterized
    ]
    try:
        subprocess.run(cmd_slicer, check=True)
    except subprocess.CalledProcessError as e:
        log_msg(f"Context slicer failed: {e}")
        return

    # 3. Final Report Generation (Markdown for LLM)
    log_msg("Step 3: Generating final LLM-ready report...")
    report_path = os.path.join(loot_dir, "llm_analysis_report.md")
    try:
        generate_final_report(loops_json, contexts_json, report_path)
        log_msg(f"Success! Analysis completed.")
        log_msg(f"Final Integrated Report: {report_path}")
    except Exception as e:
        log_msg(f"Report generation failed: {e}")

def generate_final_report(loops_path, contexts_path, out_path):
    import json
    if not os.path.exists(loops_path) or not os.path.exists(contexts_path):
        return

    with open(loops_path, 'r', encoding='utf-8') as f:
        loops_data = json.load(f)
    with open(contexts_path, 'r', encoding='utf-8') as f:
        contexts_data = json.load(f)

    report = []
    report.append("# Ransomware Behavioral & Binary Analysis Report")
    report.append(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    report.append("## 1. High-Level Summary")
    report.append(f"- **Total Loops Detected:** {len(loops_data.get('loops', []))}")
    report.append(f"- **Total Contexts Sliced:** {len(contexts_data)}\n")

    report.append("## 2. Top Loop Detailed Analysis")
    # Map contexts for easier lookup
    ctx_map = {c['target']: c for c in contexts_data}

    for i, lp in enumerate(loops_data.get('loops', [])[:10]): # Top 10
        header = lp['header']
        report.append(f"### [Loop {i}] Address: {header}")
        report.append(f"- **Image:** {lp.get('img', 'Unknown')}")
        report.append(f"- **Function:** {lp.get('func', 'Unknown')}")
        report.append(f"- **Iterations:** {lp.get('iters', 0)}")
        report.append(f"- **Behavioral Score:** {lp.get('score', 0)}")
        
        # Add Sliced Code
        if header in ctx_map:
            ctx = ctx_map[header]
            report.append("\n#### Disassembled Code Context:")
            report.append("```assembly")
            for ins in ctx.get('instructions', []):
                prefix = "=> " if ins.get('is_target') else "   "
                report.append(f"{prefix}{ins['addr']}: {ins['mnemonic']} {ins['op_str']}")
            report.append("```")
        else:
            report.append("\n> [!] No code context found in memory dumps.")
        report.append("\n" + "-"*30 + "\n")

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(report))

if __name__ == "__main__":
    main()

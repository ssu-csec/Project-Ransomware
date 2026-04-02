"""
host_collector.py - Out-of-Band VM Data Collector (V3 - Stable Trace & Full Dump)
Uses vmrun listDirectoryInGuest + CopyFileFromGuestToHost ONLY.
Matches Pintool's .tmp -> .txt chunking logic.
"""
import os
import sys
import time
import subprocess
import argparse
import datetime

VMRUN = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"


def log_msg(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)


def vmrun_call(*args):
    """Run vmrun with given args. Returns (returncode, stdout, stderr)."""
    exe = VMRUN if os.path.exists(VMRUN) else "vmrun"
    cmd = [exe] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def list_dir_guest(vmx, user, pwd, guest_dir):
    """Returns list of filenames inside guest_dir, or None on error."""
    rc, out, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                              "listDirectoryInGuest", vmx, guest_dir)
    if rc != 0:
        return None
    lines = out.splitlines()
    # First line is "Directory list: N"
    if not lines or "Directory list" not in lines[0]:
        return []
    entries = [l.strip() for l in lines[1:] if l.strip()]
    return entries


def copy_from_guest(vmx, user, pwd, guest_path, host_path):
    """Copy a single file from guest to host. Returns True on success."""
    rc, _, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "CopyFileFromGuestToHost", vmx, guest_path, host_path)
    return rc == 0

def delete_guest_file(vmx, user, pwd, guest_path):
    """Delete a file in guest after successful extraction."""
    rc, _, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "deleteFileInGuest", vmx, guest_path)
    return rc == 0


def main():
    parser = argparse.ArgumentParser(
        description="Out-of-Band VM Collector (Stable Trace Detection)")
    parser.add_argument("vmx",        help="Path to the .vmx file")
    parser.add_argument("guest_user", help="Guest Windows username")
    parser.add_argument("guest_pass", help="Guest Windows password")
    parser.add_argument("--trace-dir",
                        default=r"C:\Users\user\trace",
                        help="Guest trace directory")
    parser.add_argument("--dump-dir",
                        default=r"C:\Users\user\Downloads\Build\dump_workspace",
                        help="Guest dump_workspace directory")
    parser.add_argument("--out",      default="loot",
                        help="Host output directory")
    parser.add_argument("--interval", type=int, default=3,
                        help="Polling interval in seconds")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    out_abs = os.path.abspath(args.out)

    log_msg(f"Started Host Collector V3")
    log_msg(f"  VM       : {args.vmx}")
    log_msg(f"  TraceDir : {args.trace_dir} (Monitoring .txt chunks, ignoring .tmp)")
    log_msg(f"  DumpDir  : {args.dump_dir} (Recursive fetch for all regions)")
    log_msg(f"  Host out : {out_abs}")

    fetched_files = set()   # keys: "trace/filename" or "dump/subdir/filename"

    while True:
        try:
            # ─── 1. TRACE DIRECTORY (.txt ONLY, ignore .tmp) ────────────────
            trace_entries = list_dir_guest(args.vmx, args.guest_user,
                                           args.guest_pass, args.trace_dir)
            if trace_entries is None:
                log_msg("Cannot list trace dir (VM off or Tools issue?)", "WARN")
            else:
                for fname in trace_entries:
                    # 1) Finished Chunks (.done)
                    if fname.endswith(".done"):
                        key = "trace/" + fname
                        if key not in fetched_files:
                            guest_path = args.trace_dir + "\\" + fname
                            host_path  = os.path.join(out_abs, fname)
                            ok = copy_from_guest(args.vmx, args.guest_user,
                                                 args.guest_pass, guest_path, host_path)
                            if ok:
                                size = os.path.getsize(host_path) if os.path.exists(host_path) else -1
                                if size >= 0:
                                    log_msg(f"[TRACE] Finished Chunk Verified: {fname} ({size//1024} KB). Deleting on Guest.")
                                    fetched_files.add(key)
                                    delete_guest_file(args.vmx, args.guest_user, args.guest_pass, guest_path)
                                else:
                                    log_msg(f"[TRACE] Verification failed for {fname}.", "WARN")
                    

                    # 2) 현재 쓰는 중인 파일 (.tmp)
                    #    .done 이 아니므로 게스트에서 삭제되지 않은 파일 = 아직 활성 상태
                    #    매 폴링마다 덮어쓰기로 최신 내용을 가져옴
                    #    파일 잠금으로 복사 실패하면 조용히 넘기고 다음 폴링에서 재시도
                    elif fname.endswith(".tmp"):
                        guest_path = args.trace_dir + "\\" + fname
                        host_path  = os.path.join(out_abs, fname)
                        ok = copy_from_guest(args.vmx, args.guest_user,
                                             args.guest_pass, guest_path, host_path)
                        if ok:
                            size = os.path.getsize(host_path) if os.path.exists(host_path) else -1
                            log_msg(f"[TRACE] Live snapshot: {fname} ({size//1024 if size >= 0 else '?'} KB)")
                        # 실패 시 로그 없이 넘김 (잠금 중일 뿐, 다음 폴링에서 재시도)


            # ─── 2. DUMP DIRECTORIES (Recursive fetch) ──────────────────────
            dump_entries = list_dir_guest(args.vmx, args.guest_user,
                                          args.guest_pass, args.dump_dir)
            if dump_entries is not None:
                for dname in dump_entries:
                    # Ignore partial folders (dumper use _tmp suffix while writing)
                    if "_tmp" in dname:
                        continue
                    if not dname.startswith("dump_"):
                        continue

                    # Traverse inside dump_000, dump_001...
                    guest_subdir = args.dump_dir + "\\" + dname
                    host_subdir  = os.path.join(out_abs, dname)
                    os.makedirs(host_subdir, exist_ok=True)

                    sub_files = list_dir_guest(args.vmx, args.guest_user,
                                               args.guest_pass, guest_subdir)
                    if sub_files is None:
                        continue

                    any_new = False
                    for fn in sub_files:
                        key = f"dump/{dname}/{fn}"
                        if key in fetched_files:
                            continue

                        # Check if host already has it (crash recovery)
                        hf = os.path.join(host_subdir, fn)
                        if os.path.exists(hf) and os.path.getsize(hf) > 0:
                            fetched_files.add(key)
                            continue

                        gf = guest_subdir + "\\" + fn
                        ok = copy_from_guest(args.vmx, args.guest_user,
                                             args.guest_pass, gf, hf)
                        if ok:
                            fetched_files.add(key)
                            any_new = True
                        else:
                            # File might be locked by memory dumper
                            pass
                    
                    if any_new:
                        log_msg(f"[DUMP ] Synced folder: {dname}")

        except KeyboardInterrupt:
            log_msg("Stopped by user.")
            break
        except Exception as e:
            log_msg(f"Error: {e}", "ERROR")

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
    

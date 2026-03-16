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
import concurrent.futures
import concurrent.futures

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


def delete_from_guest(vmx, user, pwd, guest_path):
    """Delete a file inside the guest VM."""
    rc, _, _ = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
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

    print("-" * 50)
    log_msg(f"Ransomware Data Collector (FAST PARALLEL) Started")
    log_msg(f"  Target VM: {args.vmx}")
    log_msg(f"  Workers  : 4 (Safe Parallelism)")
    log_msg(f"  Output   : {out_abs}")
    print("-" * 50)
    print("Press Ctrl+C to stop collection.\n")

    fetched_files = set()
    tail_last_size = {} # Track size of .tmp files to avoid redundant small copies

    # Use a fixed-size pool to prevent overwhelming the host CPU/RAM
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        while True:
            try:
                # 1. Connection check (low impact)
                rc, _, _ = vmrun_call("-T", "ws", "-gu", args.guest_user, "-gp", args.guest_pass, "listDirectoryInGuest", args.vmx, "C:\\")
                if rc != 0:
                    log_msg("Waiting for VM/VMware Tools...", "STATUS")
                    time.sleep(5)
                    continue

                # 2. Get listings
                trace_entries = list_dir_guest(args.vmx, args.guest_user, args.guest_pass, args.trace_dir)
                dump_entries = list_dir_guest(args.vmx, args.guest_user, args.guest_pass, args.dump_dir)

                futures = []

                # --- Handle Trace Files ---
                if trace_entries:
                    for fname in trace_entries:
                        # Finished chunks: Fetch then DELETE from VM to clear "Headache"
                        if fname.endswith(".txt") or fname.endswith(".log"):
                            key = f"trace/{fname}"
                            if key not in fetched_files:
                                g_path = f"{args.trace_dir}\\{fname}"
                                h_path = os.path.join(out_abs, fname)
                                
                                # Define a task that copies and then deletes
                                def fetch_and_cleanup(v, u, p, gp, hp):
                                    if copy_from_guest(v, u, p, gp, hp):
                                        delete_from_guest(v, u, p, gp)
                                        return True
                                    return False

                                futures.append(executor.submit(fetch_and_cleanup, args.vmx, args.guest_user, args.guest_pass, g_path, h_path))
                                fetched_files.add(key)

                        # Live sample (Tail Tracking)
                        elif fname.endswith(".tmp"):
                            # We don't delete .tmp because Pin is writing to it.
                            # But we only pull if it has grown significantly (e.g. 64KB)
                            g_path = f"{args.trace_dir}\\{fname}"
                            # We'd need the size from listDirectoryInGuest, but vmrun doesn't give it easily.
                            # So we just pull it every 2-3 iterations or if we feel like it.
                            # For now, let's just pull it but with less priority.
                            h_path = os.path.join(out_abs, fname + ".live")
                            executor.submit(copy_from_guest, args.vmx, args.guest_user, args.guest_pass, g_path, h_path)

                # --- Handle Dump Folders ---
                if dump_entries:
                    for dname in dump_entries:
                        if not dname.startswith("dump_") or "_tmp" in dname:
                            continue
                        
                        g_subdir = f"{args.dump_dir}\\{dname}"
                        h_subdir = os.path.join(out_abs, dname)
                        os.makedirs(h_subdir, exist_ok=True)

                        sub_files = list_dir_guest(args.vmx, args.guest_user, args.guest_pass, g_subdir)
                        if sub_files:
                            for fn in sub_files:
                                key = f"dump/{dname}/{fn}"
                                if key not in fetched_files:
                                    hf = os.path.join(h_subdir, fn)
                                    gf = f"{g_subdir}\\{fn}"
                                    # Dumps are large, we fetch and keep (usually no need to delete immediately unless space is low)
                                    futures.append(executor.submit(copy_from_guest, args.vmx, args.guest_user, args.guest_pass, gf, hf))
                                    fetched_files.add(key)
                
                # Report progress
                if futures:
                    finished, _ = concurrent.futures.wait(futures, timeout=30)
                    success_count = sum(1 for f in finished if f.result())
                    if success_count > 0:
                        log_msg(f"Parallel Task: Successfully fetched and cleaned up {success_count} chunks.")

            except KeyboardInterrupt:
                log_msg("Stopping collector...")
                break
            except Exception as e:
                log_msg(f"Loop Error: {e}", "ERROR")

            time.sleep(args.interval)


if __name__ == "__main__":
    main()

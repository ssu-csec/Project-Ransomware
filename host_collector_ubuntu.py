#!/usr/bin/env python3
"""
host_collector_ubuntu.py - Out-of-Band Data Collector for Ubuntu Hosts
Supports 5 experimental VMs by using the --vm-name argument to organize output folders.
Guest paths use Windows ('\\') while Host paths use Ubuntu natively.
"""
import os
import sys
import time
import subprocess
import argparse
import datetime

# 우분투 환경의 vmrun 경로 (환경변수 PATH에 있으면 "vmrun"만 써도 무방)
VMRUN = "/usr/bin/vmrun"

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
    rc, out, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                              "listDirectoryInGuest", vmx, guest_dir)
    if rc != 0:
        return None
    lines = out.splitlines()
    if not lines or "Directory list" not in lines[0]:
        return []
    entries = [l.strip() for l in lines[1:] if l.strip()]
    return entries

def copy_from_guest(vmx, user, pwd, guest_path, host_path):
    rc, _, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "CopyFileFromGuestToHost", vmx, guest_path, host_path)
    return rc == 0

def delete_guest_file(vmx, user, pwd, guest_path):
    rc, _, err = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "deleteFileInGuest", vmx, guest_path)
    return rc == 0

def main():
    parser = argparse.ArgumentParser(description="Ubuntu Host Collector for experimental Windows VMs")
    parser.add_argument("--vmx",        help="Path to the .vmx file on Ubuntu")
    parser.add_argument("--guest-user", help="Guest Windows username")
    parser.add_argument("--guest-pass", help="Guest Windows password")
    
    # 여러 대의 VM을 실험하므로 구분하기 쉬운 폴더 할당 기능 추가
    parser.add_argument("--vm-name",  help="Name of the experimental VM (e.g., VM01).")
    
    parser.add_argument("--trace-dir",
                        default=r"C:\Users\user\trace",
                        help="Guest Windows trace directory (Must use Windows paths)")
    parser.add_argument("--dump-dir",
                        default=r"C:\Users\user\Downloads\Build\dump_workspace",
                        help="Guest Windows dump directory (Must use Windows paths)")
    parser.add_argument("--out",      default="./loot",
                        help="Host output base directory (Ubuntu path, default: ./loot)")
    parser.add_argument("--interval", type=int, default=3,
                        help="Polling interval in seconds")
    
    # Parse existing args
    args, unknown = parser.parse_known_args()

    # 대화형 입력 처리 (명령줄 인자가 없을 경우)
    print("="*60)
    print(" Ubuntu Ransomware Data Host Collector (대화형 모드)")
    print("="*60)
    
    if not args.vmx:
        args.vmx = input("1. VMX 파일 경로를 입력(또는 복사해서 붙여넣기)하세요: ").strip().replace('"', '').replace("'", "")
        if not args.vmx:
            print("[ERROR] VMX 경로가 필요합니다.")
            sys.exit(1)

    if not args.out or args.out == "./loot":
        user_out = input("2. 호스트 저장 저장 절대 경로를 입력하세요 (엔터 시 ./loot): ").strip().replace('"', '').replace("'", "")
        if user_out: args.out = user_out

    if not args.guest_user:
        user_input = input("3. VM 윈도우 계정명 (엔터 시 기본값 user): ").strip()
        args.guest_user = user_input if user_input else "user"

    if not args.guest_pass:
        pass_input = input("4. VM 윈도우 비밀번호 (엔터 시 기본값 1234): ").strip()
        args.guest_pass = pass_input if pass_input else "1234"
    
    if not args.vm_name:
        name_input = input("5. 실험 VM 이름 (엔터 시 폴더 분리 안 함): ").strip()
        if name_input: args.vm_name = name_input
    
    print("-"*60)

    # 호스트 저장 폴더 결정 (vm-name 파라미터가 있다면 서브폴더로 분리)
    if args.vm_name:
        target_out_dir = os.path.join(args.out, args.vm_name)
    else:
        target_out_dir = args.out

    os.makedirs(target_out_dir, exist_ok=True)
    out_abs = os.path.abspath(target_out_dir)

    log_msg(f"Started Ubuntu Host Collector")
    log_msg(f"  VM File  : {args.vmx}")
    log_msg(f"  TraceDir : {args.trace_dir} (Guest)")
    log_msg(f"  DumpDir  : {args.dump_dir} (Guest)")
    log_msg(f"  Host Out : {out_abs} (Target Folder)")

    fetched_files = set()

    while True:
        try:
            # 1. TRACE DIRECTORY
            trace_entries = list_dir_guest(args.vmx, args.guest_user,
                                           args.guest_pass, args.trace_dir)
            if trace_entries is None:
                log_msg("Cannot list trace dir (VM off or Tools issue?)", "WARN")
            else:
                for fname in trace_entries:
                    if fname.endswith(".done"):
                        key = "trace/" + fname
                        if key not in fetched_files:
                            guest_path = args.trace_dir + "\\" + fname # Windows Path
                            host_path  = os.path.join(out_abs, fname)  # Ubuntu Path
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
                    
                    elif fname.endswith(".tmp"):
                        # 사용자의 요청에 따라 활성 중인 .tmp 파일은 호스트로 복사하지 않음 (잠금 충돌 방지)
                        pass

            # 2. DUMP DIRECTORIES
            dump_entries = list_dir_guest(args.vmx, args.guest_user,
                                          args.guest_pass, args.dump_dir)
            if dump_entries is not None:
                for dname in dump_entries:
                    if "_tmp" in dname:
                        continue
                    if not dname.startswith("dump_"):
                        continue

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
                    
                    if any_new:
                        log_msg(f"[DUMP ] Synced folder: {dname}")
                
                # 호스트 측 덤프 폴더 정리 (최신 2개 폴더만 유지)
                import shutil
                host_dumps = [os.path.join(out_abs, d) for d in os.listdir(out_abs) if d.startswith("dump_") and "_tmp" not in d and os.path.isdir(os.path.join(out_abs, d))]
                if len(host_dumps) > 2:
                    host_dumps.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                    for old_dump in host_dumps[2:]:
                        try:
                            shutil.rmtree(old_dump, ignore_errors=True)
                            log_msg(f"[DUMP ] Cleaned up old host dump folder: {os.path.basename(old_dump)}")
                        except:
                            pass

        except KeyboardInterrupt:
            log_msg("Stopped by user.")
            break
        except Exception as e:
            log_msg(f"Error: {e}", "ERROR")

        time.sleep(args.interval)

if __name__ == "__main__":
    main()

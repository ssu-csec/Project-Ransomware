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
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            # 에러 발생 시 모든 출력(stdout, stderr)을 로그에 남김
            log_msg(f"vmrun failed (RC={r.returncode})", "ERROR")
            if r.stdout.strip(): log_msg(f"STDOUT: {r.stdout.strip()}", "ERROR")
            if r.stderr.strip(): log_msg(f"STDERR: {r.stderr.strip()}", "ERROR")
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        log_msg(f"Required command '{exe}' not found. Please check if VMware Workstation is installed.", "ERROR")
        return -1, "", "Executable not found"

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
    rc, _, _ = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "CopyFileFromGuestToHost", vmx, guest_path, host_path)
    return rc == 0

def delete_guest_file(vmx, user, pwd, guest_path):
    rc, _, _ = vmrun_call("-T", "ws", "-gu", user, "-gp", pwd,
                            "deleteFileInGuest", vmx, guest_path)
    return rc == 0

def main():
    parser = argparse.ArgumentParser(description="Ubuntu Host Collector for experimental Windows VMs")
    # 위치 기반 인자(Positional)와 선택적 인자(Optional)를 모두 지원하도록 수정
    parser.add_argument("vmx_pos",        nargs='?', help="Path to the .vmx file")
    parser.add_argument("user_pos",       nargs='?', help="Guest Windows username")
    parser.add_argument("pass_pos",       nargs='?', help="Guest Windows password")
    
    parser.add_argument("--vmx",        help="Path to the .vmx file (Optional override)")
    parser.add_argument("--guest-user", help="Guest Windows username (Optional override)")
    parser.add_argument("--guest-pass", help="Guest Windows password (Optional override)")
    parser.add_argument("--vm-name",    help="Name of the experimental VM (e.g., VM01)")
    
    parser.add_argument("--trace-dir",  default=None, help="Guest Windows trace directory")
    parser.add_argument("--dump-dir",   default=None, help="Guest Windows dump directory")
    parser.add_argument("--out",        default="./loot", help="Host output base directory")
    parser.add_argument("--interval",   type=int, default=3, help="Polling interval in seconds")
    
    args = parser.parse_args()

    # 값 병합 (명령줄 입력 우선)
    vmx = args.vmx or args.vmx_pos
    guest_user = args.guest_user or args.user_pos
    guest_pass = args.guest_pass or args.pass_pos

    # 대화형 입력 처리 (값이 하나라도 없을 경우)
    if not (vmx and guest_user and guest_pass):
        print("="*60)
        print(" Ubuntu Ransomware Data Host Collector (대화형 모드)")
        print("="*60)
        if not vmx:
            vmx = input("1. VMX 파일 경로를 입력하세요: ").strip().replace('"', '').replace("'", "")
        if not guest_user:
            guest_user = input("2. VM 윈도우 계정명 (엔터 시 기본값 user): ").strip()
            if not guest_user: guest_user = "user"
        if not guest_pass:
            guest_pass = input("3. VM 윈도우 비밀번호 (엔터 시 기본값 1234): ").strip()
            if not guest_pass: guest_pass = "1234"
        print("-"*60)

    # 경로 자동 보정 (계정명에 맞춰 기본 경로 설정)
    trace_dir = args.trace_dir if args.trace_dir else f"C:\\Users\\{guest_user}\\trace"
    dump_dir = args.dump_dir if args.dump_dir else f"C:\\Users\\{guest_user}\\Downloads\\Build\\dump_workspace"

    # 전역 args 객체 대신 변수 사용을 위해 덮어쓰기
    args.vmx = vmx
    args.guest_user = guest_user
    args.guest_pass = guest_pass
    args.trace_dir = trace_dir
    args.dump_dir = dump_dir

    # --- [자동 증분 로직 시작] ---
    # 1. VM 이름 자동 결정 (vm-name 파라미터가 없다면 VM01, VM02... 자동 생성)
    if not args.vm_name:
        idx = 1
        while True:
            candidate = f"VM{idx:02d}"
            if not os.path.exists(os.path.join(args.out, candidate)):
                args.vm_name = candidate
                break
            idx += 1
    
    vm_dir = os.path.join(args.out, args.vm_name)
    os.makedirs(vm_dir, exist_ok=True)

    # 2. 리포트 회차 자동 결정 (report1, report2... 자동 생성)
    report_idx = 1
    while True:
        report_dir_name = f"report{report_idx}"
        candidate_path = os.path.join(vm_dir, report_dir_name)
        if not os.path.exists(candidate_path):
            target_out_dir = candidate_path
            break
        report_idx += 1

    os.makedirs(target_out_dir, exist_ok=True)
    out_abs = os.path.abspath(target_out_dir)
    # --- [자동 증분 로직 종료] ---

    log_msg(f"Started Ubuntu Host Collector")
    log_msg(f"  VM File  : {args.vmx}")
    log_msg(f"  TraceDir : {args.trace_dir} (Guest)")
    log_msg(f"  DumpDir  : {args.dump_dir} (Guest)")
    log_msg(f"  Host Out : {out_abs} (Session Folder)")

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

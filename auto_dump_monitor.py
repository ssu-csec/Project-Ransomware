import os
import sys
import time
import subprocess
import argparse
import datetime

def log_msg(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out_str = f"[{timestamp}] {msg}"
    print(out_str)
    try:
        # Logs to the same directory as this script
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor_debug.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(out_str + "\n")
    except:
        pass

def get_pid_by_name(process_name):
    try:
        output = subprocess.check_output(f'tasklist /FI "IMAGENAME eq {process_name}" /NH /FO CSV', shell=True).decode('ansi', errors='ignore')
        for line in output.strip().split('\n'):
            if process_name.lower() in line.lower():
                parts = line.split('","')
                if len(parts) >= 2:
                    pid = parts[1].replace('"', '')
                    if pid.isdigit():
                        return int(pid)
    except Exception as e:
        log_msg(f"[Monitor ERROR] Finding PID: {e}")
    return None

def main():
    parser = argparse.ArgumentParser(description="Auto memory dump monitor (Background process)")
    parser.add_argument("target", help="Target executable name (e.g., target.exe)")
    parser.add_argument("--delay", type=int, default=20, help="Delay in seconds before dumping")
    parser.add_argument("--out", default="dump_workspace", help="Output directory")
    
    args = parser.parse_args()

    log_msg(f"Started tracking '{args.target}'. Sleeping {args.delay} seconds to wait for unpacking...")
    
    # 지정된 초만큼 대기 (랜섬웨어 언팩 및 런타임 진입)
    time.sleep(args.delay)
    
    # PID 찾기 (최대 3회 재시도)
    pid = None
    for attempt in range(3):
        pid = get_pid_by_name(args.target)
        if pid:
            break
        log_msg(f"Process '{args.target}' not found. Retrying in 10s... ({attempt+1}/3)")
        
        # DEBUG: log all running process names briefly to see what is actually running
        try:
            full_out = subprocess.check_output('tasklist /NH /FO CSV', shell=True).decode('ansi', errors='ignore')
            running_names = set()
            for ln in full_out.strip().split('\n'):
                pp = ln.split('","')
                if len(pp) >= 1: running_names.add(pp[0].replace('"', ''))
            # Print only a subset or if it resembles the target
            similars = [n for n in running_names if args.target[:4].lower() in n.lower() or 'wannacry' in n.lower() or 'tasksche' in n.lower() or 'decrypt' in n.lower()]
            if similars:
                log_msg(f"Similar processes running: {', '.join(similars)}")
        except: pass
        
        time.sleep(10)
        
    if not pid:
        log_msg(f"Could not find '{args.target}'. Exiting auto-dump monitor.")
        sys.exit(1)

    log_msg(f"Found {args.target} running at PID {pid}. Launching memory dumper...")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dumper_script = os.path.join(script_dir, "memory_dumper.py")
    
    if not os.path.exists(dumper_script):
        log_msg(f"Cannot find dumper script at: {dumper_script}")
        sys.exit(1)
        
    # 주기적 덤프 루프 (최신 덤프 파일만 유지, 이전 파일은 삭제/교체)
    import shutil
    dump_count = 0
    while True:
        timestamp_dir = os.path.join(args.out, "dump_latest_tmp")
        final_dir = os.path.join(args.out, "dump_latest")
        
        # 이전 임시 폴더 잔여물 정리
        if os.path.exists(timestamp_dir):
            shutil.rmtree(timestamp_dir, ignore_errors=True)
        
        # 메모리 덤퍼 스크립트 실행
        cmd = [sys.executable, dumper_script, str(pid), "--out", timestamp_dir]
        try:
            log_msg(f"Running dump iteration #{dump_count}... (Overwriting previous)")
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.stdout:
                log_msg(f"[Dumper out] {result.stdout.strip()}")
            if result.stderr:
                log_msg(f"[Dumper err] {result.stderr.strip()}")
            
            if result.returncode != 0:
                log_msg(f"Dumper exited with error code {result.returncode}. Assuming process is dead. Exiting monitor.")
                break
                
            # 기존 완료 폴더 삭제 후 새 덤프로 덮어쓰기
            if os.path.exists(timestamp_dir):
                if os.path.exists(final_dir):
                    shutil.rmtree(final_dir, ignore_errors=True)
                try:
                    os.rename(timestamp_dir, final_dir)
                    log_msg(f"[Rename] Updated {os.path.basename(final_dir)} with latest memory dump.")
                except Exception as re_err:
                    log_msg(f"[WARN] Rename 실패: {re_err} (이미 사용 중일 수 있음)")
            
            log_msg(f"Auto-dump #{dump_count} successfully replaced the previous dump for {args.target}.")
        except Exception as e:
            log_msg(f"Auto-dump failed with exception: {e}")
            break
            
        dump_count += 1
        log_msg(f"Sleeping 10 minutes (600 seconds) before next dump...")
        time.sleep(600)

if __name__ == "__main__":
    main()

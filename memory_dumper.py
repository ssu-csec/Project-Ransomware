import ctypes
from ctypes import wintypes
import sys
import os
import json

# --- 윈도우 상수 ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x2000
MEM_IMAGE = 0x1000000

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# 메모리 보호 속성 문자열 변환용 헬퍼 함수
def get_protection_str(protect):
    if protect & PAGE_EXECUTE_READWRITE: return "RWX"
    if protect & PAGE_EXECUTE_READ: return "RX"
    if protect & PAGE_EXECUTE: return "X"
    if protect & PAGE_READWRITE: return "RW"
    if protect & PAGE_READONLY: return "R"
    return "??"

# --- ctypes 구조체 ---
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]

def enable_debug_privilege():
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    
    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
        return False

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        kernel32.CloseHandle(h_token)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    success = advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
    kernel32.CloseHandle(h_token)
    return bool(success)

class MemoryDumper:
    def __init__(self, pid):
        self.pid = pid
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        # 32비트 환경 고려
        self.is_64_bit = sys.maxsize > 2**32
        import platform
        print(f"[*] Python Architecture: {platform.architecture()[0]}")
        
        if enable_debug_privilege():
            print("[*] SeDebugPrivilege enabled successfully.")
        else:
            print("[!] Failed to enable SeDebugPrivilege. Some system processes might be inaccessible.")
            
        # 프로세스 핸들 열기
        self.h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.h_process:
            print(f"[!] PROCESS_ALL_ACCESS failed. Trying PROCESS_QUERY_INFORMATION | PROCESS_VM_READ...")
            self.h_process = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
            
        if not self.h_process:
            print(f"[!] Failed to open process. PID: {self.pid}. Error: {ctypes.get_last_error()}")
            sys.exit(1)
            
        # Declare explicit arguments for ReadProcessMemory to support 64-bit Pointers correctly
        self.kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
            
        print(f"[*] Successfully opened process handle for PID: {self.pid}")

    def scan_and_dump(self, out_dir):
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        
        regions = []
        target_regions = []
        
        while True:
            result = self.kernel32.VirtualQueryEx(self.h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if result == 0:
                break
            base = mbi.BaseAddress
            size = mbi.RegionSize
            state = mbi.State
            protect = mbi.Protect
            mtype = mbi.Type
            
            # MEM_COMMIT 상태인 메모리만 기록
            if state == MEM_COMMIT:
                prot_str = get_protection_str(protect)
                type_str = ""
                if mtype == MEM_PRIVATE: type_str = "PRIVATE"
                elif mtype == MEM_IMAGE: type_str = "IMAGE"
                else: type_str = "MAPPED"
                
                region_info = {
                    "base": hex(base) if base else "0x0",
                    "size": size,
                    "protect": prot_str,
                    "type": type_str
                }
                regions.append(region_info)
                
                # 추출 대상: RWX, RX의 PRIVATE 또는 IMAGE 섹션
                if prot_str in ["RWX", "RX"]:
                    target_regions.append(region_info)
            
            address += size
            
        # 맵 정보 저장 (확장자를 JSON에서 비표준으로 위장하여 랜섬웨어 암호화 방지)
        map_path = os.path.join(out_dir, "memory_map.sys_dump")
        with open(map_path, "w") as f:
            json.dump(regions, f, indent=4)
            
        # OS 속성 락 걸기 (Read-Only:1)
        ctypes.windll.kernel32.SetFileAttributesW(map_path, 1)
        
        print(f"[*] Memory map saved to {map_path} ({len(regions)} regions)")
        
        # 관심 영역 덤프
        print(f"[*] Dumping {len(target_regions)} target regions (RX/RWX)...")
        for idx, reg in enumerate(target_regions):
            base_addr = int(reg["base"], 16)
            size = reg["size"]
            
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            
            success = self.kernel32.ReadProcessMemory(self.h_process, ctypes.c_void_p(base_addr), buffer, size, ctypes.byref(bytes_read))
            
            # success can be a non-zero integer if true
            if success != 0 and bytes_read.value > 0:
                dump_filename = f"region_{idx}_{hex(base_addr)}_{reg['protect']}_{reg['type']}.sys_dump"
                dump_path = os.path.join(out_dir, dump_filename)
                with open(dump_path, "wb") as f:
                    f.write(buffer.raw[:bytes_read.value])
                    
                # 덤프 파일에도 읽기 전용 속성 부여 (랜섬웨어 방어)
                ctypes.windll.kernel32.SetFileAttributesW(dump_path, 1)
            else:
                print(f"[!] Read failed for region {hex(base_addr)} (Error {ctypes.get_last_error()}). success={success}, bytes_read={bytes_read.value}")
                continue
                
        print("[*] Memory dump complete.")
        
        print("[*] Memory dump complete. (Rename deferred to monitor script)")

    def __del__(self):
        if hasattr(self, 'h_process') and self.h_process:
            self.kernel32.CloseHandle(self.h_process)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process Memory Dumper")
    parser.add_argument("pid", type=int, help="Target process ID")
    parser.add_argument("--out", default="dump_workspace", help="Output directory")
    args = parser.parse_args()
    
    dumper = MemoryDumper(args.pid)
    dumper.scan_and_dump(args.out)

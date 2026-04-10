import os
import sys
import glob
import json
import subprocess

def main():
    if len(sys.argv) < 5:
        print("Usage: python batch_slicer.py <context_slicer.py> <dump_workspace_dir> <target_json> <out_json>")
        sys.exit(1)
        
    slicer_py = sys.argv[1]
    dump_workspace = sys.argv[2]
    target_json = sys.argv[3]
    out_json = sys.argv[4]
    
    print(f"[*] 덤프 워크스페이스 검색: {dump_workspace}")
    
    # 덤프 폴더 찾기 (dump_000, dump_001 등)
    dump_dirs = sorted(glob.glob(os.path.join(dump_workspace, "dump_*")))
    valid_dumps = [d for d in dump_dirs if os.path.exists(os.path.join(d, "memory_map.sys_dump"))]
    
    print(f"[*] 총 {len(valid_dumps)} 개의 유효한 덤프 폴더를 찾았습니다.")
    if not valid_dumps:
        print("[-] 처리할 덤프가 없습니다. 종료합니다.")
        sys.exit(0)
        
    # 성공적으로 스캔된 루트 주소의 블록들을 모을 딕셔너리
    merged_slices = {}
    
    for idx, dump in enumerate(valid_dumps):
        print(f"[{idx+1}/{len(valid_dumps)}] {os.path.basename(dump)} 처리 중...")
        
        cmd = [
            sys.executable, slicer_py,
            "--dump-dir", dump,
            "--target-json", target_json,
            "--arch", "32",
            "--max-hops", "3",
            "--max-blocks", "80"
        ]
        
        try:
            # Slicer 실행 및 결과 캡처 (에러 출력 무시, 텍스트 변환 시 안전하게 디코딩)
            result = subprocess.run(cmd, capture_output=True)
            if not result.stdout:
                continue
            
            # 한글 경로명(cp949, euckr) 등에 의해 utf-8 변환 실패 시 다운되지 않도록 안전 디코딩 
            out_text = result.stdout.decode('utf-8', errors='replace')
            
            if not out_text.strip():
                continue
                
            try:
                dump_slices = json.loads(out_text)
                if not isinstance(dump_slices, list):
                    continue
            except json.JSONDecodeError:
                continue
                
            found_count = 0
            for slice_obj in dump_slices:
                # 추출 성공 여부는 blocks 배열의 존재 여부로 확인
                blocks = slice_obj.get("blocks", [])
                if not blocks:
                    continue
                    
                target_addr = slice_obj.get("target_address", 0)
                if isinstance(target_addr, int):
                    addr_key = hex(target_addr)
                else:
                    addr_key = str(target_addr)
                
                # 아직 못 찾은 주소이거나, 이번 덤프에서 더 많은 블록(압축 해제 후 로직 등)이 추출된 경우 덮어쓰기
                if addr_key not in merged_slices or len(blocks) > len(merged_slices[addr_key].get("blocks", [])):
                    if addr_key not in merged_slices:
                        found_count += 1
                    merged_slices[addr_key] = slice_obj
            
            if found_count > 0:
                print(f"    --> 신규 {found_count} 개의 루프 분기 해석 (누적 추출 성공: {len(merged_slices)} 개)")
                
            # 만약 모든 대상(target_json 안의 개수)을 다 찾았다면 조기 종료 가능하지만 현재는 계속 수행
                
        except Exception as e:
            print(f"    [!] 슬라이서 실행 중 에러 발생: {e}")
            
    print(f"\n[*] 자동화 스캔 완료! 총 {len(merged_slices)} 개의 루프/분기 흐름 추출 성공.")
    
    # 딕셔너리 값들만 분리해서 리스트로 만들고 결과 저장
    final_output = list(merged_slices.values())
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=4)
        
    print(f"[*] 결과 파일 저장 위치: {out_json}")

if __name__ == '__main__':
    main()

@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ====================================================
:: [Step 1] Ransomware Data Collector (VM -> Host)
:: ====================================================

echo [*] 호스트 데이터 수집기를 가동합니다.
echo.

:: --- [사용자 설정 항목] ---
set "VMX_PATH=C:\Users\user\Documents\Virtual Machines\Ransomware_Test\Ransomware_Test.vmx"
set "GUEST_USER=user"
set "GUEST_PASS=1234"
set "LOOT_DIR=C:\Users\user\Desktop\Ransom_Analysis_folder"
:: -------------------------

if not exist "%~dp0host_collector.py" (
    echo [!] 오류: host_collector.py 파일을 찾을 수 없습니다.
    pause
    exit /b 1
)

:: 1. 파이썬 실행 경로 탐색 (아나콘다 우선)
set "PY_EXE=python"
if exist "C:\Users\user\anaconda3\python.exe" (
    set "PY_EXE=C:\Users\user\anaconda3\python.exe"
)

echo [상태] 파이썬 경로: "!PY_EXE!"
echo [상태] VM 모니터링 중... (%LOOT_DIR% 폴더 확인)
echo [알림] 수집을 중단하려면 창을 닫거나 Ctrl+C를 누르세요.
echo.

:: 2. 스크립트 실행
if exist "%~dp0host_collector.py" (
    "!PY_EXE!" "%~dp0host_collector.py" "%VMX_PATH%" "%GUEST_USER%" "%GUEST_PASS%" --out "%LOOT_DIR%" --interval 2
) else (
    echo [!] 오류: host_collector.py 파일을 찾을 수 없습니다.
)

pause

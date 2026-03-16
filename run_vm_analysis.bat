@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ====================================================
:: Ransomware Analysis - VM SIDE RUNNER (Mixed-Mode)
:: ====================================================

:: 1. trace 폴더 초기화
mkdir "%USERPROFILE%\trace" 2>nul
del /f /q "%USERPROFILE%\trace\debug_log.txt" 2>nul
del /f /q "%USERPROFILE%\trace\pin.log" 2>nul

echo [VM] 랜섬웨어 계측 및 분석 준비 완료
echo.

:: 2. 경로 설정
set "PIN_ROOT=C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows"
set "PIN_EXE=%PIN_ROOT%\pin.exe"
set "TOOL32=%~dp0RansomwarePintool.dll"
set "TOOL64=%~dp0RansomwarePintool_x64.dll"

:: 분석 대상 경로 (입력 가능)
set "TARGET=C:\Users\user\Desktop\test\wannacry.exe"
if not exist "%TARGET%" (
    echo [경고] 대상 파일을 찾을 수 없습니다: %TARGET%
    set /p TARGET="실제 .exe 경로를 입력하세요: "
)
set "TRACEDIR=%USERPROFILE%\trace"

:: 3. 자동 덤퍼 실행
for %%F in ("%TARGET%") do set "TARGET_NAME=%%~nxF"
echo [*] [AUTO-DUMP] %TARGET_NAME% 감시 시작 (20초 후 덤프)
start "AutoDumpMonitor" /b python "%~dp0auto_dump_monitor.py" "%TARGET_NAME%" --delay 20 --out "%~dp0dump_workspace"

echo [*] Pin 엔진 가시화 및 계측 시작...
echo.

:: 4. Mixed-Mode 계측 실행
"%PIN_EXE%" -follow_execv -logfile "%TRACEDIR%\pin.log" ^
    -t "%TOOL32%" -instrument_all 0 -follow_child 1 -only_main 1 -crypto_only 0 -hot_iters 20 -top 200 -cap_max_ins 50000 -log_meta 1 -break_iters 0 -prefix "%TRACEDIR%\wc_all" ^
    -t64 "%TOOL64%" ^
    -- "%TARGET%"

echo.
echo [*] VM 측 분석 종료. 호스트의 수집기를 확인하세요.
pause

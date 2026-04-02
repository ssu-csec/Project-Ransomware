@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ====================================================
:: Ransomware Analysis - Pin 실행 스크립트 (안정성 강화)
:: ====================================================

:: 1. trace 폴더 생성 + 이전 파일 초기화
mkdir "%USERPROFILE%\trace" 2>nul
del /f /q "%USERPROFILE%\trace\*.*" 2>nul

echo [*] 이전 trace 파일 완전 삭제 완료
echo.

:: 2. 경로 설정
set "PIN_ROOT=C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows"
:: root pin.exe = mixed-mode launcher (32/64 자동 처리)
set "PIN_EXE=%PIN_ROOT%\pin.exe"
set "PROJECT=%~dp0"

:: DLL 경로 탐색
set "TOOL32="
set "TOOL64="

if exist "%PROJECT%Build\RansomwarePintool.dll" (set "TOOL32=%PROJECT%Build\RansomwarePintool.dll")
if exist "%PROJECT%Build\RansomwarePintool_x64.dll" (set "TOOL64=%PROJECT%Build\RansomwarePintool_x64.dll")

if "%TOOL32%"=="" (if exist "C:\Users\user\Downloads\Build\RansomwarePintool.dll" set "TOOL32=C:\Users\user\Downloads\Build\RansomwarePintool.dll")
if "%TOOL64%"=="" (if exist "C:\Users\user\Downloads\Build\RansomwarePintool_x64.dll" set "TOOL64=C:\Users\user\Downloads\Build\RansomwarePintool_x64.dll")

set "TARGET=C:\Users\user\Desktop\test\wannacry.exe"
if not exist "%TARGET%" (
    echo [경고] TARGET 파일을 찾을 수 없습니다: %TARGET%
    echo 실제 .exe 실행 파일의 전체 경로를 입력해 주세요.
    set /p TARGET="대상 경로 입력: "
)
set "TRACEDIR=%USERPROFILE%\trace"

:: 3. 경로 유효성 최종 확인
echo [*] 경로 확인:
echo     Pin:   "%PIN_EXE%"
echo     32bit: "%TOOL32%"
echo     64bit: "%TOOL64%"
echo     대상:  "%TARGET%"
echo.

if not exist "%PIN_EXE%" ( echo [ERROR] Pin.exe가 없습니다: "%PIN_EXE%" & pause & exit /b 1 )
if "%TOOL32%"=="" ( echo [ERROR] 32비트 DLL을 찾을 수 없습니다. & pause & exit /b 1 )
if "%TOOL64%"=="" ( echo [ERROR] 64비트 DLL을 찾을 수 없습니다. & pause & exit /b 1 )
if not exist "%TARGET%" ( echo [ERROR] 대상 파일이 없습니다: "%TARGET%" & pause & exit /b 1 )

echo [*] 분석을 시작합니다...
echo.

for %%F in ("%TARGET%") do set "TARGET_NAME=%%~nxF"
echo [*] 자동 메모리 덤퍼를 예약합니다. (목표: %TARGET_NAME%, 20초 후 덤프 실행)
start "AutoDumpMonitor" /b python "%PROJECT%auto_dump_monitor.py" "%TARGET_NAME%" --delay 20 --out "%PROJECT%dump_workspace"


:: Session ID 생성 (YYYYMMDD_HHMMSS_RANDOM)
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set "SESSION_ID=!datetime:~0,8!_!datetime:~8,6!_!RANDOM!"
echo [*] Session ID: !SESSION_ID!

:: mixed-mode: -t (32bit + 모든 knob) 먼저, -t64 (64bit DLL만) 마지막
"%PIN_EXE%" -follow_execv -logfile "%TRACEDIR%\pin.log" ^
    -t "%TOOL32%" -instrument_all 0 -follow_child 1 -only_main 1 -hot_iters 5 -cap_max_ins 50000 -break_iters 0 -prefix "%TRACEDIR%" -session_id "!SESSION_ID!" -top 50 -crypto_only 0 ^
    -t64 "%TOOL64%" -instrument_all 0 -follow_child 1 -only_main 1 -hot_iters 5 -cap_max_ins 50000 -break_iters 0 -prefix "%TRACEDIR%" -session_id "!SESSION_ID!" -top 50 -crypto_only 0 ^
    -- "%TARGET%"

echo.
echo [*] 실행이 완료되었습니다. 결과 파일 목록을 확인합니다...
dir "%TRACEDIR%\*.txt" 2>nul
echo.
echo [*] debug_log.txt 내용 (시작 로그 확인):
if exist "%TRACEDIR%\debug_log.txt" (type "%TRACEDIR%\debug_log.txt") else (echo [DEBUG] debug_log.txt 파일이 생성되지 않았습니다.)
echo.

pause

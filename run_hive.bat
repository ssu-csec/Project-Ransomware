@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ====================================================
:: Hive Ransomware Analysis - Pin 실행 스크립트 (Golang 맞춤형)
:: ====================================================

:: 1. trace 폴더 생성 + 이전 debug_log.txt 초기화
mkdir "%USERPROFILE%\trace" 2>nul
del /f /q "%USERPROFILE%\trace\debug_log.txt" 2>nul

echo [*] 이전 debug_log.txt 삭제 완료
echo.

:: 2. 경로 설정
set "PIN_ROOT=C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows"
:: root pin.exe = mixed-mode launcher (32/64 자동 처리)
set "PIN_EXE=%PIN_ROOT%\pin.exe"
set "PROJECT=%~dp0"

:: DLL 경로 명시적 할당 (사용자 요청 사항)
set "TOOL32=C:\Users\user\Downloads\Build\HivePintool.dll"
set "TOOL64=C:\Users\user\Downloads\Build\HivePintool_x64.dll"

:: 대상 파일 경로 설정 (사용자 요청 사항)
set "TARGET=C:\Users\user\Desktop\test\hive.exe"

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
if not exist "%TOOL32%" ( echo [ERROR] 32비트 DLL을 찾을 수 없습니다: "%TOOL32%" & pause & exit /b 1 )
if not exist "%TOOL64%" ( echo [ERROR] 64비트 DLL을 찾을 수 없습니다: "%TOOL64%" & pause & exit /b 1 )
if not exist "%TARGET%" ( echo [ERROR] 대상 파일이 없습니다: "%TARGET%" & pause & exit /b 1 )

echo [*] 분석을 시작합니다...
echo.

:: mixed-mode: -t (32bit + 모든 knob) 먼저, -t64 (64bit DLL만) 마지막
:: Hive를 위해 접두어를 hive_trace로 변경
"%PIN_EXE%" -logfile "%TRACEDIR%\pin.log" ^
    -t "%TOOL32%" -instrument_all 0 -follow_child 1 -only_main 0 -crypto_only 0 -hot_iters 20 -top 200 -cap_max_ins 50000 -log_meta 0 -break_iters 0 -log_images 1 -prefix "%TRACEDIR%\hive_trace" ^
    -t64 "%TOOL64%" ^
    -- "%TARGET%"

echo.
echo [*] 실행이 완료되었습니다. 결과 파일 목록을 확인합니다...
dir "%TRACEDIR%\*.txt" 2>nul
echo.
echo [*] debug_log.txt 내용 (시작 로그 확인):
if exist "%TRACEDIR%\debug_log.txt" (type "%TRACEDIR%\debug_log.txt") else (echo [DEBUG] debug_log.txt 파일이 생성되지 않았습니다.)
echo.
pause

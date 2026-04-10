@echo off
chcp 65001 >nul
setlocal

echo ==========================================
echo VM 내부 분석 파이프라인 (경로 직접 입력 모드)
echo ==========================================
echo.

:: 1. 경로 수동 입력받기
set /p TRACE_PARSER="1. trace_parser.py 파일의 전체 경로를 입력하세요: "
echo.
set /p TRACE_DIR="2. trace_*.done 파일들이 모여있는 폴더 경로를 입력하세요: "
echo.
set /p REPORT_DIR="3. 분석 결과를 저장할 새 폴더 경로를 입력하세요: "
echo.

:: (선택) 경로 앞뒤에 따옴표가 입력되었을 경우 제거하는 처리
set TRACE_PARSER=%TRACE_PARSER:"=%
set TRACE_DIR=%TRACE_DIR:"=%
set REPORT_DIR=%REPORT_DIR:"=%

:: 출력 폴더 생성
if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

echo [*] 분석을 시작합니다... (수백 개의 trace_*.done 파일 병합 파싱)
echo [!] 파일이 아주 많을 경우 시간이 다소 소요될 수 있습니다.

if not exist "%TRACE_PARSER%" (
    echo [ERROR] 파이썬 스크립트를 찾을 수 없습니다: "%TRACE_PARSER%"
    pause
    exit /b
)

python "%TRACE_PARSER%" --trace "%TRACE_DIR%\trace_*.done" --report "%REPORT_DIR%"

echo.
echo [*] Trace 분석이 완료되었습니다.
echo [*] 레포트는 다음 경로에 생성되었습니다: "%REPORT_DIR%"
echo [*] 바탕화면 등으로 이 폴더만 복사해 오시면 됩니다!
echo.
pause

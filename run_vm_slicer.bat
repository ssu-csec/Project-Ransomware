@echo off
chcp 65001 >nul
setlocal

echo ==========================================
echo VM 내부 메모리 분기 블록 추출 (경로 직접 입력)
echo ==========================================
echo.

:: 경로 수동 입력받기
set /p CONTEXT_SLICER="1. context_slicer.py 파일의 전체 경로를 입력하세요: "
echo.
set /p DUMP_DIR="2. 덤프 최상위 폴더 (예: C:\Users\user\Downloads\Build\dump_workspace) 경로를 입력하세요: "
echo.
set /p TARGET_JSON="3. 방금 생성된 target_cfg_blocks.json 파일 경로를 입력하세요: "
echo.
set /p OUT_JSON="4. 생성될 결과물(context_slices.json)의 전체 폴더/파일 경로를 지정하세요: "
echo.

:: (선택) 경로 앞뒤에 따옴표가 입력되었을 경우 제거하는 처리
set CONTEXT_SLICER=%CONTEXT_SLICER:"=%
set DUMP_DIR=%DUMP_DIR:"=%
set TARGET_JSON=%TARGET_JSON:"=%
set OUT_JSON=%OUT_JSON:"=%

:: 사용자가 폴더 경로만 입력했을 경우 파일명을 자동으로 붙여줌
if exist "%OUT_JSON%\" (
    set "OUT_JSON=%OUT_JSON%\context_slices.json"
)

echo [*] 메모리 분기 블록 (전체 덤프 대상) 추출을 시작합니다...
echo [!] 워크스페이스 내 덤프 폴더 수에 따라 상당히 오래 걸릴 수 있습니다 (커피 한 잔 다녀오세요).

if not exist "%CONTEXT_SLICER%" (
    echo [ERROR] 스크립트를 찾을 수 없습니다: "%CONTEXT_SLICER%"
    pause
    exit /b
)

:: 방금 작성한 자동화 파이썬 스크립트를 호출하여 내부적으로 context_slicer.py를 루프시킵니다.
set "BATCH_SLICER=%~dp0batch_slicer.py"
python "%BATCH_SLICER%" "%CONTEXT_SLICER%" "%DUMP_DIR%" "%TARGET_JSON%" "%OUT_JSON%"

echo.
echo [*] 일괄 추출 자동화가 완료되었습니다.
echo [*] 병합된 분기 컨텍스트는 다음 경로에 생성되었습니다: "%OUT_JSON%"
echo.
pause

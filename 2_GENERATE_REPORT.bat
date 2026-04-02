@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ====================================================
:: [Step 2] Ransomware Data Analyzer & Report Generator
:: ====================================================

echo [*] 수집된 데이터를 통합 분석하여 리포트를 생성합니다.
echo.

:: --- [사용자 설정 항목] ---
set "LOOT_DIR=C:\Users\user\Desktop\Ransom_Analysis_folder"
:: -------------------------

if not exist "%~dp0master_analyzer.py" (
    echo [!] 오류: master_analyzer.py 파일을 찾을 수 없습니다.
    pause
    exit /b 1
)

:: 1. 파이썬 실행 경로 탐색 (아나콘다 우선)
set "PY_EXE=python"
if exist "C:\Users\user\anaconda3\python.exe" (
    set "PY_EXE=C:\Users\user\anaconda3\python.exe"
)

echo [상태] 파이썬 경로: "!PY_EXE!"
echo [상태] 분석 파이프라인 가동... (%LOOT_DIR% 데이터 처리)
echo.

:: 2. 통합 분석기 실행
if exist "%~dp0master_analyzer.py" (
    "!PY_EXE!" "%~dp0master_analyzer.py" --loot "%LOOT_DIR%"
) else (
    echo [!] 오류: master_analyzer.py 파일을 찾을 수 없습니다.
)

echo.
echo [완료] 분석 리포트 생성이 끝났습니다.
pause

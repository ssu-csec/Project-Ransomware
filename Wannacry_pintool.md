set "PINROOT=C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows"
set "PIN=%PINROOT%\ia32\bin\pin.exe"
set "TOOL=%PINROOT%\source\tools\MyPinTool\Debug\MyPinTool.dll"
set "OUT=%USERPROFILE%\trace"

if not exist "%OUT%" mkdir "%OUT%"

"%PIN%" ^
  -follow_execv ^
  -logfile "%OUT%\pin_wc_all.log" ^
  -t "%TOOL%" ^
  -only_main 0 ^
  -follow_child 1 ^
  -log_images 0 ^
  -hot_iters 2000 ^
  -cap_max_ins 50000 ^
  -top 50 ^
  -prefix "%OUT%\wc_all" ^
  -- ^
  "C:\Users\user\Desktop\test\wannacry.exe"

///
mkdir "%USERPROFILE%\trace"

pushd "C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows\ia32\bin"

pin.exe ^
  -logfile "%USERPROFILE%\trace\pin_wc_all.log" ^
  -t "C:\Users\user\Downloads\pin-external-3.31-98869-gfa6f126a8-msvc-windows\source\tools\MyPinTool\Debug\MyPinTool.dll" ^
  -instrument_all 1 ^
  -follow_child 1 ^
  -only_main 0 ^
  -crypto_only 0 ^
  -hot_iters 2000 ^
  -top 200 ^
  -cap_max_ins 50000 ^
  -max_backedge_dist 2097152 ^
  -prefix "%USERPROFILE%\trace\wc_all" -- ^
  "C:\Users\user\Desktop\test\wannacry.exe"

popd
///


///
cd /d "C:\Users\user\trace"

python trace_parser.py --trace wc_all_P????.wct --meta wc_all_P????_meta.wcm --llm > report.txt
///

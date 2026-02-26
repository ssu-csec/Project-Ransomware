// === MyPinTool.cpp (Fast Hot-Loop Capture + TRACE-level IMG filter, no
// dangling pointers) === Pin 3.31 / Windows / IA-32 / MSVC (C++03 compatible)
//
// 핵심 유지 기능:
//  - taken back-edge 기반 loop 카운트(스레드별)
//  - hot_iters 이상 반복된 loop만 1 iteration 캡처(txt 생성)
//  - 캡처 완료 시 CSV에 1줄 append
//  - follow child 지원
//  - crypto DLL load/exec reach 로깅(images.txt) 옵션
//
// 최적화/안정화:
//  - INS_AddInstrumentFunction 대신 TRACE_AddInstrumentFunction 사용: IMG 판정
//  1회/TRACE
//  - IMG 로그는 버퍼링(매번 fflush 제거)
//  - CRYPTO_EXEC 로깅도 TRACE 단위로 1회만(중복 최소)
//  - rank_global을 전역 증가로 채움
//
// 출력:
//  CSV 헤더(요구사항 그대로):
//    tid,rank_global,rank_thread,start_addr,end_addr,body_len,iter,score,func,img,memR,memW,stackR,stackW,xor,addsub,shlshr,mul
//
// 주의:
//  - IA-32(32-bit) 타깃 전용 (WOW64 포함)

#ifdef _MSC_VER
#pragma warning(disable : 5208)
#endif

// STL includes MUST come before pin.H to avoid CRT conflicts (C2371, C2011)
// #include <algorithm> // REMOVED
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
// #include <fstream> // REMOVED to avoid LNK2019 conflicts
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility> // for pair
#include <vector>

// Pin header
#include "pin.H"

using namespace std;
// #include <Windows.h> // Removed to avoid conflict
namespace MyWin {
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

static const DWORD GENERIC_WRITE = 0x40000000L;
static const DWORD FILE_SHARE_READ = 0x00000001;
static const DWORD FILE_SHARE_WRITE = 0x00000002;
static const DWORD CREATE_ALWAYS = 2;
static const DWORD FILE_ATTRIBUTE_HIDDEN = 0x00000002;
static const DWORD FILE_ATTRIBUTE_SYSTEM = 0x00000004;
static const DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;
static const DWORD OPEN_ALWAYS = 4; // Open existing or create new
static const DWORD FILE_APPEND_DATA = 0x00000004;
static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)-1;

extern "C" __declspec(dllimport) HANDLE __stdcall
CreateFileA(const char *lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
            void *lpSecurityAttributes, DWORD dwCreationDisposition,
            DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

extern "C" __declspec(dllimport) BOOL __stdcall
WriteFile(HANDLE hFile, const void *lpBuffer, DWORD nNumberOfBytesToWrite,
          DWORD *lpNumberOfBytesWritten, void *lpOverlapped);

extern "C" __declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE hObject);

extern "C" __declspec(dllimport) DWORD __stdcall GetLastError();

typedef struct _MEMORY_BASIC_INFORMATION {
  void *BaseAddress;
  void *AllocationBase;
  DWORD AllocationProtect;
  size_t RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
} MEMORY_BASIC_INFORMATION;

extern "C" __declspec(dllimport) size_t __stdcall
VirtualQuery(const void *lpAddress, MEMORY_BASIC_INFORMATION *lpBuffer,
             size_t dwLength);
} // namespace MyWin

// Duplicate STL includes removed.
// using declarations removed (covered by using namespace std;)

// Universal Build: Supports both IA-32 and Intel64
// #if !defined(TARGET_IA32)
// #  error "This pintool is intended for IA-32 (32-bit) target only."
// #endif

// -------------------- Knobs --------------------
KNOB<BOOL> KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "0",
                        "Instrument only main executable (1=main only, 0=all)");

KNOB<BOOL> KnobInstrumentAll(
    KNOB_MODE_WRITEONCE, "pintool", "instrument_all", "0",
    "Instrument all images (overrides only_main/crypto_only)");

KNOB<BOOL>
    KnobFollowChild(KNOB_MODE_WRITEONCE, "pintool", "follow_child", "1",
                    "Follow child processes (spawned via CreateProcess)");

KNOB<UINT32> KnobTop(KNOB_MODE_WRITEONCE, "pintool", "top", "50",
                     "Max hot loops to capture per thread");

KNOB<UINT32>
    KnobHotIters(KNOB_MODE_WRITEONCE, "pintool", "hot_iters", "20000",
                 "Minimum iterations to trigger capture (hot loop threshold)");

KNOB<UINT32> KnobCapMaxIns(KNOB_MODE_WRITEONCE, "pintool", "cap_max_ins",
                           "20000",
                           "Max instructions to capture per loop iteration");

KNOB<UINT32> KnobMaxLoopIters(
    KNOB_MODE_WRITEONCE, "pintool", "break_iters", "0",
    "Max iterations before forcing loop exit (Loop Breaker, 0=Disabled)");

KNOB<string> KnobPrefix(
    KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace",
    "Output file prefix (can include folder, e.g. C:\\trace\\wc_all");

// --- Legacy Knobs (Restored for compatibility) ---
KNOB<UINT32> KnobMaxInsts(KNOB_MODE_WRITEONCE, "pintool", "max_insts", "500000",
                          "[Legacy] Unused in new binary log version (kept for "
                          "script compatibility)");

KNOB<BOOL> KnobCapAll(
    KNOB_MODE_WRITEONCE, "pintool", "cap_all", "0",
    "[Legacy] Unused (always captures hot loops) - Default changed to 0");

KNOB<BOOL> KnobEmitStubTrace(KNOB_MODE_WRITEONCE, "pintool", "emit_stub_trace",
                             "1", "[Legacy] Unused");

KNOB<BOOL> KnobResolveCsv(KNOB_MODE_WRITEONCE, "pintool", "resolve_csv", "1",
                          "[Legacy] Unused");

KNOB<BOOL> KnobLogMeta(KNOB_MODE_WRITEONCE, "pintool", "log_meta", "1",
                       "Enable Metadata logging (asm/img/name)");
// ------------------------------------------------

KNOB<BOOL> KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0",
                       "Enable verbose logging");

// --- Crypto DLL load/exec reach test knobs ---
KNOB<BOOL> KnobLogImages(KNOB_MODE_WRITEONCE, "pintool", "log_images", "1",
                         "Log IMG load/exec reach to images.txt");

KNOB<BOOL> KnobCryptoOnly(KNOB_MODE_WRITEONCE, "pintool", "crypto_only", "0",
                          "Instrument only crypto DLLs (for testing)");

KNOB<string> KnobCryptoDlls(
    KNOB_MODE_WRITEONCE, "pintool", "crypto_dlls",
    "cryptbase.dll;bcrypt.dll;bcryptprimitives.dll;crypt32.dll;ncrypt.dll;"
    "ncryptprov.dll;rsaenh.dll;dssenh.dll;schannel.dll;secur32.dll",
    "List of crypto DLL basenames (semicolon separated)");

KNOB<UINT32> KnobMaxBackedgeDist(KNOB_MODE_WRITEONCE, "pintool",
                                 "max_backedge_dist", "2097152",
                                 "Max backedge distance for loop detection");

// Pin root launcher adds -p64 internally for mixed-mode; absorb it here
// so PIN_Init does not reject it as an unknown option.
KNOB<string>
    KnobP64Path(KNOB_MODE_WRITEONCE, "pintool", "p64", "",
                "[internal] Path to 64-bit pin binary (auto-set by pin.exe)");

// Pin root launcher adds -t64 internally for mixed-mode; absorb it here
KNOB<string>
    KnobT64Path(KNOB_MODE_WRITEONCE, "pintool", "t64", "",
                "[internal] Path to 64-bit tool (auto-set by pin.exe)");

// -------------------- Utils --------------------
static string ToLowerStr(const string &s) {
  string t = s;
  for (size_t i = 0; i < t.size(); ++i)
    t[i] = (char)std::tolower((unsigned char)t[i]);
  return t;
}

static string Trim(const string &s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == string::npos)
    return "";
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

static void CsvWriteEscaped(FILE *fp, const string &s) {
  bool need = false;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == ',' || c == '"' || c == '\n' || c == '\r') {
      need = true;
      break;
    }
  }
  if (!need) {
    std::fputs(s.c_str(), fp);
    return;
  }
  std::fputc('"', fp);
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == '"')
      std::fputc('"', fp);
    std::fputc(c, fp);
  }
  std::fputc('"', fp);
}

static string Hex8(UINT32 x) {
  std::ostringstream oss;
  oss << std::hex << std::setw(8) << std::setfill('0') << x;
  return oss.str();
}

static string BaseNameLower(const string &path) {
  size_t p1 = path.find_last_of('\\');
  size_t p2 = path.find_last_of('/');
  size_t p = string::npos;
  if (p1 != string::npos && p2 != string::npos)
    p = (p1 > p2) ? p1 : p2;
  else if (p1 != string::npos)
    p = p1;
  else
    p = p2;

  string base = (p == string::npos) ? path : path.substr(p + 1);
  return ToLowerStr(base);
}

static void SplitSemicolonLower(const string &s, vector<string> &out) {
  out.clear();
  std::istringstream iss(s);
  string tok;
  while (std::getline(iss, tok, ';')) {
    tok = Trim(tok);
    if (!tok.empty())
      out.push_back(ToLowerStr(tok));
  }
}

// -------------------- Crypto list --------------------
// -------------------- Crypto list --------------------
static vector<string> *gCryptoDllList = NULL;

static void InitCryptoDllList() {
  gCryptoDllList = new vector<string>();
  SplitSemicolonLower(KnobCryptoDlls.Value(), *gCryptoDllList);
  SplitSemicolonLower(KnobCryptoDlls.Value(), *gCryptoDllList);
}

// Helper for safe debug logging (Global Scope)
static void LogDebug(const string &msg) {
  string logPath = string(getenv("USERPROFILE")) + "\\trace\\debug_log.txt";
  // [FIX] Add FILE_SHARE_WRITE to allow multiple processes (32/64 bit mixed
  // mode) to log simultaneously.
  MyWin::HANDLE hFile = MyWin::CreateFileA(
      logPath.c_str(), MyWin::FILE_APPEND_DATA,
      MyWin::FILE_SHARE_READ | MyWin::FILE_SHARE_WRITE, NULL,
      MyWin::OPEN_ALWAYS, MyWin::FILE_ATTRIBUTE_NORMAL, NULL);

  if (hFile != MyWin::INVALID_HANDLE_VALUE) {
    MyWin::DWORD written;
    MyWin::WriteFile(hFile, msg.c_str(), (MyWin::DWORD)msg.length(), &written,
                     NULL);
    MyWin::WriteFile(hFile, "\n", 1, &written, NULL); // Add newline
    MyWin::CloseHandle(hFile);
  }
}

static bool IsCryptoBaseLower(const string &baseLower) {
  if (!gCryptoDllList)
    return false;
  for (size_t i = 0; i < gCryptoDllList->size(); ++i) {
    if (baseLower == (*gCryptoDllList)[i])
      return true;
  }
  return false;
}

// -------------------- Static Meta --------------------
enum OpClass { OP_NONE = 0, OP_XOR, OP_ADDSUB, OP_SHLSHR, OP_MUL };

// --- Binary Structures (Packed) ---
#pragma pack(push, 1)
struct TraceEntry {
  ADDRINT ip;
  ADDRINT regs[8]; // EAX/RAX, EBX/RBX, ...
  ADDRINT memAddr; // 0 if no mem access
};

// -------------------- Globals --------------------
// static FILE *gTraceFp = NULL; // Unused
// static FILE *gMetaFp = NULL;  // REMOVED
static PIN_LOCK gMetaLock;
static PIN_LOCK gTraceLock;

// Using PIN_LOCK for simple atomic counter simulation or just use locked
// increment
static PIN_LOCK gGlobalSeqLock;
static UINT64 gGlobalLoopSeq = 0; // First-seen sequence (Changed to UINT64)

// Map to store FirstSeenSeq for each loop key (Header+BackEdge) to avoid
// re-assigning This fixes the "All GlobalSeq=0" issue or unstable sequencing.
static PIN_LOCK gFirstSeenLock;
static map<pair<ADDRINT, ADDRINT>, UINT32> *gLoopFirstSeen = NULL;

// Structs
// Loop Header Marker
#define MAGIC_LOOP_HEAD 0x4C4F4F50 // "LOOP"

struct LoopHeaderEntry {
  UINT32 magic;     // MAGIC_LOOP_HEAD
  UINT32 tid;       // Thread ID
  UINT32 header;    // Header IP (Start of Loop)
  UINT32 backedge;  // Backedge IP (End of Loop)
  UINT32 rank;      // Thread-local rank/score (heuristic)
  UINT32 globalSeq; // Global execution order (First Seen) [NEW]
};
#pragma pack(pop)

struct StaticMeta {
  ADDRINT addr; // full
  UINT32 addr32;
  string addrStr;
  string assembly;
  string funcName;
  string imgName;
  string opcLower;
  string memMeta; // Base|Index|Scale|Disp
  OpClass opClass;
  bool isStackMem;
};

static map<ADDRINT, StaticMeta *> *gMeta =
    NULL; // heap ptr: avoids destructor crash after Pin teardown
// static PIN_LOCK gMetaLock; // Defined in block at line ~266

// -------------------- Globals for I/O Log --------------------
// static FILE* gIoFp = NULL; // REMOVED
// static PIN_LOCK gIoLock;   // REMOVED

// -------------------- Trace Dump (Text) --------------------
// -------------------- Trace Dump (Text) --------------------
static string *gTracePath = NULL; // Text Trace
static MyWin::HANDLE gTraceHandle = MyWin::INVALID_HANDLE_VALUE;

// -------------------- Optimization: Global Buffer & Fast Hex
// --------------------
static const size_t GLOBAL_BUF_SIZE = 64 * 1024; // 64KB buffer
static string *gGlobalBuf = NULL;                // Protected by gTraceLock

static void FlushGlobalBuffer() {
  if (!gGlobalBuf || gGlobalBuf->empty())
    return;
  if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE)
    return;

  MyWin::DWORD written = 0;
  MyWin::WriteFile(gTraceHandle, gGlobalBuf->c_str(),
                   (MyWin::DWORD)gGlobalBuf->size(), &written, NULL);
  gGlobalBuf->clear();
  // reserve to avoid realloc?
  if (gGlobalBuf->capacity() < GLOBAL_BUF_SIZE)
    gGlobalBuf->reserve(GLOBAL_BUF_SIZE);
}

static void WriteGlobalTrace(const string &msg) {
  if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE)
    return;

  // Safe init check (just in case called before main init, though unlikely with
  // locks)
  if (!gGlobalBuf)
    return;

  PIN_GetLock(&gTraceLock, 1);
  *gGlobalBuf += msg;
  if (gGlobalBuf->size() >= GLOBAL_BUF_SIZE) {
    FlushGlobalBuffer();
  }
  PIN_ReleaseLock(&gTraceLock);
}

// Fast Hex (No sprintf)
static const char HEX_DIGITS[] = "0123456789abcdef";

static inline void FastHex32(char *&p, UINT32 v) {
  // Variable length hex? Or fixed 8?
  // Let's do variable for compactness like %x
  if (v == 0) {
    *p++ = '0';
    return;
  }
  char buf[8];
  int i = 0;
  while (v) {
    buf[i++] = HEX_DIGITS[v & 0xF];
    v >>= 4;
  }
  while (i > 0)
    *p++ = buf[--i];
}

static inline void FastHexAddr(char *&p, ADDRINT v) {
  if (v == 0) {
    *p++ = '0';
    return;
  }
  char buf[16]; // 64-bit safe
  int i = 0;
  while (v) {
    buf[i++] = HEX_DIGITS[v & 0xF];
    v >>= 4;
  }
  while (i > 0)
    *p++ = buf[--i];
}

// -------------------- Loop Key / Stats --------------------
struct LoopKey {
  ADDRINT header;
  ADDRINT backedge;

  bool operator<(const LoopKey &o) const {
    if (header != o.header)
      return header < o.header;
    return backedge < o.backedge;
  }
};

struct LoopAgg {
  UINT64 iters;
  bool captured;
  UINT32 globalSeq;

  UINT64 body_len;
  UINT64 memR, memW, stackR, stackW;
  UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;

  string func;
  string img;
  string tracePath;

  LoopAgg()
      : iters(0), captured(false), globalSeq(0), body_len(0), memR(0), memW(0),
        stackR(0), stackW(0), xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0) {
  }
};

struct CaptureState {
  bool armed;
  bool recording;

  LoopKey key;
  UINT32 rank_thread;

  UINT64 capIns;
  UINT64 capMaxIns;

  string func;
  string img;

  UINT64 body_len;
  UINT64 memR, memW, stackR, stackW;
  UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;
  UINT64 reg_accum;

  bool candValid;
  LoopKey candKey;
  UINT64 candIters;

  CaptureState()
      : armed(false), recording(false), rank_thread(0), capIns(0), capMaxIns(0),
        body_len(0), memR(0), memW(0), stackR(0), stackW(0), xorCnt(0),
        addsubCnt(0), shlshrCnt(0), mulCnt(0), reg_accum(0), candValid(false),
        candIters(0) {
    candKey.header = 0;
    candKey.backedge = 0;
    key.header = 0;
    key.backedge = 0;
  }
};

struct TData {
  UINT32 tid;    // Pin Thread ID
  UINT32 os_tid; // OS Thread ID
  map<LoopKey, LoopAgg> loops;
  UINT32 capturedCount;
  CaptureState cap;

  // Loop Hierarchy Stack [NEW]
  vector<ADDRINT> loopStack;

  // Buffering - Text Buffer
  string loopBuf;

  TData() : os_tid(0), capturedCount(0) { loopBuf.reserve(64 * 1024); }
};

// Forward Declarations
static void StopAndCommitCapture(TData *td, const char *reason);
static void ArmBestCandidateIfIdle(TData *td);
static void
StartCaptureAtHeader(TData *td,
                     const StaticMeta *headerMeta); // Added forward decl

static void FlushBuffer(TData *td) {
  if (td->loopBuf.empty())
    return;

  if (gTraceHandle != MyWin::INVALID_HANDLE_VALUE) {
    PIN_GetLock(&gTraceLock, 1);
    MyWin::DWORD written = 0;
    MyWin::WriteFile(gTraceHandle, td->loopBuf.c_str(),
                     (MyWin::DWORD)td->loopBuf.size(), &written, NULL);
    PIN_ReleaseLock(&gTraceLock);
  }

  td->loopBuf.clear();
}

static void BufferedWriteText(TData *td, const string &s) {
  td->loopBuf += s;
  // Chunked Flush: Write to disk every 4KB to prevent data loss on crash
  if (td->loopBuf.size() > 4096) {
    FlushBuffer(td);
  }
}

static TLS_KEY gTlsKey;

// -------------------- Output files --------------------
// -------------------- Output files --------------------
static string *gRunPrefix = NULL; // prefix + "_P<pid>"
static string *gCsvPath = NULL;   // Statistics CSV (Summary)
// static FILE* gCsvFp = NULL; // already static global? Re-check
// static PIN_LOCK gCsvLock;   // already static global? Re-check
// Wait, gCsvFp was not in the top block. Only gMetaFp was re-defined.

static FILE *gCsvFp = NULL;
static PIN_LOCK gCsvLock;

// static string gTracePath; // Moved to top
// static MyWin::HANDLE gTraceHandle = ...
// static PIN_LOCK gTraceLock;

static string *gMetaPath = NULL; // Static Meta
// static FILE* gMetaFp = NULL; // Redefined, remove this line.
static set<string> *gCryptoExecLogged = NULL; // basename lower

// 큰 버퍼(오버헤드 감소)
static char *gCsvBuf = NULL;

// -------------------- Saved Pin cmdline for child --------------------
static INT gSavedArgc = 0;
static const CHAR **gSavedArgv = NULL;

// -------------------- IMG log --------------------
// -------------------- IMG/Meta log (Moved to DumpStaticMeta)
// -------------------- Removed dynamic ImgLogLine_NoFlush since we will dump
// static meta at the end.

// -------------------- CSV --------------------
// Helper for CSV escaping to string
static string EscapeCsv(const string &s) {
  if (s.find_first_of(",\"\n\r") == string::npos)
    return s;
  string ret = "\"";
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '"')
      ret += "\"\"";
    else
      ret += s[i];
  }
  ret += "\"";
  return ret;
}

static void AppendLoopRowToCsv(UINT32 tid, UINT32 rank_global,
                               ADDRINT start_addr, ADDRINT end_addr,
                               UINT64 body_len, UINT64 iterCount, double score,
                               const string &func, const string &img,
                               UINT64 memR, UINT64 memW, UINT64 stackR,
                               UINT64 stackW, UINT64 xorCnt, UINT64 addsubCnt,
                               UINT64 shlshrCnt, UINT64 mulCnt) {
  // Unified Trace CSV
  std::ostringstream oss;
  oss << "EXT_CSV:" << tid << "," << rank_global << ",0," << std::hex
      << start_addr << "," << end_addr << std::dec << "," << body_len << ","
      << iterCount << "," << (long long)score << "," << EscapeCsv(func).c_str()
      << "," << EscapeCsv(img).c_str() << "," << memR << "," << memW << ","
      << stackR << "," << stackW << "," << xorCnt << "," << addsubCnt << ","
      << shlshrCnt << "," << mulCnt << "\n";

  WriteGlobalTrace(oss.str());
}

// -------------------- StaticMeta builder --------------------
// TRACE 단위로 IMG 이름/lowaddr를 전달받아 IMG_FindByAddress 호출을 줄임
static StaticMeta *GetOrCreateMeta(INS ins, ADDRINT a,
                                   const string &traceImgName,
                                   ADDRINT traceImgLow) {
  StaticMeta *sm = NULL;

  PIN_GetLock(&gMetaLock, 1);
  map<ADDRINT, StaticMeta *>::iterator it = gMeta->find(a);
  if (it != gMeta->end()) {
    sm = it->second;
    PIN_ReleaseLock(&gMetaLock);
    return sm;
  }
  PIN_ReleaseLock(&gMetaLock);

  StaticMeta *m = new StaticMeta();
  m->opClass = OP_NONE; // Fix UB if log_meta=0
  m->addr = a;
  m->addr32 = (UINT32)a;
  m->addrStr = Hex8((UINT32)a);
  // Disassemble only if log_meta is on or for debug?
  // We assume parser always needs generic ASM?
  // Actually generic parser relies on it. But for extreme speed user can
  // disable.
  if (KnobLogMeta.Value()) {
    m->assembly = INS_Disassemble(ins);

    // opcode lower
    {
      std::istringstream iss(m->assembly);
      string opc;
      iss >> opc;
      m->opcLower = ToLowerStr(opc);
    }
  } else {
    m->assembly = "disasm_disabled";
    m->opcLower = "unknown";
  }

  // opClass logic needs opcLower
  // If meta logging disabled, we probably can't classify op?
  // We can try to decode opcode bytes manually or just INS_Opcode(ins) enum.
  // For now, let's assume if log_meta=0, we skip opClass checks to save speed?
  // OR we just use INS_Opcode.
  // Let's stick to simple: if LogMeta=0, we just do minimal.
  // BUT we need opClass for stats (XOR/ADD etc).
  // Let's compute opClass from INS_Opcode ideally, but sticking to string for
  // now. Optimization: If user wants speed, they might accept loss of OpClass
  // stats.

  // Recovery for OpClass if string suppressed?
  // Let's just do the string op if LogMeta is ON.
  if (KnobLogMeta.Value()) {
    m->opClass = OP_NONE;
    if (m->opcLower == "xor" || m->opcLower == "pxor" || m->opcLower == "vpxor")
      m->opClass = OP_XOR;
    else if (m->opcLower == "add" || m->opcLower == "sub" ||
             m->opcLower == "adc" || m->opcLower == "sbb" ||
             m->opcLower == "inc" || m->opcLower == "dec")
      m->opClass = OP_ADDSUB;
    else if (m->opcLower == "shl" || m->opcLower == "sal" ||
             m->opcLower == "shr" || m->opcLower == "sar" ||
             m->opcLower == "rol" || m->opcLower == "ror")
      m->opClass = OP_SHLSHR;
    else if (m->opcLower == "mul" || m->opcLower == "imul" ||
             m->opcLower == "fmul")
      m->opClass = OP_MUL;
  }

  // func/img
  m->imgName = traceImgName;
  if (m->imgName.empty())
    m->imgName = "Unmapped/Shellcode";

  {
    string funcName;
    RTN rtn = INS_Rtn(ins);
    if (!RTN_Valid(rtn))
      rtn = RTN_FindByAddress(a);

    if (RTN_Valid(rtn)) {
      string rawName = RTN_Name(rtn);
      string undec = PIN_UndecorateSymbolName(rawName, UNDECORATION_NAME_ONLY);
      funcName = undec.empty() ? rawName : undec;

      // imgName 보정: RTN 기반 SEC->IMG가 더 정확할 때가 있음
      SEC sec = RTN_Sec(rtn);
      if (SEC_Valid(sec)) {
        IMG imgForFunc = SEC_Img(sec);
        if (IMG_Valid(imgForFunc)) {
          string fixImg = IMG_Name(imgForFunc);
          if (!fixImg.empty())
            m->imgName = fixImg;
        }
      }
    } else {
      // fallback: IMG+offset or raw addr
      if (!traceImgName.empty() && traceImgLow != 0) {
        std::ostringstream oss;
        oss << traceImgName << "+0x" << std::hex << (a - traceImgLow);
        funcName = oss.str();
      } else {
        std::ostringstream oss;
        oss << "func_0x" << std::hex << a;
        funcName = oss.str();
      }
    }
    if (funcName.empty())
      funcName = "Unknown_Func";
    m->funcName = funcName;
  }

  // stack mem? & memMeta construction
  m->isStackMem = false;
  if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
    REG base = INS_MemoryBaseReg(ins);
    REG idx = INS_MemoryIndexReg(ins);
    UINT32 scale = INS_MemoryScale(ins);
    ADDRINT disp = INS_MemoryDisplacement(ins);

    if (base == REG_ESP || base == REG_EBP || idx == REG_ESP || idx == REG_EBP)
      m->isStackMem = true;

    // Save structured info: BaseName|IndexName|Scale|Disp
    std::ostringstream moss;
    moss << (REG_valid(base) ? REG_StringShort(base) : "") << "|"
         << (REG_valid(idx) ? REG_StringShort(idx) : "") << "|" << scale << "|"
         << disp;
    m->memMeta = moss.str();
  }

  PIN_GetLock(&gMetaLock, 1);
  // Double-check pattern to avoid race/dup/leak
  map<ADDRINT, StaticMeta *>::iterator it2 = gMeta->find(a);
  if (it2 != gMeta->end()) {
    PIN_ReleaseLock(&gMetaLock);
    delete m; // Discard duplicate
    return it2->second;
  }

  gMeta->insert(std::make_pair(a, m));

  // Incremental Dump (Unified Trace)
  if (KnobLogMeta.Value()) {
    std::ostringstream moss;
    moss << "EXT_META:" << std::hex << m->addr << ","; // Use full addr
    moss << EscapeCsv(m->funcName).c_str() << ","
         << EscapeCsv(m->imgName).c_str() << ","
         << EscapeCsv(m->assembly).c_str() << ",";

    // MemStruct (Base|Index|Scale|Disp)
    if (!m->memMeta.empty())
      moss << EscapeCsv(m->memMeta).c_str();

    moss << "\n";
    WriteGlobalTrace(moss.str());
  }

  // (gMetaFp logic removed)

  PIN_ReleaseLock(&gMetaLock);

  return m;
}

// -------------------- Trace Dump (Binary) --------------------
// -------------------- Trace Dump (Binary) --------------------
// Removed direct WriteBinaryEntry, replaced with BufferedWrite calls

static void WriteLoopEnter(TData *td, UINT32 tid, ADDRINT header,
                           ADDRINT backedge, UINT32 rank, ADDRINT parent,
                           UINT32 depth) {
  // HEADER Format: LOOP_ENTER,tid,header,backedge,rank,globalSeq,parent,depth
  UINT32 gSeq = 0;
  LoopKey k;
  k.header = header;
  k.backedge = backedge;
  if (td->loops.count(k))
    gSeq = td->loops[k].globalSeq;

  std::ostringstream oss;
  oss << "LOOP_ENTER," << tid << "," << std::hex << header << "," << backedge
      << "," << std::dec << rank << "," << gSeq << "," << std::hex << parent
      << "," << std::dec << depth << "\n";
  BufferedWriteText(td, oss.str());
}

// -------------------- Capture control --------------------
static void ResetCaptureStats(CaptureState &c) {
  c.capIns = 0;
  c.body_len = 0;
  c.memR = c.memW = c.stackR = c.stackW = 0;
  c.xorCnt = c.addsubCnt = c.shlshrCnt = c.mulCnt = 0;
  c.func.clear();
  c.img.clear();
}

static inline void AccumulateOp(const StaticMeta *sm, CaptureState &c) {
  if (!sm)
    return;
  if (sm->opClass == OP_XOR)
    c.xorCnt++;
  else if (sm->opClass == OP_ADDSUB)
    c.addsubCnt++;
  else if (sm->opClass == OP_SHLSHR)
    c.shlshrCnt++;
  else if (sm->opClass == OP_MUL)
    c.mulCnt++;
}

static void StopAndCommitCapture(TData *td, const char *reason) {
  CaptureState &c = td->cap;
  if (!c.recording)
    return;

  if (c.recording) {
    // Recording ended, flush buffer ATOMICALLY
    FlushBuffer(td);
  }
  c.recording = false;

  map<LoopKey, LoopAgg>::iterator it = td->loops.find(c.key);
  if (it != td->loops.end()) {
    LoopAgg &agg = it->second;
    agg.captured = true;
    agg.body_len = c.body_len;
    agg.memR = c.memR;
    agg.memW = c.memW;
    agg.stackR = c.stackR;
    agg.stackW = c.stackW;
    agg.xorCnt = c.xorCnt;
    agg.addsubCnt = c.addsubCnt;
    agg.shlshrCnt = c.shlshrCnt;
    agg.mulCnt = c.mulCnt;
    agg.func = c.func;
    agg.img = c.img;
    if (gTracePath)
      agg.tracePath = *gTracePath; // All in one

    UINT64 iterCount = agg.iters;

    // LOOP_FINISH 레코드 출력 [NEW]
    std::ostringstream oss;
    oss << "LOOP_FINISH," << td->os_tid << "," << std::hex << c.key.header
        << "," << c.key.backedge << "," << std::dec << iterCount << "\n";
    BufferedWriteText(td, oss.str());

    double score = (double)agg.body_len * (double)iterCount;
    AppendLoopRowToCsv(td->os_tid,
                       agg.globalSeq, // FIXED: Pass GlobalSeq, not ThreadRank
                       c.key.header, c.key.backedge, agg.body_len, iterCount,
                       score, agg.func, agg.img, agg.memR, agg.memW, agg.stackR,
                       agg.stackW, agg.xorCnt, agg.addsubCnt, agg.shlshrCnt,
                       agg.mulCnt);

    if (KnobVerbose.Value()) {
      cerr << "[pin-loop] capture done TID=" << td->os_tid << " L"
           << c.rank_thread << " H=" << std::hex << c.key.header
           << " B=" << std::hex << c.key.backedge << std::dec
           << " reason=" << reason
           << " body_len=" << (unsigned long long)agg.body_len
           << " iters=" << (unsigned long long)iterCount << endl;
    }
  }

  c.armed = false;
  c.key.header = 0;
  c.key.backedge = 0;
}

static void ArmBestCandidateIfIdle(TData *td) {
  CaptureState &c = td->cap;
  if (c.recording)
    return;
  if (td->capturedCount >= KnobTop.Value())
    return;
  if (!c.candValid)
    return;

  map<LoopKey, LoopAgg>::iterator it = td->loops.find(c.candKey);
  if (it == td->loops.end()) {
    c.candValid = false;
    return;
  }
  if (it->second.captured) {
    c.candValid = false;
    return;
  }

  c.key = c.candKey;
  c.armed = true;
}

static void StartCaptureAtHeader(TData *td, const StaticMeta *headerMeta) {
  CaptureState &c = td->cap;
  if (!c.armed)
    return;
  if (c.recording)
    return;

  td->capturedCount++;
  c.rank_thread = td->capturedCount;

  c.rank_thread = td->capturedCount;

  ResetCaptureStats(c);

  // START NEW CAPTURE: Clear buffer first (should be empty if logic is correct)
  td->loopBuf.clear();

  c.capMaxIns = (UINT64)KnobCapMaxIns.Value();
  c.recording = true;

  c.func = headerMeta ? headerMeta->funcName : "";
  c.img = headerMeta ? headerMeta->imgName : "";

  // Write Header to Global Trace File
  ADDRINT parent = td->loopStack.empty() ? 0 : td->loopStack.back();
  UINT32 depth = (UINT32)td->loopStack.size();

  WriteLoopEnter(td, td->os_tid, c.key.header, c.key.backedge, c.rank_thread,
                 parent, depth);

  // Push to stack [NEW]
  td->loopStack.push_back(c.key.header);

  if (KnobVerbose.Value()) {
    cerr << "[pin-loop] capture start TID=" << td->os_tid << " L"
         << c.rank_thread << " H=" << std::hex << c.key.header
         << " B=" << std::hex << c.key.backedge << std::dec << endl;
  }

  c.armed = false;
}

// -------------------- Fast IF --------------------
static VOID CapIf(THREADID tid, const StaticMeta *sm) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm)
    return;

  CaptureState &c = td->cap;
  if (c.recording)
    return;

  if (c.armed && sm->addr32 == c.key.header) {
    StartCaptureAtHeader(td, sm);
  }
}

// -------------------- Record (THEN) --------------------
// -------------------- Record (THEN) - Text (Optimized) --------------------
static void CapRecordNoMem(THREADID tid, const StaticMeta *sm, CONTEXT *ctxt) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm)
    return;

  CaptureState &c = td->cap;
  if (!c.recording)
    return;

  ADDRINT eax = PIN_GetContextReg(ctxt, REG_GAX);
  ADDRINT ebx = PIN_GetContextReg(ctxt, REG_GBX);
  ADDRINT ecx = PIN_GetContextReg(ctxt, REG_GCX);
  ADDRINT edx = PIN_GetContextReg(ctxt, REG_GDX);
  ADDRINT esi = PIN_GetContextReg(ctxt, REG_GSI);
  ADDRINT edi = PIN_GetContextReg(ctxt, REG_GDI);
  ADDRINT esp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
  ADDRINT ebp = PIN_GetContextReg(ctxt, REG_GBP);

  // Manual fast formatting: "I,IP,0,regs...\n"
  char buf[256];
  char *p = buf;
  *p++ = 'I';
  *p++ = ',';
  FastHex32(p, sm->addr32);
  *p++ = ',';
  *p++ = '0';
  *p++ = ','; // No mem
  FastHex32(p, eax);
  *p++ = ',';
  FastHex32(p, ebx);
  *p++ = ',';
  FastHex32(p, ecx);
  *p++ = ',';
  FastHex32(p, edx);
  *p++ = ',';
  FastHex32(p, esi);
  *p++ = ',';
  FastHex32(p, edi);
  *p++ = ',';
  FastHex32(p, esp);
  *p++ = ',';
  FastHex32(p, ebp);
  *p++ = '\n';
  *p = 0;

  td->loopBuf.append(buf, p - buf);
  if (td->loopBuf.size() > 4096)
    FlushBuffer(td);

  c.body_len++;
  AccumulateOp(sm, c);

  c.capIns++;
  if (c.capIns >= c.capMaxIns) {
    StopAndCommitCapture(td, "cap_max_ins");
  }
}

static void CapRecordMemR(THREADID tid, const StaticMeta *sm, ADDRINT ea,
                          CONTEXT *ctxt) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm)
    return;

  CaptureState &c = td->cap;
  if (!c.recording)
    return;

  ADDRINT eax = PIN_GetContextReg(ctxt, REG_GAX);
  ADDRINT ebx = PIN_GetContextReg(ctxt, REG_GBX);
  ADDRINT ecx = PIN_GetContextReg(ctxt, REG_GCX);
  ADDRINT edx = PIN_GetContextReg(ctxt, REG_GDX);
  ADDRINT esi = PIN_GetContextReg(ctxt, REG_GSI);
  ADDRINT edi = PIN_GetContextReg(ctxt, REG_GDI);
  ADDRINT esp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
  ADDRINT ebp = PIN_GetContextReg(ctxt, REG_GBP);

  char buf[512];
  char *p = buf;
  *p++ = 'R';
  *p++ = ',';
  FastHexAddr(p, sm->addr);
  *p++ = ',';
  FastHexAddr(p, ea);
  *p++ = ',';
  FastHexAddr(p, eax);
  *p++ = ',';
  FastHexAddr(p, ebx);
  *p++ = ',';
  FastHexAddr(p, ecx);
  *p++ = ',';
  FastHexAddr(p, edx);
  *p++ = ',';
  FastHexAddr(p, esi);
  *p++ = ',';
  FastHexAddr(p, edi);
  *p++ = ',';
  FastHexAddr(p, esp);
  *p++ = ',';
  FastHexAddr(p, ebp);
  *p++ = '\n';
  *p = 0;

  td->loopBuf.append(buf, p - buf);
  if (td->loopBuf.size() > 4096)
    FlushBuffer(td);

  c.body_len++;
  c.memR++;
  if (sm->isStackMem)
    c.stackR++;
  AccumulateOp(sm, c);

  c.capIns++;
  if (c.capIns >= c.capMaxIns) {
    StopAndCommitCapture(td, "cap_max_ins");
  }
}

static void CapRecordMemW(THREADID tid, const StaticMeta *sm, ADDRINT ea,
                          CONTEXT *ctxt) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm)
    return;

  CaptureState &c = td->cap;
  if (!c.recording)
    return;

  ADDRINT eax = PIN_GetContextReg(ctxt, REG_GAX);
  ADDRINT ebx = PIN_GetContextReg(ctxt, REG_GBX);
  ADDRINT ecx = PIN_GetContextReg(ctxt, REG_GCX);
  ADDRINT edx = PIN_GetContextReg(ctxt, REG_GDX);
  ADDRINT esi = PIN_GetContextReg(ctxt, REG_GSI);
  ADDRINT edi = PIN_GetContextReg(ctxt, REG_GDI);
  ADDRINT esp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
  ADDRINT ebp = PIN_GetContextReg(ctxt, REG_GBP);

  // Manual fast formatting: "W,IP,EA,regs...\n"
  char buf[512];
  char *p = buf;
  *p++ = 'W';
  *p++ = ',';
  FastHexAddr(p, sm->addr);
  *p++ = ',';
  FastHexAddr(p, ea);
  *p++ = ',';
  FastHexAddr(p, eax);
  *p++ = ',';
  FastHexAddr(p, ebx);
  *p++ = ',';
  FastHexAddr(p, ecx);
  *p++ = ',';
  FastHexAddr(p, edx);
  *p++ = ',';
  FastHexAddr(p, esi);
  *p++ = ',';
  FastHexAddr(p, edi);
  *p++ = ',';
  FastHexAddr(p, esp);
  *p++ = ',';
  FastHexAddr(p, ebp);
  *p++ = '\n';
  *p = 0;

  td->loopBuf.append(buf, p - buf);
  if (td->loopBuf.size() > 4096)
    FlushBuffer(td);

  c.body_len++;
  c.memW++;
  if (sm->isStackMem)
    c.stackW++;
  AccumulateOp(sm, c);

  c.capIns++;
  if (c.capIns >= c.capMaxIns) {
    StopAndCommitCapture(td, "cap_max_ins");
  }
}

// -------------------- Loop counter (taken back-edge) --------------------
static VOID OnTakenBranch(CONTEXT *ctxt, THREADID tid, ADDRINT ip,
                          ADDRINT target, ADDRINT fallthrough) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td)
    return;

  if (target >= ip)
    return; // backward only

  UINT32 backedge = (UINT32)ip;
  UINT32 header = (UINT32)target;

  // backward
  // Check Max Distance
  if ((UINT32)(ip - target) > KnobMaxBackedgeDist.Value()) {
    // too far, likely not a loop (e.g. ret to caller in high mem)
    return;
  }

  LoopKey key;
  key.header = header;
  key.backedge = backedge;

  // LOOP BREAKER LOGIC
  if (KnobMaxLoopIters.Value() > 0 && td->loops.count(key) &&
      td->loops[key].iters >= KnobMaxLoopIters.Value()) {
    LoopAgg &agg = td->loops[key];
    if (agg.iters == KnobMaxLoopIters.Value()) {
      cerr << "\n[pin-loop] *** LOOP BREAKER TRIGGERED ***" << endl;
      cerr << "  Thread: " << td->os_tid << endl;
      cerr << "  Header: 0x" << std::hex << header << endl;
      cerr << "  Count:  " << std::dec << agg.iters << endl;
      cerr << "  Action: Forcing jump to Fallthrough (0x" << std::hex
           << fallthrough << ")" << endl;
    }
    PIN_SetContextReg(ctxt, REG_INST_PTR, fallthrough);
    PIN_ExecuteAt(ctxt);
    return;
  }

  // Hierarchy Maintenance [NEW]
  // 만약 현재 header가 스택 top과 다르다면 (새 루프 진입 시도)
  // 스택을 검사하여 현재 header가 이미 스택에 있는지 확인 (재귀 또는 루프 탈출
  // 후 재진입)
  if (!td->loopStack.empty()) {
    if (header != td->loopStack.back()) {
      // 만약 스택의 어딘가에 이 header가 있다면, 그 위를 모두 날림 (이미 나간
      // 루프들)
      bool found = false;
      for (size_t i = 0; i < td->loopStack.size(); ++i) {
        if (td->loopStack[i] == header) {
          td->loopStack.resize(i + 1);
          found = true;
          break;
        }
      }
      // 못 찾았다면 새롭게 들어가는 계층 (StartCaptureAtHeader에서 push됨)
    }
  }

  // Check FirstSeenSeq for this loop variant (Global Stability)
  UINT32 seq = 0;

  // Optimization: Check if agg already has it?
  // Thread-local 'agg' might be fresh if map lookup, but 'td->loops' persists
  // for thread life. However, multiple threads might see same loop code. We
  // want GLOBAL first seen. So we check global map.

  // Double-checked locking or just lock? Lock is safer.
  // Optimization: Read without lock? Map is not thread safe for read
  // overlapping write. Use lock.
  PIN_GetLock(&gFirstSeenLock, 1);

  // Use explicit std::pair and std::map to avoid ambiguity
  pair<ADDRINT, ADDRINT> valKey = make_pair((ADDRINT)header, (ADDRINT)backedge);
  map<pair<ADDRINT, ADDRINT>, UINT32>::iterator it =
      gLoopFirstSeen->find(valKey);

  if (it != gLoopFirstSeen->end()) {
    seq = it->second;
  } else {
    // New Loop detected globally!
    PIN_GetLock(&gGlobalSeqLock, 1);
    gGlobalLoopSeq++;
    seq = (UINT32)gGlobalLoopSeq;
    PIN_ReleaseLock(&gGlobalSeqLock);

    (*gLoopFirstSeen)[valKey] = seq;
  }
  PIN_ReleaseLock(&gFirstSeenLock);

  LoopAgg &agg = td->loops[key];
  if (agg.globalSeq == 0)
    agg.globalSeq = seq; // Assign once
  agg.iters++;

  // Relaxed: if target == header, treat as loop boundary
  if (td->cap.recording && td->cap.key.header == target) {
    StopAndCommitCapture(td, "iteration_end");
    ArmBestCandidateIfIdle(td);
    return;
  }

  // Maintain hot candidate (keep max iters one)
  // Check threshold (KnobHotIters or 1 if CapAll)
  // NOTE: KnobCapAll defaults to 0 now.
  UINT64 threshold = KnobCapAll.Value() ? 1 : (UINT64)KnobHotIters.Value();

  if (!agg.captured && agg.iters >= threshold) {
    if (!td->cap.candValid || agg.iters > td->cap.candIters) {
      td->cap.candValid = true;
      td->cap.candKey = key;
      td->cap.candIters = agg.iters;
    }
  }

  // Arm candidate if idle
  if (!td->cap.recording) {
    if (!td->cap.armed)
      ArmBestCandidateIfIdle(td);
  }
}

// [Duplicate OnTrace Body Removed]
// -------------------- Safe Return (Anti-Pollution) --------------------
static void OnRet(THREADID tid) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !td->cap.recording)
    return;

  // Stop immediately on RET to prevent capturing unrelated code
  StopAndCommitCapture(td, "ret_instruction");
}

// -------------------- I/O Logging --------------------
static void OnIoCall(THREADID mid, const char *apiName, ADDRINT handle,
                     ADDRINT arg2) {
  // Trace Unified IO Log
  // FIX: Use OS TID to match Trace file (mid is Pin TID)
  UINT32 os_tid = (UINT32)PIN_GetTid();

  std::ostringstream oss;
  oss << "IO:" << os_tid << "," << apiName << "," << std::hex << handle << ","
      << arg2 << "\n";
  WriteGlobalTrace(oss.str());
}

// -------------------- Child Loop Logging --------------------
static VOID LogChildLoop(THREADID tid, ADDRINT headerAddr) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !td->cap.recording)
    return;

  if (td->cap.key.header != headerAddr) {
    char buf[128];
    char *p = buf;
    // strcpy/memcpy "EXT_CHILD_LOOP,"
    const char PRE[] = "EXT_CHILD_LOOP,";
    for (int i = 0; PRE[i]; ++i)
      *p++ = PRE[i];
    FastHexAddr(p, headerAddr);
    *p++ = '\n';
    *p = 0;

    td->loopBuf.append(buf, p - buf);
    if (td->loopBuf.size() > 4096)
      FlushBuffer(td);
  }
}

// -------------------- Trace Instrumentation --------------------
static VOID OnTrace(TRACE trace, VOID *v) {
  // TRACE-level filtering
  if (!KnobInstrumentAll.Value()) {
    // ... (Keep existing filtering logic if possible, but for brevity check
    // IMG) Assuming existing logic is fine.
  }

  ADDRINT addr = TRACE_Address(trace);
  IMG img = IMG_FindByAddress(addr);
  bool instrument = false;
  bool bimgValid = IMG_Valid(img);
  string bimgName = bimgValid ? IMG_Name(img) : "";
  ADDRINT bimgLow = bimgValid ? IMG_LowAddress(img) : 0;

  // Simplified TRACE check (Reuse existing logic concepts)
  if (KnobInstrumentAll.Value())
    instrument = true;
  else if (!bimgValid)
    instrument = true;
  else if (IMG_IsMainExecutable(img))
    instrument = true;
  else if (KnobCryptoOnly.Value()) {
    if (IsCryptoBaseLower(BaseNameLower(bimgName)))
      instrument = true;
  } else if (!KnobOnlyMain.Value()) {
    instrument = true; // Capture all modules if only_main is disabled
  }

  if (!instrument)
    return;

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      StaticMeta *sm =
          GetOrCreateMeta(ins, INS_Address(ins), bimgName, bimgLow);

      // 1) Loop Count (Taken Branch)
      if (INS_IsBranch(ins)) {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnTakenBranch,
                       IARG_CONTEXT, // For Loop Breaker
                       IARG_THREAD_ID, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
                       IARG_ADDRINT,
                       INS_NextAddress(ins), // Fallthrough address
                       IARG_END);
      }

      // 2) Capture Start - Direct call without If/Then pattern
      // The CapIf function will check internally if capture should start

      // [NEW] Log Child Loop Detection
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogChildLoop, IARG_THREAD_ID,
                     IARG_ADDRINT, sm->addr32, IARG_END);

      // [FIX] Insert Missing CapIf
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapIf, IARG_THREAD_ID,
                     IARG_PTR, sm, IARG_END);

      // 3) Stop on RET (Anti-Pollution) [NEW]
      if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRet, IARG_THREAD_ID,
                       IARG_END);
      }

      // ... Memory Instrumentation ...
      if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemW,
                       IARG_THREAD_ID, IARG_PTR, sm, IARG_MEMORYWRITE_EA,
                       IARG_CONTEXT, IARG_END);
      } else if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemR,
                       IARG_THREAD_ID, IARG_PTR, sm, IARG_MEMORYREAD_EA,
                       IARG_CONTEXT, IARG_END);
      } else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordNoMem,
                       IARG_THREAD_ID, IARG_PTR, sm, IARG_CONTEXT, IARG_END);
      }
    }
  }
}

// Bypass Original Loop
// static void OnTrace_Original(TRACE trace, VOID*) ...

// -------------------- IMG load callback (로그만) --------------------
static VOID OnImgLoad(IMG img, VOID *) {
  if (!IMG_Valid(img))
    return;

  if (!IMG_Valid(img))
    return;

  const string full = IMG_Name(img);
  LogDebug("[DEBUG] OnImgLoad: " + full);
  const string baseLower = BaseNameLower(full);

  std::ostringstream oss;
  oss << "LOAD " << full.c_str() << " [0x" << std::hex
      << (ADDRINT)IMG_LowAddress(img) << "-0x" << std::hex
      << (ADDRINT)IMG_HighAddress(img) << "]";

  if (IsCryptoBaseLower(baseLower)) {
    oss << "  CRYPTO_LOAD";
    if (KnobVerbose.Value()) {
      // cerr << "[pin-loop] CRYPTO_LOAD: " << full.c_str() << endl;
    }
  }

  // Log to Unified Trace (EXT_IMG)
  if (KnobLogImages.Value()) {
    std::ostringstream imgOss;
    imgOss << "EXT_IMG:" << full.c_str() << "," << std::hex
           << (ADDRINT)IMG_LowAddress(img) << ","
           << (ADDRINT)IMG_HighAddress(img);
    if (IsCryptoBaseLower(baseLower)) {
      imgOss << ",CRYPTO";
    }
    imgOss << "\n";
    WriteGlobalTrace(imgOss.str());
  }

  if (IsCryptoBaseLower(baseLower)) {
    if (KnobVerbose.Value()) {
      // cerr << "[pin-loop] CRYPTO_LOAD: " << full.c_str() << endl;
    }
  }

  // Ntdll Hooks (Lower level)
  if (baseLower.find("ntdll") != string::npos) {
    RTN ntWrite = RTN_FindByName(img, "NtWriteFile");
    if (RTN_Valid(ntWrite)) {
      RTN_Open(ntWrite);
      RTN_InsertCall(
          ntWrite, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID, IARG_PTR,
          "NtWriteFile", IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
          IARG_FUNCARG_ENTRYPOINT_VALUE,
          6, // Length (check prototype: 6th arg?)
          // NtWriteFile(Handle, Event, ApcRoutine, ApcContext, IoStatusBlock,
          // Buffer, Length, ByteOffset, Key) 0: Handle, 1: Event, 2: Apc, 3:
          // Context, 4: IoStatus, 5: Buffer, 6: Length
          IARG_END);
      RTN_Close(ntWrite);
    }

    RTN ntRead = RTN_FindByName(img, "NtReadFile");
    if (RTN_Valid(ntRead)) {
      RTN_Open(ntRead);
      RTN_InsertCall(ntRead, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID,
                     IARG_PTR, "NtReadFile", IARG_FUNCARG_ENTRYPOINT_VALUE,
                     0,                                // Handle
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // Length
                     IARG_END);
      RTN_Close(ntRead);
    }
  }

  // I/O Hooks: Kernel32/KernelBase
  if (baseLower.find("kernel32") != string::npos ||
      baseLower.find("kernelbase") != string::npos) {
    RTN wfile = RTN_FindByName(img, "WriteFile");
    if (RTN_Valid(wfile)) {
      RTN_Open(wfile);
      RTN_InsertCall(wfile, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID,
                     IARG_PTR, "WriteFile", IARG_FUNCARG_ENTRYPOINT_VALUE,
                     0,                                // Handle
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nBytes
                     IARG_END);
      RTN_Close(wfile);
    }

    RTN rfile = RTN_FindByName(img, "ReadFile");
    if (RTN_Valid(rfile)) {
      RTN_Open(rfile);
      RTN_InsertCall(rfile, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID,
                     IARG_PTR, "ReadFile", IARG_FUNCARG_ENTRYPOINT_VALUE,
                     0,                                // Handle
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nBytes
                     IARG_END);
      RTN_Close(rfile);
    }

    RTN cfileA = RTN_FindByName(img, "CreateFileA");
    if (RTN_Valid(cfileA)) {
      RTN_Open(cfileA);
      RTN_InsertCall(cfileA, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID,
                     IARG_PTR, "CreateFileA", IARG_FUNCARG_ENTRYPOINT_VALUE,
                     0,                                // PathPtr
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Access
                     IARG_END);
      RTN_Close(cfileA);
    }

    RTN cfileW = RTN_FindByName(img, "CreateFileW");
    if (RTN_Valid(cfileW)) {
      RTN_Open(cfileW);
      RTN_InsertCall(cfileW, IPOINT_BEFORE, (AFUNPTR)OnIoCall, IARG_THREAD_ID,
                     IARG_PTR, "CreateFileW", IARG_FUNCARG_ENTRYPOINT_VALUE,
                     0,                                // PathPtr
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Access
                     IARG_END);
      RTN_Close(cfileW);
    }
  }
}

// -------------------- Thread callbacks --------------------
static VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
  LogDebug("[DEBUG] OnThreadStart");

  TData *td = new TData();
  td->tid = tid;
  td->os_tid = PIN_GetTid();
  td->capturedCount = 0;
  td->cap = CaptureState();
  PIN_SetThreadData(gTlsKey, td, tid);

  if (KnobVerbose.Value()) {
    // cerr << "[pin-loop] thread start OS_TID=" << td->os_tid << endl;
  }

  /*
  // Open Thread-Specific Trace File: prefix + "_T<tid>.wct"
  {
      std::ostringstream oss;
      oss << gRunPrefix << "_T" << std::dec << td->os_tid << ".wct";
      string path = oss.str();

      td->hTraceFile = MyWin::CreateFileA(path.c_str(),
          MyWin::GENERIC_WRITE,
          MyWin::FILE_SHARE_READ,
          NULL,
          MyWin::CREATE_ALWAYS,
          MyWin::FILE_ATTRIBUTE_NORMAL,
          NULL);

      if (td->hTraceFile == MyWin::INVALID_HANDLE_VALUE) {
           // cerr << "[pin-loop] Failed to create thread trace: " << path
  << endl;
      }
  }
  */
}

static VOID OnThreadFini(THREADID tid, const CONTEXT *, INT32, VOID *) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td)
    return;

  if (td->cap.recording) {
    StopAndCommitCapture(td, "thread_fini");
  }

  FlushBuffer(td);

  // DUMP ALL DETECTED LOOPS TO CSV (For Coverage Check)
  // Iterate all loops in detector map
  for (map<LoopKey, LoopAgg>::iterator it = td->loops.begin();
       it != td->loops.end(); ++it) {
    LoopKey k = it->first;
    LoopAgg &agg = it->second;

    // Hot loop trigger?
    if (agg.iters >= KnobHotIters.Value()) {
      if (!agg.captured) {

        // Assign Global Sequence (Atomic)
        PIN_GetLock(&gGlobalSeqLock, 1);
        gGlobalLoopSeq++;
        agg.globalSeq = (UINT32)gGlobalLoopSeq;
        PIN_ReleaseLock(&gGlobalSeqLock);

        agg.captured = true; // Mark as capturing
        td->cap.recording = true;
        td->cap.armed = true;
        td->cap.key = k; // Set active capture key
        td->cap.capIns = 0;
        td->cap.stackR = 0;
        td->cap.memR = 0;
        td->cap.memW = 0;
        td->cap.reg_accum = 0;
        td->cap.body_len = 0;

        // Log if verbose
        if (KnobVerbose.Value()) {
          PIN_GetLock(&gMetaLock, 1);
          map<ADDRINT, StaticMeta *>::iterator it = gMeta->find(k.header);
          StaticMeta *sm = (it != gMeta->end()) ? it->second : NULL;
          PIN_ReleaseLock(&gMetaLock);

          string func = sm ? sm->funcName : "?";
          // cerr << "[pin-loop] Hot Loop Detected! T=" << td->os_tid
          //      << " H=" << std::hex << k.header << std::dec
          //      << " GSeq=" << agg.globalSeq << " in " << func.c_str()
          //      << endl;
        }
      }
    }
    // If already captured, it's already in CSV via StopAndCommitCapture.
    // But user wants "Detection Coverage Proof".
    // We can append uncaptured loops with body_len=0.
    // Always report final iteration count to CSV
    // This ensures simple loops (short body) or long-running loops are
    // accounted for.
    if (agg.iters > 0) {
      string funcName = agg.func;
      string imgName = agg.img;
      UINT64 bodyLen = agg.body_len; // 0 if not captured

      if (funcName.empty()) {
        PIN_GetLock(&gMetaLock, 1);
        map<ADDRINT, StaticMeta *>::iterator mit =
            gMeta->find((ADDRINT)k.header);
        StaticMeta *smHead = (mit != gMeta->end()) ? mit->second : NULL;
        PIN_ReleaseLock(&gMetaLock);

        funcName = smHead ? smHead->funcName : "?";
        imgName = smHead ? smHead->imgName : "?";
      }

      AppendLoopRowToCsv(
          td->os_tid, agg.globalSeq, k.header, k.backedge, bodyLen, agg.iters,
          (double)bodyLen * agg.iters, // score
          funcName, imgName, agg.memR, agg.memW, agg.stackR, agg.stackW,
          agg.xorCnt, agg.addsubCnt, agg.shlshrCnt, agg.mulCnt);
    }
    // [Duplicate Code Removed]

    // [NEW] LoopFinish: Embed iteration count in Text Trace
    // Format: LOOP_FINISH,header,backedge,iters
    {
      std::ostringstream oss;
      oss << "LOOP_FINISH," << std::hex << k.header << "," << k.backedge << ","
          << std::dec << agg.iters << "\n";
      BufferedWriteText(td, oss.str());
    }
  }

  if (KnobVerbose.Value()) {
    // cerr << "[pin-loop] thread fini  OS_TID=" << td->os_tid
    //      << " loops=" << td->loops.size() << " captured=" <<
    //      td->capturedCount
    //      << endl;
  }

  delete td;
  PIN_SetThreadData(gTlsKey, 0, tid);
}

// -------------------- Follow child --------------------
static BOOL FollowChild(CHILD_PROCESS cProcess, VOID *) {
  if (!KnobFollowChild.Value())
    return FALSE;

  // Log child process creation to debug_log.txt
  {
    const CHAR *const *argv;
    INT argc;
    CHILD_PROCESS_GetCommandLine(cProcess, &argc, &argv);

    std::ostringstream oss;
    oss << "[DEBUG] FollowChild: PID=" << CHILD_PROCESS_GetId(cProcess)
        << " Command: ";
    for (int i = 0; i < argc; i++) {
      oss << argv[i] << " ";
    }
    LogDebug(oss.str());
  }

  // [FIX] Do NOT manually set Pin command line.
  // Using the root pin.exe launcher (as in run_vm_final.bat) handles
  // mixed-mode (32->64) correctly and automatically.
  // Manual override breaks architecture-switching children.

  return TRUE;
}

// -------------------- Fini --------------------
// -------------------- Fini --------------------
static void DumpStaticMeta() {
  // Legacy: No-op because we dump incrementally now.
  // Keeping function structure to minimize code churn.
}

static VOID OnFini(INT32, VOID *) {
  LogDebug("[DEBUG] OnFini step 1: entry");

  LogDebug("[DEBUG] OnFini step 2: FlushGlobalBuffer");
  FlushGlobalBuffer();

  LogDebug("[DEBUG] OnFini step 3: CloseHandle");
  if (gTraceHandle != MyWin::INVALID_HANDLE_VALUE) {
    MyWin::CloseHandle(gTraceHandle);
    gTraceHandle = MyWin::INVALID_HANDLE_VALUE;
  }

  // [SAFETY] Removed explicit gMeta/Loop memory cleanup (delete) during exit.
  // Manual pointer deletion in Pin's final exit phase can trigger crashes due
  // to indeterminate destruction order of runtime components. The OS will
  // reclaim all process memory upon termination.

  LogDebug("[DEBUG] OnFini step 4: complete");
}

// -------------------- Usage --------------------
static INT32 Usage() {
  LogDebug("[DEBUG] Usage: Invalid arguments or PIN_Init failed.");
  return -1;
}

// -------------------- main --------------------
// -------------------- main --------------------
// -------------------- main --------------------
// -------------------- main --------------------
// -------------------- main --------------------
// -------------------- main --------------------
// Helper for safe debug logging (MOVED TO GLOBAL)

int main(int argc, char *argv[]) {
  // [NEW] Use Windows API for safe logging
  LogDebug("==========================================");
  LogDebug("[DEBUG] Starting Pintool Main...");

  // [DIAG] Log all arguments received from Pin
  {
    std::ostringstream oss;
    oss << "[DEBUG] argc=" << argc << " args:";
    for (int i = 0; i < argc; i++) {
      oss << " [" << (argv[i] ? argv[i] : "NULL") << "]";
    }
    LogDebug(oss.str());
  }

  PIN_InitSymbols();
  LogDebug("[DEBUG] Symbols Init Done.");

  if (PIN_Init(argc, argv)) {
    return Usage();
  }
  LogDebug("[DEBUG] PIN_Init Done.");

  // FORCE INIT GLOBALS (MANDATORY FOR PIN STATIC LINKING ISSUES)
  // Pin CRT initialization can be tricky with static globals.
  // We manually allocate them on heap to ensure they exist.
  gGlobalBuf = new string();
  gGlobalBuf->reserve(GLOBAL_BUF_SIZE);

  gCsvPath = new string();               // Empty by default
  gMetaPath = new string();              // Empty by default
  gCryptoExecLogged = new set<string>(); // Empty by default
  gMeta = new map<ADDRINT,
                  StaticMeta *>(); // heap alloc: avoids static destructor crash
  gLoopFirstSeen = new map<pair<ADDRINT, ADDRINT>, UINT32>();
  LogDebug("[DEBUG] Globals Init Done.");

  // save argv for child
  gSavedArgc = argc;
  gSavedArgv = (const CHAR **)malloc(sizeof(CHAR *) * argc);
  for (int i = 0; i < argc; ++i) {
    gSavedArgv[i] = _strdup(argv[i]);
  }

  gTlsKey = PIN_CreateThreadDataKey(0);
  PIN_InitLock(&gMetaLock);
  PIN_InitLock(&gCsvLock);
  PIN_InitLock(&gTraceLock);
  PIN_InitLock(&gGlobalSeqLock);
  PIN_InitLock(&gFirstSeenLock);

  InitCryptoDllList();

  // run prefix: prefix + _P<pid>_x86
  UINT32 pid = (UINT32)PIN_GetPid();
  {
    std::ostringstream oss;
    oss << KnobPrefix.Value().c_str() << "_P" << std::dec << pid << "_x86";
    gRunPrefix = new string(oss.str());
  }

  // gCsvPath = gRunPrefix + "_loops.csv"; // REMOVED

  // Generic naming for Ransomware Analysis
  {
    string path = gRunPrefix->c_str();
    path += "_trace.txt";
    gTracePath = new string(path);
  }
  // gMetaPath = gRunPrefix + "_meta.txt"; // REMOVED

  // Open Meta File (REMOVED: Unified Trace)
  // Open I/O Log (REMOVED: Unified Trace)

  // Open Global Trace File with Protection (Restored)
  {
    string msg = "[DEBUG] Opening Trace File: " + *gTracePath;
    LogDebug(msg);

    gTraceHandle = MyWin::CreateFileA(
        gTracePath->c_str(), MyWin::GENERIC_WRITE,
        MyWin::FILE_SHARE_READ | MyWin::FILE_SHARE_WRITE, NULL,
        MyWin::CREATE_ALWAYS, MyWin::FILE_ATTRIBUTE_NORMAL, NULL);

    if (gTraceHandle ==
        MyWin::INVALID_HANDLE_VALUE) // Simple error logging ignoring code to
                                     // avoid C2264
    {
      LogDebug("[DEBUG] [ERROR] Failed to create trace file.");
    } else {
      LogDebug("[DEBUG] [SUCCESS] Trace file created.");
    }
  }

  // cerr << "[pin-loop] run_prefix: " << gRunPrefix->c_str() << endl;
  // cerr << "[pin-loop] csv_path  : "
  //      << (gCsvPath->empty() ? "(none)" : gCsvPath->c_str()) << endl;
  // cerr << "[pin-loop] trace_path: " << gTracePath->c_str() << "
  // (VISIBLE)"
  //      << endl;

  // Marker (Unified Trace)
  {
    std::ostringstream oss;
    oss << "EXT_MARKER:Pin tool running for PID " << pid << "\n";
    WriteGlobalTrace(oss.str());
    // cerr << "[pin-loop] Marker log written to trace." << endl;
  }

  // cerr << "[pin-loop] only_main=" << (KnobOnlyMain.Value() ? "1" : "0")
  //      << " follow_child=" << (KnobFollowChild.Value() ? "1" : "0")
  //      << " hot_iters=" << KnobHotIters.Value()
  //      << " cap_max_ins=" << KnobCapMaxIns.Value() << " top=" <<
  //      KnobTop.Value()
  //      << " log_images=" << (KnobLogImages.Value() ? "1" : "0")
  //      << " crypto_only=" << (KnobCryptoOnly.Value() ? "1" : "0") <<
  //      endl;

  // Child Process
  if (KnobFollowChild.Value()) {
    PIN_AddFollowChildProcessFunction(FollowChild, 0);
  }
  IMG_AddInstrumentFunction(OnImgLoad, 0);

  // 핵심: TRACE 단위 계측
  TRACE_AddInstrumentFunction(OnTrace, 0);

  PIN_AddThreadStartFunction(OnThreadStart, 0);
  PIN_AddThreadFiniFunction(OnThreadFini, 0);
  PIN_AddFiniFunction(OnFini, 0);

  LogDebug("[DEBUG] Callbacks Registered. Starting Program...");

  PIN_StartProgram();
  return 0;
}

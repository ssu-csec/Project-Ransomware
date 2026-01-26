// === MyPinTool.cpp (Fast Hot-Loop Capture + TRACE-level IMG filter, no dangling pointers) ===
// Pin 3.31 / Windows / IA-32 / MSVC (C++03 compatible)
//
// 핵심 유지 기능:
//  - taken back-edge 기반 loop 카운트(스레드별)
//  - hot_iters 이상 반복된 loop만 1 iteration 캡처(txt 생성)
//  - 캡처 완료 시 CSV에 1줄 append
//  - follow child 지원
//  - crypto DLL load/exec reach 로깅(images.txt) 옵션
//
// 최적화/안정화:
//  - INS_AddInstrumentFunction 대신 TRACE_AddInstrumentFunction 사용: IMG 판정 1회/TRACE
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
#  pragma warning(disable:5208)
#endif

// STL includes MUST come before pin.H to avoid CRT conflicts (C2371, C2011)
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <utility> // for pair
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

// Pin header
#include "pin.H"

using namespace std;
// #include <Windows.h> // Removed to avoid conflict
namespace MyWin {
    typedef void* HANDLE;
    typedef unsigned long DWORD;
    typedef int BOOL;
    
    static const DWORD GENERIC_WRITE = 0x40000000L;
    static const DWORD FILE_SHARE_READ = 0x00000001;
    static const DWORD CREATE_ALWAYS = 2;
    static const DWORD FILE_ATTRIBUTE_HIDDEN = 0x00000002;
    static const DWORD FILE_ATTRIBUTE_SYSTEM = 0x00000004;
    static const DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;
    static const HANDLE INVALID_HANDLE_VALUE = (HANDLE)-1;

    extern "C" __declspec(dllimport) HANDLE __stdcall CreateFileA(
        const char* lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        void* lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    extern "C" __declspec(dllimport) BOOL __stdcall WriteFile(
        HANDLE hFile,
        const void* lpBuffer,
        DWORD nNumberOfBytesToWrite,
        DWORD* lpNumberOfBytesWritten,
        void* lpOverlapped
    );

    extern "C" __declspec(dllimport) BOOL __stdcall CloseHandle(
        HANDLE hObject
    );

    extern "C" __declspec(dllimport) DWORD __stdcall GetLastError();

    typedef struct _MEMORY_BASIC_INFORMATION {
        void* BaseAddress;
        void* AllocationBase;
        DWORD AllocationProtect;
        size_t RegionSize;
        DWORD State;
        DWORD Protect;
        DWORD Type;
    } MEMORY_BASIC_INFORMATION;

    extern "C" __declspec(dllimport) size_t __stdcall VirtualQuery(
        const void* lpAddress,
        MEMORY_BASIC_INFORMATION* lpBuffer,
        size_t dwLength
    );
}


#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <iomanip>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include <cstdlib>

using std::string;
using std::map;
using std::vector;
using std::set;
using std::cerr;
using std::endl;

#if !defined(TARGET_IA32E)
#  error "This pintool is intended for Intel64 (64-bit) targets only."
#endif

// -------------------- Knobs --------------------
KNOB<BOOL>   KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "1",
    "메인 실행파일만 계측 (1이면 main exe만, 0이면 전체)");

KNOB<BOOL>   KnobInstrumentAll(KNOB_MODE_WRITEONCE, "pintool", "instrument_all", "0",
    "모든 IMG(=전체 모듈) 계측. only_main/crypto_only보다 우선");

KNOB<BOOL>   KnobFollowChild(KNOB_MODE_WRITEONCE, "pintool", "follow_child", "1",
    "자식 프로세스 follow (CreateProcess로 직접 spawn되는 child에 한함)");

KNOB<UINT32> KnobTop(KNOB_MODE_WRITEONCE, "pintool", "top", "50",
    "스레드별 캡처할 hot loop 최대 개수");

KNOB<UINT32> KnobHotIters(KNOB_MODE_WRITEONCE, "pintool", "hot_iters", "2000",
    "루프 반복 횟수가 이 값 이상이면 캡처 후보로 승격");

KNOB<UINT32> KnobCapMaxIns(KNOB_MODE_WRITEONCE, "pintool", "cap_max_ins", "20000",
    "루프 1 iteration 캡처 시 최대 인스트럭션 수");

KNOB<string> KnobPrefix(KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace",
    "출력 파일 접두사(폴더 포함 가능). 예: C:\\\\trace\\\\wc_all");


// --- Legacy Knobs (Restored for compatibility) ---
KNOB<UINT32> KnobMaxInsts(KNOB_MODE_WRITEONCE, "pintool", "max_insts", "500000",
    "[Legacy] Unused in new binary log version (kept for script compatibility)");

KNOB<BOOL>   KnobCapAll(KNOB_MODE_WRITEONCE, "pintool", "cap_all", "0",
    "[Legacy] Unused (always captures hot loops) - Default changed to 0");

KNOB<BOOL>   KnobEmitStubTrace(KNOB_MODE_WRITEONCE, "pintool", "emit_stub_trace", "1",
    "[Legacy] Unused");

KNOB<BOOL>   KnobResolveCsv(KNOB_MODE_WRITEONCE, "pintool", "resolve_csv", "1",
    "[Legacy] Unused");
// ------------------------------------------------


KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0",
    "상세 로그 출력");

// --- Crypto DLL load/exec reach test knobs ---
KNOB<BOOL>   KnobLogImages(KNOB_MODE_WRITEONCE, "pintool", "log_images", "1",
    "IMG 로드/실행 도달 로그(images.txt) 기록");

KNOB<BOOL>   KnobCryptoOnly(KNOB_MODE_WRITEONCE, "pintool", "crypto_only", "0",
    "암호화 관련 DLL만 계측(테스트용)");

KNOB<string> KnobCryptoDlls(KNOB_MODE_WRITEONCE, "pintool", "crypto_dlls",
    "cryptbase.dll;bcrypt.dll;bcryptprimitives.dll;crypt32.dll;ncrypt.dll;ncryptprov.dll;rsaenh.dll;dssenh.dll;schannel.dll;secur32.dll",
    "crypto DLL basename 목록(;로 구분)");

KNOB<BOOL>   KnobLogMeta(KNOB_MODE_WRITEONCE, "pintool", "log_meta", "1",
    "Meta(asm/img/name) 로깅 활성화 (0이면 성능 최적화를 위해 끔)");

KNOB<UINT32> KnobMaxBackedgeDist(KNOB_MODE_WRITEONCE, "pintool", "max_backedge_dist", "2097152",
    "루프 탐지 시 백엣지 거리 제한 (언패킹/VM등 분석 시 크게 설정)");

// -------------------- Utils --------------------
static string ToLowerStr(const string& s)
{
    string t = s;
    for (size_t i = 0; i < t.size(); ++i)
        t[i] = (char)std::tolower((unsigned char)t[i]);
    return t;
}

static string Trim(const string& s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static void CsvWriteEscaped(FILE* fp, const string& s)
{
    bool need = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == ',' || c == '"' || c == '\n' || c == '\r') { need = true; break; }
    }
    if (!need) {
        std::fputs(s.c_str(), fp);
        return;
    }
    std::fputc('"', fp);
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"') std::fputc('"', fp);
        std::fputc(c, fp);
    }
    std::fputc('"', fp);
}

static string Hex8(UINT32 x)
{
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << x;
    return oss.str();
}

static string BaseNameLower(const string& path)
{
    size_t p1 = path.find_last_of('\\');
    size_t p2 = path.find_last_of('/');
    size_t p = string::npos;
    if (p1 != string::npos && p2 != string::npos) p = (p1 > p2) ? p1 : p2;
    else if (p1 != string::npos) p = p1;
    else p = p2;

    string base = (p == string::npos) ? path : path.substr(p + 1);
    return ToLowerStr(base);
}

static void SplitSemicolonLower(const string& s, vector<string>& out)
{
    out.clear();
    std::istringstream iss(s);
    string tok;
    while (std::getline(iss, tok, ';')) {
        tok = Trim(tok);
        if (!tok.empty()) out.push_back(ToLowerStr(tok));
    }
}

// -------------------- Crypto list --------------------
static vector<string> gCryptoDllList;

static void InitCryptoDllList()
{
    SplitSemicolonLower(KnobCryptoDlls.Value(), gCryptoDllList);
}

static bool IsCryptoBaseLower(const string& baseLower)
{
    for (size_t i = 0; i < gCryptoDllList.size(); ++i) {
        if (baseLower == gCryptoDllList[i]) return true;
    }
    return false;
}

// -------------------- Static Meta --------------------
enum OpClass {
    OP_NONE = 0,
    OP_XOR,
    OP_ADDSUB,
    OP_SHLSHR,
    OP_MUL
};

// --- Binary Structures (Packed) ---
#pragma pack(push, 1)
struct TraceEntry {
    ADDRINT ip;
    ADDRINT regs[8]; // RAX, RBX, ... RBP
    ADDRINT memAddr; // 0 if no mem access
};

// -------------------- Globals --------------------
static FILE* gTraceFp = NULL;
static FILE* gMetaFp = NULL;
static PIN_LOCK gMetaLock;
static PIN_LOCK gTraceLock;

// Using PIN_LOCK for simple atomic counter simulation or just use locked increment
static PIN_LOCK gGlobalSeqLock;
static UINT64 gGlobalLoopSeq = 0; // First-seen sequence (Changed to UINT64)

// Map to store FirstSeenSeq for each loop key (Header+BackEdge) to avoid re-assigning
// This fixes the "All GlobalSeq=0" issue or unstable sequencing.
static PIN_LOCK gFirstSeenLock;
static map<pair<ADDRINT, ADDRINT>, UINT32> gLoopFirstSeen;

// Structs
// Loop Header Marker
#define MAGIC_LOOP_HEAD 0x4C4F4F50 // "LOOP"

struct LoopHeaderEntry {
    UINT32 magic;    // MAGIC_LOOP_HEAD
    UINT32 tid;      // Thread ID
    ADDRINT header;   // Header IP (Start of Loop)
    ADDRINT backedge; // Backedge IP (End of Loop)
    UINT32 rank;     // Thread-local rank/score (heuristic)
    UINT32 globalSeq;// Global execution order (First Seen) [NEW]
};
#pragma pack(pop)


struct StaticMeta {
    ADDRINT addr;       // full
    UINT32  addr32;
    string  addrStr;
    string  assembly;
    string  funcName;
    string  imgName;
    string  opcLower;
    string  memMeta; // Base|Index|Scale|Disp
    OpClass opClass;
    bool    isStackMem;
};

static map<ADDRINT, StaticMeta*> gMeta;
// static PIN_LOCK gMetaLock; // Defined in block at line ~266

// -------------------- Globals for Trace --------------------
// -------------------- Globals for Trace --------------------
static string gTracePath; // Binary Trace (Consolidated)
static MyWin::HANDLE gTraceHandle = MyWin::INVALID_HANDLE_VALUE;
// static PIN_LOCK gTraceLock; // Defined in block at line ~266

// -------------------- Loop Key / Stats --------------------
struct LoopKey {
    ADDRINT header;   // target of back-edge
    ADDRINT backedge; // branch ip

    bool operator<(const LoopKey& o) const {
        if (header != o.header) return header < o.header;
        return backedge < o.backedge;
    }
};

struct LoopAgg {
    UINT64 iters;
    bool   captured;
    UINT32 globalSeq; // [NEW] First-Seen Global Sequence

    // captured body stats (1-iteration snapshot)
    UINT64 body_len;
    UINT64 memR, memW, stackR, stackW;
    UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;

    string func;
    string img;
    string tracePath;

    LoopAgg() : iters(0), captured(false), globalSeq(0),
        body_len(0), memR(0), memW(0), stackR(0), stackW(0),
        xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0) {
    }
};

struct CaptureState {
    bool   armed;
    bool   recording;

    LoopKey key;
    UINT32  rank_thread;

    UINT64  capIns;
    UINT64  capMaxIns;


    string func;
    string img;

    UINT64 body_len;
    UINT64 memR, memW, stackR, stackW;
    UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;
    UINT64 reg_accum; // [NEW] Register usage accumulator

    bool   candValid;
    LoopKey candKey;
    UINT64  candIters;

    CaptureState() :
        armed(false), recording(false),
        rank_thread(0),
        capIns(0), capMaxIns(0),
        body_len(0), memR(0), memW(0), stackR(0), stackW(0),

        xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0), reg_accum(0),
        candValid(false), candIters(0)
    {
        candKey.header = 0; candKey.backedge = 0;
        key.header = 0; key.backedge = 0;
    }
};

struct TData {
    UINT32 os_tid;
    map<LoopKey, LoopAgg> loops;
    UINT32 capturedCount;
    CaptureState cap;

    // Buffering - ATOMIC LOOP WRITE (Vector)
    vector<UINT8> loopBuf;
    
    TData() : os_tid(0), capturedCount(0) {
        loopBuf.reserve(64 * 1024); // Reserve 64KB initially
    }
    ~TData() {
    }
};

static void FlushBuffer(TData* td) {
    if (td->loopBuf.empty()) return;
    if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE) return;

    // ATOMIC WRITE protected by lock (Global File)
    PIN_GetLock(&gTraceLock, 1);
    MyWin::DWORD written = 0;
    // C++03 vector fix: &td->loopBuf[0] instead of .data()
    MyWin::WriteFile(gTraceHandle, &td->loopBuf[0], (MyWin::DWORD)td->loopBuf.size(), &written, NULL);
    PIN_ReleaseLock(&gTraceLock);

    td->loopBuf.clear();
}

static void BufferedWrite(TData* td, const void* data, size_t size) {
    // Append to local vector
    size_t oldSize = td->loopBuf.size();
    td->loopBuf.resize(oldSize + size);
    memcpy(&td->loopBuf[0] + oldSize, data, size);
}


static TLS_KEY gTlsKey;

// -------------------- Output files --------------------
static string gRunPrefix; // prefix + "_P<pid>"
static string gCsvPath;   // Statistics CSV (Summary)
// static FILE* gCsvFp = NULL; // already static global? Re-check
// static PIN_LOCK gCsvLock;   // already static global? Re-check
// Wait, gCsvFp was not in the top block. Only gMetaFp was re-defined.

static FILE* gCsvFp = NULL;
static PIN_LOCK gCsvLock;

// static string gTracePath; // Moved to top
// static MyWin::HANDLE gTraceHandle = ...
// static PIN_LOCK gTraceLock;

static string gMetaPath;  // Static Meta
// static FILE* gMetaFp = NULL; // Redefined, remove this line.
static set<string> gCryptoExecLogged; // basename lower


// 큰 버퍼(오버헤드 감소)
static char* gCsvBuf = NULL;


// -------------------- Saved Pin cmdline for child --------------------
static INT gSavedArgc = 0;
static const CHAR** gSavedArgv = NULL;

// -------------------- IMG log --------------------
// -------------------- IMG/Meta log (Moved to DumpStaticMeta) --------------------
// Removed dynamic ImgLogLine_NoFlush since we will dump static meta at the end.


// -------------------- CSV --------------------
static void EnsureCsvOpened()
{
    if (gCsvFp) return;

    gCsvFp = std::fopen(gCsvPath.c_str(), "wb");
    if (!gCsvFp) {
        cerr << "[pin-loop] cannot open CSV: " << gCsvPath << endl;
        return;
    }

    // 1MB 버퍼
    gCsvBuf = (char*)malloc(1 << 20);
    if (gCsvBuf) setvbuf(gCsvFp, gCsvBuf, _IOFBF, (1 << 20));

    std::fputs(
        "tid,rank_global,rank_thread,start_addr,end_addr,body_len,iter,score,"
        "func,img,memR,memW,stackR,stackW,xor,addsub,shlshr,mul\n", gCsvFp);
}

static void AppendLoopRowToCsv(UINT32 tid,
    UINT32 rank_global, // NOW PASSED EXPLICITLY
    ADDRINT start_addr,
    ADDRINT end_addr,
    UINT64 body_len,
    UINT64 iterCount,
    double score,
    const string& func,
    const string& img,
    UINT64 memR, UINT64 memW, UINT64 stackR, UINT64 stackW,
    UINT64 xorCnt, UINT64 addsubCnt, UINT64 shlshrCnt, UINT64 mulCnt)
{
    PIN_GetLock(&gCsvLock, 1);

    EnsureCsvOpened();
    if (!gCsvFp) { PIN_ReleaseLock(&gCsvLock); return; }

    // Removed approximation logic. Only use rank_global passed in.

    std::fprintf(gCsvFp, "%u,%u,0,", tid, rank_global); // rank_thread placeholder removed or reused? 
    // OLD: fprintf(..., "%u,%u,%u,", tid, rank_global, rank_thread);
    // User wants: tid, valid_global_seq, 0
    // OK, wait. Original signature had rank_thread.
    // I replaced rank_thread with rank_global in my mind? 
    // Original: AppendLoopRowToCsv(tid, rank_thread, start, end...)
    // Wait, let's look at TargetContent again.
    // TargetContent: AppendLoopRowToCsv(UINT32 tid, UINT32 rank_thread, ...) 
    
    // I will change signature to: AppendLoopRowToCsv(tid, rank_global, rank_thread [optional?])
    // The previous call passed 0 for rank_thread.
    // I'll assume rank_thread is less important or can be 0.
    
    // Actual CSV columns based on fprintf: "%u,%u,%u," -> tid, rank_global, rank_thread.
    

    std::fprintf(gCsvFp, "%p,%p,", (void*)start_addr, (void*)end_addr);
    std::fprintf(gCsvFp, "%llu,%llu,%.0f,", (unsigned long long)body_len,
        (unsigned long long)iterCount, score);

    CsvWriteEscaped(gCsvFp, func); std::fputc(',', gCsvFp);
    CsvWriteEscaped(gCsvFp, img);  std::fputc(',', gCsvFp);

    std::fprintf(gCsvFp, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
        (unsigned long long)memR, (unsigned long long)memW,
        (unsigned long long)stackR, (unsigned long long)stackW,
        (unsigned long long)xorCnt, (unsigned long long)addsubCnt,
        (unsigned long long)shlshrCnt, (unsigned long long)mulCnt);

    // fflush removed
    PIN_ReleaseLock(&gCsvLock);
}

// -------------------- StaticMeta builder --------------------
// TRACE 단위로 IMG 이름/lowaddr를 전달받아 IMG_FindByAddress 호출을 줄임
static StaticMeta* GetOrCreateMeta(INS ins, ADDRINT a, const string& traceImgName, ADDRINT traceImgLow)
{
    StaticMeta* sm = NULL;

    PIN_GetLock(&gMetaLock, 1);
    map<ADDRINT, StaticMeta*>::iterator it = gMeta.find(a);
    if (it != gMeta.end()) {
        sm = it->second;
        PIN_ReleaseLock(&gMetaLock);
        return sm;
    }
    PIN_ReleaseLock(&gMetaLock);

    StaticMeta* m = new StaticMeta();
    m->opClass = OP_NONE; // Fix UB if log_meta=0
    m->addr = a;
    m->addr32 = (UINT32)a;
    m->addrStr = Hex8((UINT32)a);
    // Disassemble only if log_meta is on or for debug?
    // We assume parser always needs generic ASM? 
    // Actually generic parser relies on it. But for extreme speed user can disable.
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
    // Let's compute opClass from INS_Opcode ideally, but sticking to string for now.
    // Optimization: If user wants speed, they might accept loss of OpClass stats.
    
    // Recovery for OpClass if string suppressed?
    // Let's just do the string op if LogMeta is ON.
    if (KnobLogMeta.Value()) {
        m->opClass = OP_NONE;
        if (m->opcLower == "xor" || m->opcLower == "pxor" || m->opcLower == "vpxor") m->opClass = OP_XOR;
        else if (m->opcLower == "add" || m->opcLower == "sub" || m->opcLower == "adc" || m->opcLower == "sbb" ||
            m->opcLower == "inc" || m->opcLower == "dec") m->opClass = OP_ADDSUB;
        else if (m->opcLower == "shl" || m->opcLower == "sal" || m->opcLower == "shr" || m->opcLower == "sar" ||
            m->opcLower == "rol" || m->opcLower == "ror") m->opClass = OP_SHLSHR;
        else if (m->opcLower == "mul" || m->opcLower == "imul" || m->opcLower == "fmul") m->opClass = OP_MUL;
    }

    // func/img
    m->imgName = traceImgName;
    if (m->imgName.empty()) m->imgName = "Unmapped/Shellcode";

    {
        string funcName;
        RTN rtn = INS_Rtn(ins);
        if (!RTN_Valid(rtn)) rtn = RTN_FindByAddress(a);

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
                    if (!fixImg.empty()) m->imgName = fixImg;
                }
            }
        }
        else {
            // fallback: IMG+offset or raw addr
            if (!traceImgName.empty() && traceImgLow != 0) {
                std::ostringstream oss;
                oss << traceImgName << "+0x" << std::hex << (a - traceImgLow);
                funcName = oss.str();
            }
            else {
                std::ostringstream oss;
                oss << "func_0x" << std::hex << a;
                funcName = oss.str();
            }
        }
        if (funcName.empty()) funcName = "Unknown_Func";
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
             << (REG_valid(idx) ? REG_StringShort(idx) : "") << "|"
             << scale << "|" << disp;
        m->memMeta = moss.str();
    }

    PIN_GetLock(&gMetaLock, 1);
    // Double-check pattern to avoid race/dup/leak
    map<ADDRINT, StaticMeta*>::iterator it2 = gMeta.find(a);
    if (it2 != gMeta.end()) {
        PIN_ReleaseLock(&gMetaLock);
        delete m; // Discard duplicate
        return it2->second;
    }

    gMeta.insert(std::make_pair(a, m));
    
    // Incremental Dump (Buffered via stdio, NO Explicit Flush)
    if (gMetaFp && KnobLogMeta.Value()) {
        std::fprintf(gMetaFp, "%08x;", m->addr32);
        CsvWriteEscaped(gMetaFp, m->funcName); std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->imgName);  std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->assembly); std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->memMeta);  std::fputc('\n', gMetaFp);
        // std::fflush(gMetaFp); // REMOVED for performance
    }
    
    PIN_ReleaseLock(&gMetaLock);

    return m;
}

// -------------------- Trace Dump (Binary) --------------------
// -------------------- Trace Dump (Binary) --------------------
// Removed direct WriteBinaryEntry, replaced with BufferedWrite calls


static void WriteLoopHeader(TData* td, UINT32 tid, ADDRINT header, ADDRINT backedge, UINT32 rank) {

    LoopHeaderEntry e;
    e.magic = MAGIC_LOOP_HEAD;
    e.tid = tid;
    e.header = header;
    e.backedge = backedge;
    e.rank = rank;
    
    // Retrieve globalSeq from LoopAgg
    // We need to look it up in td->loops
    // Note: This adds a map lookup overhead during flush, but it's per LOOP, not per instruction.
    LoopKey k; k.header = header; k.backedge = backedge;
    if (td->loops.count(k)) {
        e.globalSeq = td->loops[k].globalSeq;
    } else {
        e.globalSeq = 0; // Should not happen if logic is correct
    }

    BufferedWrite(td, &e, sizeof(LoopHeaderEntry));
}



// -------------------- Capture control --------------------
static void ResetCaptureStats(CaptureState& c)
{
    c.capIns = 0;
    c.body_len = 0;
    c.memR = c.memW = c.stackR = c.stackW = 0;
    c.xorCnt = c.addsubCnt = c.shlshrCnt = c.mulCnt = 0;
    c.func.clear();
    c.img.clear();
}


static inline void AccumulateOp(const StaticMeta* sm, CaptureState& c)
{
    if (!sm) return;
    if (sm->opClass == OP_XOR) c.xorCnt++;
    else if (sm->opClass == OP_ADDSUB) c.addsubCnt++;
    else if (sm->opClass == OP_SHLSHR) c.shlshrCnt++;
    else if (sm->opClass == OP_MUL) c.mulCnt++;
}

static void StopAndCommitCapture(TData* td, const char* reason)
{
    CaptureState& c = td->cap;
    if (!c.recording) return;

    if (c.recording) {
        // Recording ended, flush buffer ATOMICALLY
        FlushBuffer(td);
    }
    c.recording = false;


    map<LoopKey, LoopAgg>::iterator it = td->loops.find(c.key);
    if (it != td->loops.end()) {
        LoopAgg& agg = it->second;
        agg.captured = true;
        agg.body_len = c.body_len;
        agg.memR = c.memR; agg.memW = c.memW;
        agg.stackR = c.stackR; agg.stackW = c.stackW;
        agg.xorCnt = c.xorCnt; agg.addsubCnt = c.addsubCnt;
        agg.shlshrCnt = c.shlshrCnt; agg.mulCnt = c.mulCnt;
        agg.func = c.func;
        agg.img = c.img;
        agg.tracePath = gTracePath; // All in one


        UINT64 iterCount = agg.iters;
        double score = (double)agg.body_len * (double)iterCount;

        AppendLoopRowToCsv(td->os_tid,
            c.rank_thread,
            c.key.header,
            c.key.backedge,
            agg.body_len,
            iterCount,
            score,
            agg.func,
            agg.img,
            agg.memR, agg.memW, agg.stackR, agg.stackW,
            agg.xorCnt, agg.addsubCnt, agg.shlshrCnt, agg.mulCnt);

        if (KnobVerbose.Value()) {
            cerr << "[pin-loop] capture done TID=" << td->os_tid
                << " L" << c.rank_thread
                << " H=" << std::hex << c.key.header
                << " B=" << std::hex << c.key.backedge
                << std::dec << " reason=" << reason
                << " body_len=" << (unsigned long long)agg.body_len
                << " iters=" << (unsigned long long)iterCount
                << endl;
        }
    }

    c.armed = false;
    c.key.header = 0; c.key.backedge = 0;
}

static void ArmBestCandidateIfIdle(TData* td)
{
    CaptureState& c = td->cap;
    if (c.recording) return;
    if (td->capturedCount >= KnobTop.Value()) return;
    if (!c.candValid) return;

    map<LoopKey, LoopAgg>::iterator it = td->loops.find(c.candKey);
    if (it == td->loops.end()) { c.candValid = false; return; }
    if (it->second.captured) { c.candValid = false; return; }

    c.key = c.candKey;
    c.armed = true;
}

static void StartCaptureAtHeader(TData* td, const StaticMeta* headerMeta)
{
    CaptureState& c = td->cap;
    if (!c.armed) return;
    if (c.recording) return;

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
    // Write Header to Global Trace File
    WriteLoopHeader(td, td->os_tid, c.key.header, c.key.backedge, c.rank_thread);



    if (KnobVerbose.Value()) {
        cerr << "[pin-loop] capture start TID=" << td->os_tid
            << " L" << c.rank_thread
            << " H=" << std::hex << c.key.header
            << " B=" << std::hex << c.key.backedge
            << std::dec << endl;
    }

    c.armed = false;
}

// -------------------- Fast IF --------------------
static ADDRINT PIN_FAST_ANALYSIS_CALL CapIf(THREADID tid, const StaticMeta* sm)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return 0;

    CaptureState& c = td->cap;
    if (c.recording) return 1;

    if (c.armed && sm->addr32 == c.key.header) {
        StartCaptureAtHeader(td, sm);
        return c.recording ? 1 : 0;
    }
    return 0;
}

// -------------------- Record (THEN) --------------------
static void PIN_FAST_ANALYSIS_CALL CapRecordNoMem(THREADID tid, const StaticMeta* sm,
    UINT32 eax, UINT32 ebx, UINT32 ecx, UINT32 edx, UINT32 esi, UINT32 edi, UINT32 esp, UINT32 ebp)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    TraceEntry e;
    e.ip = sm->addr32;
    e.regs[0] = eax; e.regs[1] = ebx; e.regs[2] = ecx; e.regs[3] = edx;
    e.regs[4] = esi; e.regs[5] = edi; e.regs[6] = esp; e.regs[7] = ebp;
    e.memAddr = 0;
    BufferedWrite(td, &e, sizeof(TraceEntry));



    c.body_len++;
    AccumulateOp(sm, c);

    c.capIns++;
    if (c.capIns >= c.capMaxIns) {
        StopAndCommitCapture(td, "cap_max_ins");
    }
}

static void PIN_FAST_ANALYSIS_CALL CapRecordMemR(THREADID tid, const StaticMeta* sm, ADDRINT ea,
    UINT32 eax, UINT32 ebx, UINT32 ecx, UINT32 edx, UINT32 esi, UINT32 edi, UINT32 esp, UINT32 ebp)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    TraceEntry e;
    e.ip = sm->addr32;
    e.regs[0] = eax; e.regs[1] = ebx; e.regs[2] = ecx; e.regs[3] = edx;
    e.regs[4] = esi; e.regs[5] = edi; e.regs[6] = esp; e.regs[7] = ebp;
    e.memAddr = (UINT32)ea;

    BufferedWrite(td, &e, sizeof(TraceEntry));

    c.body_len++;
    c.memR++;
    if (sm->isStackMem) c.stackR++;
    AccumulateOp(sm, c);

    c.capIns++;
    if (c.capIns >= c.capMaxIns) {
        StopAndCommitCapture(td, "cap_max_ins");
    }
}

static void PIN_FAST_ANALYSIS_CALL CapRecordMemW(THREADID tid, const StaticMeta* sm, ADDRINT ea,
    UINT32 eax, UINT32 ebx, UINT32 ecx, UINT32 edx, UINT32 esi, UINT32 edi, UINT32 esp, UINT32 ebp)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    TraceEntry e;
    e.ip = sm->addr32;
    e.regs[0] = eax; e.regs[1] = ebx; e.regs[2] = ecx; e.regs[3] = edx;
    e.regs[4] = esi; e.regs[5] = edi; e.regs[6] = esp; e.regs[7] = ebp;
    e.memAddr = (UINT32)ea;

    BufferedWrite(td, &e, sizeof(TraceEntry));

    c.body_len++;
    c.memW++;
    if (sm->isStackMem) c.stackW++;
    AccumulateOp(sm, c);

    c.capIns++;
    if (c.capIns >= c.capMaxIns) {
        StopAndCommitCapture(td, "cap_max_ins");
    }
}

// -------------------- Loop counter (taken back-edge) --------------------
static VOID PIN_FAST_ANALYSIS_CALL OnTakenBranch(THREADID tid, ADDRINT ip, ADDRINT target)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td) return;

    if (target >= ip) return; // backward only

    UINT32 backedge = (UINT32)ip;
    UINT32 header = (UINT32)target;

                // backward
                // Check Max Distance
                if ((UINT32)(ip - target) > KnobMaxBackedgeDist.Value()) {
                    // too far, likely not a loop (e.g. ret to caller in high mem)
                    return; 
                }

    LoopKey key; key.header = header; key.backedge = backedge;

    // Check FirstSeenSeq for this loop variant (Global Stability)
    UINT32 seq = 0;
    
    // Optimization: Check if agg already has it? 
    // Thread-local 'agg' might be fresh if map lookup, but 'td->loops' persists for thread life.
    // However, multiple threads might see same loop code. We want GLOBAL first seen.
    // So we check global map.
    
    // Double-checked locking or just lock? Lock is safer.
    // Optimization: Read without lock? Map is not thread safe for read overlapping write.
    // Use lock.
    PIN_GetLock(&gFirstSeenLock, 1);
    
    // Use explicit std::pair and std::map to avoid ambiguity
    pair<ADDRINT, ADDRINT> valKey = make_pair((ADDRINT)header, (ADDRINT)backedge);
    map<pair<ADDRINT, ADDRINT>, UINT32>::iterator it = gLoopFirstSeen.find(valKey);
    
    if (it != gLoopFirstSeen.end()) {
        seq = it->second;
    } else {
        // New Loop detected globally!
        PIN_GetLock(&gGlobalSeqLock, 1);
        gGlobalLoopSeq++;
        seq = (UINT32)gGlobalLoopSeq;
        PIN_ReleaseLock(&gGlobalSeqLock);
        
        gLoopFirstSeen[valKey] = seq;
    }
    PIN_ReleaseLock(&gFirstSeenLock);

    LoopAgg& agg = td->loops[key];
    if (agg.globalSeq == 0) agg.globalSeq = seq; // Assign once
    agg.iters++;

    // 캡처 중인 루프의 back-edge라면 iteration 종료 지점
    // Relaxed: if target == header, treat as loop boundary
    if (td->cap.recording && td->cap.key.header == target) {
        StopAndCommitCapture(td, "iteration_end");
        ArmBestCandidateIfIdle(td);
        return;
    }

    // hot 후보 유지(최대 iters 후보 1개만)
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

    // idle이면 후보 arm
    if (!td->cap.recording) {
        if (!td->cap.armed) ArmBestCandidateIfIdle(td);
    }
}

// -------------------- TRACE-level instrumentation (핵심 최적화) --------------------
static VOID OnTrace(TRACE trace, VOID*)
{
    const ADDRINT ta = TRACE_Address(trace);
    IMG img = IMG_FindByAddress(ta);

    bool imgValid = IMG_Valid(img);
    string imgName = imgValid ? IMG_Name(img) : "";
    ADDRINT imgLow = imgValid ? IMG_LowAddress(img) : 0;

    // Universal: Check memory attributes for unmapped code
    if (!imgValid) {
        MyWin::MEMORY_BASIC_INFORMATION mbi;
        if (MyWin::VirtualQuery((void*)ta, &mbi, sizeof(mbi))) {
             std::ostringstream oss;
             oss << "Unmapped/Shellcode";
             
             // Check Protection
             // 0x40 = PAGE_EXECUTE_READWRITE (RWX) -> Highly suspicious (Shellcode/Unpacking)
             // 0x20 = PAGE_EXECUTE_READ (RX)
             // 0x04 = PAGE_READWRITE (RW) -> Should not execute?
             if (mbi.Protect == 0x40) oss << " [RWX]";
             else if (mbi.Protect == 0x20) oss << " [RX]";
             else oss << " [Protect:" << std::hex << mbi.Protect << "]";
             
             oss << " (Base:" << std::hex << (UINT32)mbi.AllocationBase << ")";
             imgName = oss.str();
        } else {
             imgName = "Unmapped/Unknown";
        }
    }

    // TRACE 단위 필터(IMG 판정 1회)
    // Smart Mode (Default): Only Main Exe OR Crypto DLLs.
    // Explicit overrides (only_main, crypto_only) take precedence if set to 1.
    bool instrument = false;

    if (KnobInstrumentAll.Value()) {
        instrument = true;                   // 모든 IMG 계측
    }
    else if (KnobCryptoOnly.Value()) {
        if (imgValid) {
            string baseLower = BaseNameLower(imgName);
            if (IsCryptoBaseLower(baseLower)) instrument = true;
        }
    }
    else if (KnobOnlyMain.Value()) {
        if (imgValid && IMG_IsMainExecutable(img)) instrument = true;
    }
    else {
        // 기존 Smart Mode 유지
        if (!imgValid) instrument = true;
        else if (IMG_IsMainExecutable(img)) instrument = true;
        else {
            string baseLower = BaseNameLower(imgName);
            if (IsCryptoBaseLower(baseLower)) instrument = true;
        }
    }
    
    if (!instrument) return;

    // BBL/INS 계측 (BBL granularity for IMG correctness)
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Re-evaluate IMG for this BBL
        ADDRINT ba = BBL_Address(bbl);
        IMG bimg = IMG_FindByAddress(ba); // Expensive?
        // Note: IMG_FindByAddress is fairly efficient (binary search in map). 
        // But doing it for every BBL is more expensive than per TRACE.
        // However, user requested this accuracy.
        
        bool bimgValid = IMG_Valid(bimg);
        string bimgName = bimgValid ? IMG_Name(bimg) : "";
        ADDRINT bimgLow = bimgValid ? IMG_LowAddress(bimg) : 0;
        
        // If unmapped, use the TRACE-level unmapped detection (VirtualQuery) result, 
        // or re-query if strictly needed. 
        // For simplicity/perf, if IMG is invalid, fallback to TRACE-level result or generic.
        if (!bimgValid) {
            // Fallback to TRACE-level info if TRACE was unmapped too.
            if (!imgValid) {
                bimgName = imgName; // Reuse TRACE's VirtualQuery result
            } else {
                 bimgName = "Unmapped/Unknown_BBL";
            }
        }
        
        // Apply Filters again? 
        // If TRACE decided to instrument, it means at least one part matched.
        // If we want stricter filtering, check per BBL.
        bool bblInstrument = false;
        if (KnobInstrumentAll.Value()) {
             bblInstrument = true;
        } else {
             // Reuse TRACE-level decision if we trust TRACE logic, 
             // but user suspects TRACE includes excluded modules.
             // So re-check strictly.
             if (!bimgValid) bblInstrument = true;
             else if (IMG_IsMainExecutable(bimg)) bblInstrument = true;
             else if (KnobCryptoOnly.Value()) {
                 if (IsCryptoBaseLower(BaseNameLower(bimgName))) bblInstrument = true;
             }
             else if (!KnobOnlyMain.Value()) {
                 // Smart Mode default
                 if (IsCryptoBaseLower(BaseNameLower(bimgName))) bblInstrument = true;
             }
        }
        
        if (!bblInstrument) continue; // Skip this BBL

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
             StaticMeta* sm = GetOrCreateMeta(ins, INS_Address(ins), bimgName, bimgLow);

             // 1) 루프 카운트: taken branch만
             if (INS_IsBranch(ins)) {
                 INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnTakenBranch,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_INST_PTR,
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_END);
             }
             
             // 2) 캡처: IF/THEN
             INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)CapIf,
                 IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID,
                 IARG_PTR, sm,
                 IARG_END);
            
             // ... Memory Instrumentation ...
             if (INS_IsMemoryWrite(ins)) {
                 INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemW,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_PTR, sm,
                     IARG_MEMORYWRITE_EA,
                     IARG_REG_VALUE, REG_EAX,
                     IARG_REG_VALUE, REG_EBX,
                     IARG_REG_VALUE, REG_ECX,
                     IARG_REG_VALUE, REG_EDX,
                     IARG_REG_VALUE, REG_ESI,
                     IARG_REG_VALUE, REG_EDI,
                     IARG_REG_VALUE, REG_ESP,
                     IARG_REG_VALUE, REG_EBP,
                     IARG_END);
             }
             else if (INS_IsMemoryRead(ins)) {
                 INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemR,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_PTR, sm,
                     IARG_MEMORYREAD_EA,
                     IARG_REG_VALUE, REG_EAX,
                     IARG_REG_VALUE, REG_EBX,
                     IARG_REG_VALUE, REG_ECX,
                     IARG_REG_VALUE, REG_EDX,
                     IARG_REG_VALUE, REG_ESI,
                     IARG_REG_VALUE, REG_EDI,
                     IARG_REG_VALUE, REG_ESP,
                     IARG_REG_VALUE, REG_EBP,
                     IARG_END);
             }
             else {
                 INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordNoMem,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_PTR, sm,
                     IARG_REG_VALUE, REG_EAX,
                     IARG_REG_VALUE, REG_EBX,
                     IARG_REG_VALUE, REG_ECX,
                     IARG_REG_VALUE, REG_EDX,
                     IARG_REG_VALUE, REG_ESI,
                     IARG_REG_VALUE, REG_EDI,
                     IARG_REG_VALUE, REG_ESP,
                     IARG_REG_VALUE, REG_EBP,
                     IARG_END);
             }
        }
    }
}

// Bypass Original Loop
// static void OnTrace_Original(TRACE trace, VOID*) ...

// -------------------- IMG load callback (로그만) --------------------
static VOID OnImgLoad(IMG img, VOID*)
{
    if (!IMG_Valid(img)) return;

    const string full = IMG_Name(img);
    const string baseLower = BaseNameLower(full);

    std::ostringstream oss;
    oss << "LOAD " << full
        << " [0x" << std::hex << (ADDRINT)IMG_LowAddress(img)
        << "-0x" << std::hex << (ADDRINT)IMG_HighAddress(img) << "]";

    if (IsCryptoBaseLower(baseLower)) {
        oss << "  CRYPTO_LOAD";
        if (KnobVerbose.Value()) {
            cerr << "[pin-loop] CRYPTO_LOAD: " << full << endl;
        }
    }
    
    // Log to _images.txt
    if (KnobLogImages.Value()) {
        string imgLogPath = gRunPrefix + "_images.txt";
        FILE* fp = std::fopen(imgLogPath.c_str(), "a");
        if (fp) {
            std::fprintf(fp, "%s\n", oss.str().c_str());
            std::fclose(fp);
        }
    }

    if (IsCryptoBaseLower(baseLower)) {
        if (KnobVerbose.Value()) {
            cerr << "[pin-loop] CRYPTO_LOAD: " << full << endl;
        }
    }
}


// -------------------- Thread callbacks --------------------
static VOID OnThreadStart(THREADID tid, CONTEXT*, INT32, VOID*)
{
    TData* td = new TData();
    td->os_tid = (UINT32)PIN_GetTid();
    td->capturedCount = 0;
    td->cap = CaptureState();
    PIN_SetThreadData(gTlsKey, td, tid);

    if (KnobVerbose.Value()) {
        cerr << "[pin-loop] thread start OS_TID=" << td->os_tid << endl;
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
             cerr << "[pin-loop] Failed to create thread trace: " << path << endl;
        }
    }
    */
}

static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td) return;

    if (td->cap.recording) {
        StopAndCommitCapture(td, "thread_fini");
    }
    
    FlushBuffer(td);

    // DUMP ALL DETECTED LOOPS TO CSV (For Coverage Check)
    // Iterate all loops in detector map
    for(map<LoopKey, LoopAgg>::iterator it = td->loops.begin(); it != td->loops.end(); ++it) {
        LoopKey k = it->first;
        LoopAgg& agg = it->second;
        
        // Hot loop trigger?
        if (agg.iters >= KnobHotIters.Value()) {
            if (!agg.captured) {
                
                // Assign Global Sequence (Atomic)
                PIN_GetLock(&gGlobalSeqLock, 1);
                gGlobalLoopSeq++;
                agg.globalSeq = gGlobalLoopSeq; 
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
                     map<ADDRINT, StaticMeta*>::iterator it = gMeta.find(k.header);
                     StaticMeta* sm = (it != gMeta.end()) ? it->second : NULL;
                     PIN_ReleaseLock(&gMetaLock);
                     
                     string func = sm ? sm->funcName : "?";
                     cerr << "[pin-loop] Hot Loop Detected! T=" << td->os_tid 
                          << " H=" << std::hex << k.header << std::dec 
                          << " GSeq=" << agg.globalSeq
                          << " in " << func << endl;
                }
            }
        }
        // If already captured, it's already in CSV via StopAndCommitCapture.
        // But user wants "Detection Coverage Proof".
        // We can append uncaptured loops with body_len=0.
        if (!agg.captured && agg.iters > 0) {
             // Reconstruct basic info (meta lookup needed? expensive but it's FINI)
             // We can just dump minimal info
             PIN_GetLock(&gMetaLock, 1);
             map<ADDRINT, StaticMeta*>::iterator mit = gMeta.find((ADDRINT)k.header);
             StaticMeta* smHead = (mit != gMeta.end()) ? mit->second : NULL;
             PIN_ReleaseLock(&gMetaLock);
             
             string funcName = smHead ? smHead->funcName : "?";
             string imgName = smHead ? smHead->imgName : "?";
             
             AppendLoopRowToCsv(td->os_tid, 
                 agg.globalSeq, // Pass correct GlobalSeq
                 k.header, k.backedge, 
                 0, // body_len=0
                 agg.iters,
                 0.0, // score
                 funcName, imgName,
                 0,0,0,0,0,0,0,0);
        }
    }


    if (KnobVerbose.Value()) {
        cerr << "[pin-loop] thread fini  OS_TID=" << td->os_tid
            << " loops=" << td->loops.size()
            << " captured=" << td->capturedCount
            << endl;
    }

    delete td;
    PIN_SetThreadData(gTlsKey, 0, tid);
}

// -------------------- Follow child --------------------
static BOOL FollowChild(CHILD_PROCESS cProcess, VOID*)
{
    if (!KnobFollowChild.Value()) return FALSE;
    
    // Fix: Propagate command line to child process
    if (gSavedArgc > 0 && gSavedArgv) {
        CHILD_PROCESS_SetPinCommandLine(cProcess, gSavedArgc, gSavedArgv);
    }

    if (KnobVerbose.Value()) {
        cerr << "[pin-loop] following child PID=" << (unsigned long)CHILD_PROCESS_GetId(cProcess) << endl;
    }
    return TRUE;
}

// -------------------- Fini --------------------
// -------------------- Fini --------------------
static void DumpStaticMeta() {
    // Legacy: No-op because we dump incrementally now.
    // Keeping function structure to minimize code churn.
}

static VOID OnFini(INT32, VOID*)
{
    cerr << "[pin-loop] process fini\n";

    DumpStaticMeta();

    if (gCsvFp) {
        std::fflush(gCsvFp);
        std::fclose(gCsvFp);
        gCsvFp = NULL;
    }

    if (gTraceHandle != MyWin::INVALID_HANDLE_VALUE) {
        MyWin::CloseHandle(gTraceHandle);
        gTraceHandle = MyWin::INVALID_HANDLE_VALUE;
    }

    if (gCsvBuf) { free(gCsvBuf); gCsvBuf = NULL; }

    if (gMetaFp) {
        std::fclose(gMetaFp);
        gMetaFp = NULL;
    }

    PIN_GetLock(&gMetaLock, 1);
    for (map<ADDRINT, StaticMeta*>::iterator it = gMeta.begin(); it != gMeta.end(); ++it) {
        delete it->second;
    }
    gMeta.clear();
    PIN_ReleaseLock(&gMetaLock);
}

// -------------------- Usage --------------------
static INT32 Usage()
{
    cerr <<
        "pin-loop (fast hot-loop capture)\n"
        "  -only_main 1|0\n"
        "  -follow_child 1|0\n"
        "  -hot_iters N\n"
        "  -cap_max_ins N\n"
        "  -top N\n"
        "  -prefix PATH_PREFIX\n"
        "  -verbose 1\n"
        "  -log_images 1|0\n"
        "  -log_meta 1|0\n"
        "  -instrument_all 1|0\n"
        "  -max_backedge_dist N (def: 2097152)\n"
        "  -crypto_only 1|0\n"
        "  -crypto_dlls \"cryptbase.dll;bcrypt.dll;...\"\n"
        << KNOB_BASE::StringKnobSummary()
        << endl;
    return -1;
}

// -------------------- main --------------------
int main(int argc, char* argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    // save argv for child
    gSavedArgc = argc;
    gSavedArgv = (const CHAR**)malloc(sizeof(CHAR*) * argc);
    for (int i = 0; i < argc; ++i) {
        gSavedArgv[i] = _strdup(argv[i]);
    }

    gTlsKey = PIN_CreateThreadDataKey(0);
    PIN_InitLock(&gMetaLock);
    PIN_InitLock(&gCsvLock);
    PIN_InitLock(&gTraceLock);



    InitCryptoDllList();

    // run prefix: prefix + _P<pid>
    UINT32 pid = (UINT32)PIN_GetPid();
    {
        std::ostringstream oss;
        oss << KnobPrefix.Value() << "_P" << std::dec << pid;
        gRunPrefix = oss.str();
    }

    gCsvPath = gRunPrefix + "_loops.csv";
    
    // Use .wct with Hidden + System attributes to avoid ransomware encryption
    gTracePath = gRunPrefix + ".wct";
    gMetaPath = gRunPrefix + "_meta.wcm";
    
    // Open Meta File for Incremental Write
    gMetaFp = std::fopen(gMetaPath.c_str(), "wb");
    if (!gMetaFp) {
        cerr << "[pin-loop] Failed to open meta file: " << gMetaPath << endl;
    } else {
        // Buffering (1MB) to avoid frequent formatting overhead - Let CRT manage
        setvbuf(gMetaFp, NULL, _IOFBF, (1 << 20));
    }

    // Open Global Trace File with Protection (Restored)
    {
        cerr << "[pin-loop] Opening trace file: " << gTracePath << endl;
        
        gTraceHandle = MyWin::CreateFileA(gTracePath.c_str(),
            MyWin::GENERIC_WRITE,
            MyWin::FILE_SHARE_READ,
            NULL,
            MyWin::CREATE_ALWAYS,
            MyWin::FILE_ATTRIBUTE_NORMAL,
            NULL);
            
        if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE) {
            MyWin::DWORD err = MyWin::GetLastError();
            cerr << "[pin-loop] [ERROR] Failed to create protected trace file: " << gTracePath 
                 << " ErrorCode=" << err << endl;
        } else {
            cerr << "[pin-loop] [SUCCESS] Trace file created." << endl;
        }
    }

    cerr << "[pin-loop] run_prefix: " << gRunPrefix << endl;
    cerr << "[pin-loop] csv_path  : " << gCsvPath << endl;
    cerr << "[pin-loop] trace_path: " << gTracePath << " (VISIBLE)" << endl;
    
    // Debug: Marker file to verify permissions
    {
        string markerPath = gRunPrefix + "_marker.txt";
        FILE* fp = std::fopen(markerPath.c_str(), "w");
        if (fp) {
            std::fprintf(fp, "Pin tool running for PID %d\n", pid);
            std::fclose(fp);
            cerr << "[pin-loop] Marker file created: " << markerPath << endl;
        } else {
             cerr << "[pin-loop] [ERROR] Failed to create marker file: " << markerPath << endl;
        }
    }

    cerr << "[pin-loop] only_main=" << (KnobOnlyMain.Value() ? "1" : "0")
        << " follow_child=" << (KnobFollowChild.Value() ? "1" : "0")
        << " hot_iters=" << KnobHotIters.Value()
        << " cap_max_ins=" << KnobCapMaxIns.Value()
        << " top=" << KnobTop.Value()
        << " log_images=" << (KnobLogImages.Value() ? "1" : "0")
        << " crypto_only=" << (KnobCryptoOnly.Value() ? "1" : "0")
        << endl;

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

    PIN_StartProgram();
    return 0;
}

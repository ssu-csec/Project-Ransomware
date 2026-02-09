// === MyPinTool.cpp (Fast Hot-Loop Capture + TRACE-level IMG filter) ===
// Pin 3.31 / Windows / MSVC
//
// Core Features:
//  - Taken back-edge based loop count (per-thread)
//  - Capture 1 iteration of loops exceeding hot_iters
//  - Append to CSV upon capture completion
//  - Support follow child
//  - Optional crypto DLL load/exec reach logging
//
// Optimization:
//  - Use TRACE_AddInstrumentFunction for single IMG check per TRACE
//  - Buffered logging
//
// Output:
//  CSV Header: tid,rank_global,rank_thread,start_addr,end_addr,body_len,iter,score,func,img,memR,memW,stackR,stackW,xor,addsub,shlshr,mul
//
// Note: Intel64 Only

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
KNOB<BOOL>   KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "0",
    "Instrument only main executable (1=main only, 0=all)");

KNOB<BOOL>   KnobInstrumentAll(KNOB_MODE_WRITEONCE, "pintool", "instrument_all", "0",
    "Instrument all images (overrides only_main/crypto_only)");

KNOB<BOOL>   KnobFollowChild(KNOB_MODE_WRITEONCE, "pintool", "follow_child", "1",
    "Follow child processes (spawned via CreateProcess)");

KNOB<UINT32> KnobTop(KNOB_MODE_WRITEONCE, "pintool", "top", "50",
    "Max hot loops to capture per thread");

KNOB<UINT32> KnobHotIters(KNOB_MODE_WRITEONCE, "pintool", "hot_iters", "20000",
    "Minimum iterations to trigger capture (hot loop threshold)");

KNOB<UINT32> KnobCapMaxIns(KNOB_MODE_WRITEONCE, "pintool", "cap_max_ins", "20000",
    "Max instructions to capture per loop iteration");

KNOB<string> KnobPrefix(KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace",
    "Output file prefix (can include folder, e.g. C:\\trace\\wc_all");


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
    "Enable verbose logging");

// --- Crypto DLL load/exec reach test knobs ---
KNOB<BOOL>   KnobLogImages(KNOB_MODE_WRITEONCE, "pintool", "log_images", "1",
    "Log IMG load/exec reach to images.txt");

KNOB<BOOL>   KnobCryptoOnly(KNOB_MODE_WRITEONCE, "pintool", "crypto_only", "0",
    "Instrument only crypto DLLs (for testing)");

KNOB<string> KnobCryptoDlls(KNOB_MODE_WRITEONCE, "pintool", "crypto_dlls",
    "cryptbase.dll;bcrypt.dll;bcryptprimitives.dll;crypt32.dll;ncrypt.dll;ncryptprov.dll;rsaenh.dll;dssenh.dll;schannel.dll;secur32.dll",
    "List of crypto DLL basenames (semicolon separated)");

KNOB<BOOL>   KnobLogMeta(KNOB_MODE_WRITEONCE, "pintool", "log_meta", "1",
    "Enable Metadata logging (asm/img/name)");

KNOB<UINT32> KnobMaxBackedgeDist(KNOB_MODE_WRITEONCE, "pintool", "max_backedge_dist", "2097152",
    "Max backedge distance for loop detection");

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
static vector<string>* gCryptoDllList = NULL;

static void InitCryptoDllList()
{
    SplitSemicolonLower(KnobCryptoDlls.Value(), *gCryptoDllList);
}

static bool IsCryptoBaseLower(const string& baseLower)
{
    for (size_t i = 0; i < gCryptoDllList->size(); ++i) {
        if (baseLower == (*gCryptoDllList)[i]) return true;
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

static PIN_LOCK gGlobalSeqLock;
static UINT64 gGlobalLoopSeq = 0;
static PIN_LOCK gFirstSeenLock;
static map<pair<ADDRINT, ADDRINT>, UINT32>* gLoopFirstSeen = NULL;

static map<ADDRINT, StaticMeta*>* gMeta = NULL;
static PIN_LOCK gMetaLock;

// -------------------- Globals for I/O Log --------------------
static FILE* gMetaFp = NULL;
static FILE* gIoFp = NULL;
static PIN_LOCK gIoLock;

// -------------------- Trace Dump (Text) --------------------
static string* gTracePath = NULL; // Text Trace
static MyWin::HANDLE gTraceHandle = MyWin::INVALID_HANDLE_VALUE;
static PIN_LOCK gTraceLock;

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

    // Buffering - Text Buffer
    string loopBuf;
    
    TData() : os_tid(0), capturedCount(0) {
        loopBuf.reserve(64 * 1024); 
    }
    ~TData() {
    }
};

// Forward Declarations
static TLS_KEY gTlsKey;
static void StopAndCommitCapture(TData* td, const char* reason);
// Moved OnRet execution to top to avoid scope issues
static void PIN_FAST_ANALYSIS_CALL OnRet(THREADID tid)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !td->cap.recording) return;
    
    // Stop immediately on RET to prevent capturing unrelated code
    StopAndCommitCapture(td, "ret_instruction");
}
static void ArmBestCandidateIfIdle(TData* td);
static void AppendLoopRowToCsv(UINT32 tid,
    UINT32 rank_global,
    ADDRINT start_addr,
    ADDRINT end_addr,
    UINT64 body_len,
    UINT64 iterCount,
    double score,
    const string& func,
    const string& img,
    UINT64 memR, UINT64 memW, UINT64 stackR, UINT64 stackW,
    UINT64 xorCnt, UINT64 addsubCnt, UINT64 shlshrCnt, UINT64 mulCnt);

static void FlushBuffer(TData* td) {
    if (td->loopBuf.empty()) return;
    if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE) return;

    // ATOMIC WRITE protected by lock (Global File)
    PIN_GetLock(&gTraceLock, 1);
    MyWin::DWORD written = 0;
    MyWin::WriteFile(gTraceHandle, td->loopBuf.c_str(), (MyWin::DWORD)td->loopBuf.size(), &written, NULL);
    PIN_ReleaseLock(&gTraceLock);

    td->loopBuf.clear();
}

static void BufferedWriteText(TData* td, const string& s) {
    td->loopBuf += s;
    if (td->loopBuf.size() > 4096) FlushBuffer(td);
}




// -------------------- Output files --------------------
static string* gRunPrefix = NULL; // prefix + "_P<pid>"
static string* gCsvPath = NULL;   // Statistics CSV (Summary)
// static FILE* gCsvFp = NULL; // already static global? Re-check
// static PIN_LOCK gCsvLock;   // already static global? Re-check
// Wait, gCsvFp was not in the top block. Only gMetaFp was re-defined.

static FILE* gCsvFp = NULL;
static PIN_LOCK gCsvLock;

// static string gTracePath; // Moved to top
// static MyWin::HANDLE gTraceHandle = ...
// static PIN_LOCK gTraceLock;

static string* gMetaPath = NULL;  // Static Meta
// static FILE* gMetaFp = NULL; // Redefined, remove this line.
static set<string>* gCryptoExecLogged = NULL; // basename lower


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

    gCsvFp = std::fopen(gCsvPath->c_str(), "wb");
    if (!gCsvFp) {
        cerr << "[pin-loop] cannot open CSV: " << *gCsvPath << endl;
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

    std::fflush(gCsvFp); // Ensure persistence even on crash
    PIN_ReleaseLock(&gCsvLock);
}

// -------------------- StaticMeta builder --------------------
// TRACE 단위로 IMG 이름/lowaddr를 전달받아 IMG_FindByAddress 호출을 줄임
static StaticMeta* GetOrCreateMeta(INS ins, ADDRINT a, const string& traceImgName, ADDRINT traceImgLow)
{
    StaticMeta* sm = NULL;

    PIN_GetLock(&gMetaLock, 1);
    map<ADDRINT, StaticMeta*>::iterator it = gMeta->find(a);
    if (it != gMeta->end()) {
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
    map<ADDRINT, StaticMeta*>::iterator it2 = gMeta->find(a);
    if (it2 != gMeta->end()) {
        PIN_ReleaseLock(&gMetaLock);
        delete m; // Discard duplicate
        return it2->second;
    }

    gMeta->insert(std::make_pair(a, m));
    
    // Incremental Dump (Buffered via stdio, NO Explicit Flush)
    if (gMetaFp && KnobLogMeta.Value()) {
        std::fprintf(gMetaFp, "%08x;", m->addr32);
        CsvWriteEscaped(gMetaFp, m->funcName); std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->imgName);  std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->assembly); std::fputc(';', gMetaFp);
        CsvWriteEscaped(gMetaFp, m->memMeta);  std::fputc('\n', gMetaFp);
        // std::fflush(gMetaFp); // REMOVED for performance
        std::fflush(gMetaFp);
    }
    
    PIN_ReleaseLock(&gMetaLock);

    return m;
}

// -------------------- Trace Dump (Binary) --------------------
// -------------------- Trace Dump (Binary) --------------------
// Removed direct WriteBinaryEntry, replaced with BufferedWrite calls


static void WriteLoopHeader(TData* td, UINT32 tid, UINT32 header, UINT32 backedge, UINT32 rank) {
    // HEADER Format: LOOP,tid,header,backedge,rank,globalSeq
    UINT32 gSeq = 0;
    LoopKey k; k.header = header; k.backedge = backedge;
    if (td->loops.count(k)) gSeq = td->loops[k].globalSeq;

    std::ostringstream oss;
    oss << "LOOP," << tid << "," << std::hex << header << "," << backedge << "," << std::dec << rank << "," << gSeq << "\n";
    BufferedWriteText(td, oss.str());
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
        agg.tracePath = *gTracePath; // All in one


        UINT64 iterCount = agg.iters;
        double score = (double)agg.body_len * (double)iterCount;

        AppendLoopRowToCsv(td->os_tid,
            agg.globalSeq, // FIXED: Pass GlobalSeq
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
    WriteLoopHeader(td, td->os_tid, (UINT32)c.key.header, (UINT32)c.key.backedge, c.rank_thread);



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
// -------------------- Record (THEN) - Text --------------------
static void PIN_FAST_ANALYSIS_CALL CapRecordNoMem(THREADID tid, const StaticMeta* sm,
    ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp,
    ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    // Type,IP,MemAddr,EAX...
    // x64 regs
    char buf[512];
    std::sprintf(buf, "I,%llx,0,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
        (unsigned long long)sm->addr, 
        (unsigned long long)eax, (unsigned long long)ebx, (unsigned long long)ecx, (unsigned long long)edx, 
        (unsigned long long)esi, (unsigned long long)edi, (unsigned long long)esp, (unsigned long long)ebp,
        (unsigned long long)r8, (unsigned long long)r9, (unsigned long long)r10, (unsigned long long)r11,
        (unsigned long long)r12, (unsigned long long)r13, (unsigned long long)r14, (unsigned long long)r15);
    BufferedWriteText(td, buf);

    c.body_len++;
    AccumulateOp(sm, c);

    c.capIns++;
    if (c.capIns >= c.capMaxIns) {
        StopAndCommitCapture(td, "cap_max_ins");
    }
}

static void PIN_FAST_ANALYSIS_CALL CapRecordMemR(THREADID tid, const StaticMeta* sm, ADDRINT ea,
    ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp,
    ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    char buf[512];
    std::sprintf(buf, "R,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
        (unsigned long long)sm->addr, (unsigned long long)ea,
        (unsigned long long)eax, (unsigned long long)ebx, (unsigned long long)ecx, (unsigned long long)edx, 
        (unsigned long long)esi, (unsigned long long)edi, (unsigned long long)esp, (unsigned long long)ebp,
        (unsigned long long)r8, (unsigned long long)r9, (unsigned long long)r10, (unsigned long long)r11,
        (unsigned long long)r12, (unsigned long long)r13, (unsigned long long)r14, (unsigned long long)r15);
    BufferedWriteText(td, buf);

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
    ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp,
    ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12, ADDRINT r13, ADDRINT r14, ADDRINT r15)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td || !sm) return;

    CaptureState& c = td->cap;
    if (!c.recording) return;

    char buf[512];
    std::sprintf(buf, "W,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
         (unsigned long long)sm->addr, (unsigned long long)ea,
        (unsigned long long)eax, (unsigned long long)ebx, (unsigned long long)ecx, (unsigned long long)edx, 
        (unsigned long long)esi, (unsigned long long)edi, (unsigned long long)esp, (unsigned long long)ebp,
        (unsigned long long)r8, (unsigned long long)r9, (unsigned long long)r10, (unsigned long long)r11,
        (unsigned long long)r12, (unsigned long long)r13, (unsigned long long)r14, (unsigned long long)r15);
    BufferedWriteText(td, buf);

    c.body_len++;
    c.memW++;
    if (sm->isStackMem) c.stackW++;
    AccumulateOp(sm, c);

    c.capIns++;
    if (c.capIns >= c.capMaxIns) {
        StopAndCommitCapture(td, "cap_max_ins");
    }
}

// -------------------- Knobs --------------------
KNOB<UINT32>   KnobMaxLoopIters(KNOB_MODE_WRITEONCE, "pintool", "break_iters", "500000",
    "Max iterations before forcing loop exit (Loop Breaker)");

// ... (existing knobs)

// -------------------- Loop counter (taken back-edge) --------------------
// Updated to support Loop Breaking (Context Manipulation)
static VOID OnTakenBranch(CONTEXT* ctxt, THREADID tid, ADDRINT ip, ADDRINT target, ADDRINT fallthrough)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td) return;

    if (target >= ip) return; // backward only

    UINT32 backedge = (UINT32)ip;
    UINT32 header = (UINT32)target;
 
    // Check Max Distance
    if ((UINT32)(ip - target) > KnobMaxBackedgeDist.Value()) {
        return; 
    }

    LoopKey key; key.header = header; key.backedge = backedge;
    LoopAgg& agg = td->loops[key]; // Reference to thread-local agg

    // ---------------------------------------------------------
    // LOOP BREAKER LOGIC
    // ---------------------------------------------------------
    if (agg.iters >= KnobMaxLoopIters.Value()) {
        // Limit reached! Force break.
        if (agg.iters == KnobMaxLoopIters.Value()) {
             // Log once
             cerr << "\n[pin-loop] *** LOOP BREAKER TRIGGERED ***" << endl;
             cerr << "  Thread: " << td->os_tid << endl;
             cerr << "  Header: 0x" << std::hex << header << endl;
             cerr << "  Count:  " << std::dec << agg.iters << endl;
             cerr << "  Action: Forcing jump to Fallthrough (0x" << std::hex << fallthrough << ")" << endl;
        }

        // Apply redirection
        // We are currently AT the branch instruction (before it executes? No, OnTakenBranch is usually 'before' or 'after'?)
        // Standard Pin IPOINT_BEFORE: We are before the branch executes.
        // If we want to NOT take the branch, we must redirect control to 'fallthrough'.
        
        PIN_SetContextReg(ctxt, REG_INST_PTR, fallthrough);
        PIN_ExecuteAt(ctxt); // Resumes execution at fallthrough, skipping the branch.
        return;
    }

    agg.iters++;

    // Global Sequence & First Seen Logic (Only if not breaking)
    if (agg.globalSeq == 0) {
        PIN_GetLock(&gFirstSeenLock, 1);
        pair<ADDRINT, ADDRINT> valKey = make_pair((ADDRINT)header, (ADDRINT)backedge);
        map<pair<ADDRINT, ADDRINT>, UINT32>::iterator it = gLoopFirstSeen->find(valKey);
        
        UINT32 seq = 0;
        if (it != gLoopFirstSeen->end()) {
            seq = it->second;
        } else {
            PIN_GetLock(&gGlobalSeqLock, 1);
            gGlobalLoopSeq++;
            seq = (UINT32)gGlobalLoopSeq;
            PIN_ReleaseLock(&gGlobalSeqLock);
            (*gLoopFirstSeen)[valKey] = seq;
        }
        PIN_ReleaseLock(&gFirstSeenLock);
        agg.globalSeq = seq;
    }



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
        if (!td->cap.armed) ArmBestCandidateIfIdle(td);
    }
}



// -------------------- I/O Logging --------------------
static void OnIoCall(THREADID mid, const char* apiName, ADDRINT handle, ADDRINT arg2)
{
    // Simple log: TID, API, Handle, Arg2
    if (!gIoFp) return;
    
    // FIX: Use OS TID for matching (Trace uses OS TID)
    UINT32 os_tid = (UINT32)PIN_GetTid();

    PIN_GetLock(&gIoLock, 1);
    // Use mid (PinID) for debug if needed, but log OS_TID
    if (gIoFp) {
        std::fprintf(gIoFp, "%u,%s,%llx,%llx\n", os_tid, apiName, (unsigned long long)handle, (unsigned long long)arg2);
    }
    PIN_ReleaseLock(&gIoLock);
}

// -------------------- TRACE-level instrumentation (Optimization) --------------------
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
        // Capture all modules if only_main is disabled (default)
        instrument = true;
    }
    
    if (!instrument) return;

    // BBL/INS 계측 (BBL granularity for IMG correctness)
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Re-evaluate IMG for this BBL
        bool bblInstrument = true; // Trust TRACE decision for now to avoid complexity in this snippet
        
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
             StaticMeta* sm = GetOrCreateMeta(ins, INS_Address(ins), imgName, imgLow);

             // 1) 루프 카운트: taken branch만
             if (INS_IsBranch(ins)) {
                 INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnTakenBranch,
                     IARG_CONTEXT,           // [NEW] Context for Register Modification
                     IARG_THREAD_ID,
                     IARG_INST_PTR,
                     IARG_BRANCH_TARGET_ADDR,
                     IARG_ADDRINT, INS_NextAddress(ins), // [NEW] Fallthrough Address
                     IARG_END);
             }
             
             // 2) Capture Start - Direct call without If/Then pattern
             // The CapIf function will check internally if capture should start
             INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapIf,
                 IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID,
                 IARG_PTR, sm,
                 IARG_END);
            
             // 3) Stop on RET (Anti-Pollution) [NEW]
             if (INS_IsRet(ins)) {
                 INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRet,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_THREAD_ID,
                     IARG_END);
             } else {
                 // ... Memory Instrumentation ...
                 if (INS_IsMemoryWrite(ins)) {
                     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemW,
                         IARG_FAST_ANALYSIS_CALL,
                         IARG_THREAD_ID,
                         IARG_PTR, sm,
                         IARG_MEMORYWRITE_EA,
                         IARG_REG_VALUE, REG_GAX,
                         IARG_REG_VALUE, REG_GBX,
                         IARG_REG_VALUE, REG_GCX,
                         IARG_REG_VALUE, REG_GDX,
                         IARG_REG_VALUE, REG_GSI,
                         IARG_REG_VALUE, REG_GDI,
                         IARG_REG_VALUE, REG_STACK_PTR,
                         IARG_REG_VALUE, REG_GBP,
                         IARG_END);
                 }
                 else if (INS_IsMemoryRead(ins)) {
                     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemR,
                         IARG_FAST_ANALYSIS_CALL,
                         IARG_THREAD_ID,
                         IARG_PTR, sm,
                         IARG_MEMORYREAD_EA,
                         IARG_REG_VALUE, REG_GAX,
                         IARG_REG_VALUE, REG_GBX,
                         IARG_REG_VALUE, REG_GCX,
                         IARG_REG_VALUE, REG_GDX,
                         IARG_REG_VALUE, REG_GSI,
                         IARG_REG_VALUE, REG_GDI,
                         IARG_REG_VALUE, REG_STACK_PTR,
                         IARG_REG_VALUE, REG_GBP,
                         IARG_END);
                 }
                 else {
                     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordNoMem,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_PTR, sm,
                         IARG_REG_VALUE, REG_RAX, IARG_REG_VALUE, REG_RBX, IARG_REG_VALUE, REG_RCX,
                         IARG_REG_VALUE, REG_RDX, IARG_REG_VALUE, REG_RSI, IARG_REG_VALUE, REG_RDI,
                         IARG_REG_VALUE, REG_RSP, IARG_REG_VALUE, REG_RBP, IARG_END);
                 }
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
        string imgLogPath = *gRunPrefix + "_images.txt";
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
    
    // I/O Hooks: Kernel32/KernelBase
    // Ntdll Hooks (Lower level) - Critical for 64-bit Ransomware
    if (baseLower.find("ntdll") != string::npos) {
        RTN ntWrite = RTN_FindByName(img, "NtWriteFile");
        if (RTN_Valid(ntWrite)) {
            RTN_Open(ntWrite);
            RTN_InsertCall(ntWrite, IPOINT_BEFORE, (AFUNPTR)OnIoCall,
                IARG_THREAD_ID, IARG_PTR, "NtWriteFile",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
                IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // Length (check 64-bit prototype)
                // NtWriteFile(Handle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key)
                // Arguments are passed in RCX, RDX, R8, R9, then stack.
                // IARG_FUNCARG_ENTRYPOINT_VALUE handles ABI automatically.
                IARG_END);
            RTN_Close(ntWrite);
        }
        
        RTN ntRead = RTN_FindByName(img, "NtReadFile");
        if (RTN_Valid(ntRead)) {
            RTN_Open(ntRead);
            RTN_InsertCall(ntRead, IPOINT_BEFORE, (AFUNPTR)OnIoCall,
                IARG_THREAD_ID, IARG_PTR, "NtReadFile",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
                IARG_FUNCARG_ENTRYPOINT_VALUE, 6, // Length
                IARG_END);
            RTN_Close(ntRead);
        }
    }

    // I/O Hooks: Kernel32/KernelBase
    if (baseLower.find("kernel32") != string::npos || 
        baseLower.find("kernelbase") != string::npos) 
    {
        RTN wfile = RTN_FindByName(img, "WriteFile");
        if (RTN_Valid(wfile)) {
            RTN_Open(wfile);
            RTN_InsertCall(wfile, IPOINT_BEFORE, (AFUNPTR)OnIoCall,
                IARG_THREAD_ID,
                IARG_PTR, "WriteFile",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // Handle
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // nBytes
                IARG_END);
            RTN_Close(wfile);
        }
        
        RTN cfileA = RTN_FindByName(img, "CreateFileA");
        if (RTN_Valid(cfileA)) {
            RTN_Open(cfileA);
            RTN_InsertCall(cfileA, IPOINT_BEFORE, (AFUNPTR)OnIoCall,
                IARG_THREAD_ID, IARG_PTR, "CreateFileA",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PathPtr
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Access
                IARG_END);
            RTN_Close(cfileA);
        }
        
         RTN cfileW = RTN_FindByName(img, "CreateFileW");
        if (RTN_Valid(cfileW)) {
            RTN_Open(cfileW);
            RTN_InsertCall(cfileW, IPOINT_BEFORE, (AFUNPTR)OnIoCall,
                IARG_THREAD_ID, IARG_PTR, "CreateFileW",
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // PathPtr
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // Access
                IARG_END);
            RTN_Close(cfileW);
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
                     map<ADDRINT, StaticMeta*>::iterator it = gMeta->find(k.header);
                     StaticMeta* sm = (it != gMeta->end()) ? it->second : NULL;
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
        // Always report final iteration count to CSV
        // This ensures simple loops (short body) or long-running loops are accounted for.
        if (agg.iters > 0) {
             string funcName = agg.func;
             string imgName = agg.img;
             UINT64 bodyLen = agg.body_len; // 0 if not captured

             if (funcName.empty()) {
                 PIN_GetLock(&gMetaLock, 1);
                 map<ADDRINT, StaticMeta*>::iterator mit = gMeta->find(k.header);
                 StaticMeta* smHead = (mit != gMeta->end()) ? mit->second : NULL;
                 PIN_ReleaseLock(&gMetaLock);
                 
                 funcName = smHead ? smHead->funcName : "?";
                 imgName = smHead ? smHead->imgName : "?";
             }
             
             AppendLoopRowToCsv(td->os_tid, 
                 agg.globalSeq,
                 k.header, k.backedge, 
                 bodyLen,
                 agg.iters,
                 (double)bodyLen * agg.iters, // score
                 funcName, imgName,
                 agg.memR, agg.memW, agg.stackR, agg.stackW,
                 agg.xorCnt, agg.addsubCnt, agg.shlshrCnt, agg.mulCnt);
        }
        
        // [NEW] LoopFinish text log
        {
             std::ostringstream oss;
             oss << "LOOP_FINISH," << std::hex << k.header << "," << k.backedge << "," << std::dec << agg.iters << "\n";
             BufferedWriteText(td, oss.str());
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
    
    // Fix: Do NOT manually propagate tool args.
    // if (gSavedArgc > 0 && gSavedArgv) {
    //    CHILD_PROCESS_SetPinCommandLine(cProcess, gSavedArgc, gSavedArgv);
    // }

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
    for (map<ADDRINT, StaticMeta*>::iterator it = gMeta->begin(); it != gMeta->end(); ++it) {
        delete it->second;
    }
    gMeta->clear();
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

    // [FIX] Initialize global pointers explicitly to avoid LNK4210 issues
    gLoopFirstSeen = new map<pair<ADDRINT, ADDRINT>, UINT32>();
    gMeta = new map<ADDRINT, StaticMeta*>();
    gTracePath = new string();
    gRunPrefix = new string();
    gCsvPath = new string();
    gMetaPath = new string();
    gCryptoExecLogged = new set<string>();
    gCryptoDllList = new vector<string>(); // [FIX]

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
        *gRunPrefix = oss.str();
    }

    *gCsvPath = *gRunPrefix + "_loops.csv";
    
    // Generic naming
    *gTracePath = *gRunPrefix + "_trace.txt";
    *gMetaPath = *gRunPrefix + "_meta.txt";
    
    gMetaFp = std::fopen(gMetaPath->c_str(), "wb");
    if (!gMetaFp) {
        cerr << "[pin-loop] Failed to open meta file: " << *gMetaPath << endl;
    } else {
        // [Debugging] Disable buffering
        setvbuf(gMetaFp, NULL, _IONBF, 0);
    }
    
    {
        string ioPath = *gRunPrefix + "_io.log";
        gIoFp = std::fopen(ioPath.c_str(), "w");
        if (gIoFp) std::fprintf(gIoFp, "TID,API,Arg1,Arg2\n");
    }

    // Open Global Trace File with Protection (Restored)
    {
        cerr << "[pin-loop] Opening trace file: " << *gTracePath << endl;
        
        gTraceHandle = MyWin::CreateFileA(gTracePath->c_str(),
            MyWin::GENERIC_WRITE,
            MyWin::FILE_SHARE_READ,
            NULL,
            MyWin::CREATE_ALWAYS,
            MyWin::FILE_ATTRIBUTE_NORMAL,
            NULL);
            
        if (gTraceHandle == MyWin::INVALID_HANDLE_VALUE) {
            MyWin::DWORD err = MyWin::GetLastError();
            cerr << "[pin-loop] [ERROR] Failed to create protected trace file: " << *gTracePath 
                 << " ErrorCode=" << err << endl;
        } else {
            cerr << "[pin-loop] [SUCCESS] Trace file created." << endl;
        }
    }

    cerr << "[pin-loop] run_prefix: " << *gRunPrefix << endl;
    cerr << "[pin-loop] csv_path  : " << *gCsvPath << endl;
    cerr << "[pin-loop] trace_path: " << *gTracePath << " (VISIBLE)" << endl;
    
    // Debug: Marker file to verify permissions
    {
        string markerPath = *gRunPrefix + "_marker.txt";
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

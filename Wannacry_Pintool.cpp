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

#include "pin.H"

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

#if !defined(TARGET_IA32)
#  error "This pintool is intended for IA-32 (32-bit) target only."
#endif

// -------------------- Knobs --------------------
KNOB<BOOL>   KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "1",
    "메인 실행파일만 계측 (1이면 main exe만, 0이면 전체)");

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

struct StaticMeta {
    ADDRINT addr;       // full
    UINT32  addr32;
    string  addrStr;
    string  assembly;
    string  funcName;
    string  imgName;
    string  opcLower;
    OpClass opClass;
    bool    isStackMem;
};

static map<ADDRINT, StaticMeta*> gMeta;
static PIN_LOCK gMetaLock;

// -------------------- Loop Key / Stats --------------------
struct LoopKey {
    UINT32 header;   // target of back-edge
    UINT32 backedge; // branch ip

    bool operator<(const LoopKey& o) const {
        if (header != o.header) return header < o.header;
        return backedge < o.backedge;
    }
};

struct LoopAgg {
    UINT64 iters;
    bool   captured;

    // captured body stats (1-iteration snapshot)
    UINT64 body_len;
    UINT64 memR, memW, stackR, stackW;
    UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;

    string func;
    string img;
    string tracePath;

    LoopAgg() : iters(0), captured(false),
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

    FILE* fp;
    string  tracePath;

    string func;
    string img;

    UINT64 body_len;
    UINT64 memR, memW, stackR, stackW;
    UINT64 xorCnt, addsubCnt, shlshrCnt, mulCnt;

    bool   candValid;
    LoopKey candKey;
    UINT64  candIters;

    CaptureState() :
        armed(false), recording(false),
        rank_thread(0),
        capIns(0), capMaxIns(0),
        fp(NULL),
        body_len(0), memR(0), memW(0), stackR(0), stackW(0),
        xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0),
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

    TData() : os_tid(0), capturedCount(0) {}
};

static TLS_KEY gTlsKey;

// -------------------- Output files --------------------
static string gRunPrefix; // prefix + "_P<pid>"
static string gCsvPath;
static FILE* gCsvFp = NULL;
static PIN_LOCK gCsvLock;
static UINT32 gRankGlobal = 0;

static string gImgLogPath;
static FILE* gImgFp = NULL;
static PIN_LOCK gImgLock;
static set<string> gCryptoExecLogged; // basename lower

// 큰 버퍼(오버헤드 감소)
static char* gCsvBuf = NULL;
static char* gImgBuf = NULL;

// -------------------- Saved Pin cmdline for child --------------------
static INT gSavedArgc = 0;
static const CHAR** gSavedArgv = NULL;

// -------------------- IMG log --------------------
static void EnsureImgLogOpened()
{
    if (!KnobLogImages.Value()) return;
    if (gImgFp) return;

    gImgFp = std::fopen(gImgLogPath.c_str(), "wb");
    if (!gImgFp) return;

    // 1MB 버퍼
    gImgBuf = (char*)malloc(1 << 20);
    if (gImgBuf) setvbuf(gImgFp, gImgBuf, _IOFBF, (1 << 20));

    std::fprintf(gImgFp, "# img log (load + first exec reach)\n");
}

static void ImgLogLine_NoFlush(const string& line)
{
    if (!KnobLogImages.Value()) return;

    PIN_GetLock(&gImgLock, 1);
    EnsureImgLogOpened();
    if (gImgFp) {
        std::fputs(line.c_str(), gImgFp);
        std::fputc('\n', gImgFp);
        // fflush 제거(종료 시 OnFini에서 flush)
    }
    PIN_ReleaseLock(&gImgLock);
}

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
    UINT32 rank_thread,
    UINT32 start_addr,
    UINT32 end_addr,
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

    UINT32 rank_global = ++gRankGlobal;

    std::fprintf(gCsvFp, "%u,%u,%u,", tid, rank_global, rank_thread);
    std::fprintf(gCsvFp, "%x,%x,", start_addr, end_addr);
    std::fprintf(gCsvFp, "%llu,%llu,%.0f,", (unsigned long long)body_len,
        (unsigned long long)iterCount, score);

    CsvWriteEscaped(gCsvFp, func); std::fputc(',', gCsvFp);
    CsvWriteEscaped(gCsvFp, img);  std::fputc(',', gCsvFp);

    std::fprintf(gCsvFp, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
        (unsigned long long)memR, (unsigned long long)memW,
        (unsigned long long)stackR, (unsigned long long)stackW,
        (unsigned long long)xorCnt, (unsigned long long)addsubCnt,
        (unsigned long long)shlshrCnt, (unsigned long long)mulCnt);

    // fflush 제거(종료 시 flush)
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
    m->addr = a;
    m->addr32 = (UINT32)a;
    m->addrStr = Hex8((UINT32)a);
    m->assembly = INS_Disassemble(ins);

    // opcode lower
    {
        std::istringstream iss(m->assembly);
        string opc;
        iss >> opc;
        m->opcLower = ToLowerStr(opc);
    }

    // opClass
    m->opClass = OP_NONE;
    if (m->opcLower == "xor" || m->opcLower == "pxor" || m->opcLower == "vpxor") m->opClass = OP_XOR;
    else if (m->opcLower == "add" || m->opcLower == "sub" || m->opcLower == "adc" || m->opcLower == "sbb" ||
        m->opcLower == "inc" || m->opcLower == "dec") m->opClass = OP_ADDSUB;
    else if (m->opcLower == "shl" || m->opcLower == "sal" || m->opcLower == "shr" || m->opcLower == "sar" ||
        m->opcLower == "rol" || m->opcLower == "ror") m->opClass = OP_SHLSHR;
    else if (m->opcLower == "mul" || m->opcLower == "imul" || m->opcLower == "fmul") m->opClass = OP_MUL;

    // func/img
    m->imgName = traceImgName;
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
            IMG imgForFunc = SEC_Img(sec);
            if (IMG_Valid(imgForFunc)) m->imgName = IMG_Name(imgForFunc);
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
                oss << "0x" << std::hex << a;
                funcName = oss.str();
            }
        }
        m->funcName = funcName;
    }

    // stack mem?
    m->isStackMem = false;
    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
        REG base = INS_MemoryBaseReg(ins);
        REG idx = INS_MemoryIndexReg(ins);
        if (base == REG_ESP || base == REG_EBP || idx == REG_ESP || idx == REG_EBP)
            m->isStackMem = true;
    }

    PIN_GetLock(&gMetaLock, 1);
    gMeta.insert(std::make_pair(a, m));
    PIN_ReleaseLock(&gMetaLock);

    return m;
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
    c.tracePath.clear();
    c.fp = NULL;
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

    c.recording = false;

    if (c.fp) {
        std::fflush(c.fp);
        std::fclose(c.fp);
        c.fp = NULL;
    }

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
        agg.tracePath = c.tracePath;

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

    ResetCaptureStats(c);
    c.capMaxIns = (UINT64)KnobCapMaxIns.Value();
    c.recording = true;

    c.func = headerMeta ? headerMeta->funcName : "";
    c.img = headerMeta ? headerMeta->imgName : "";

    {
        std::ostringstream oss;
        oss << gRunPrefix << "_T" << std::dec << td->os_tid
            << "_L" << std::dec << c.rank_thread << ".txt";
        c.tracePath = oss.str();
    }

    c.fp = std::fopen(c.tracePath.c_str(), "wb");
    if (!c.fp) {
        cerr << "[pin-loop] cannot open trace file: " << c.tracePath << endl;
        c.recording = false;
        c.armed = false;
        return;
    }

    // trace 파일도 버퍼링(성능)
    {
        char* buf = (char*)malloc(1 << 20);
        if (buf) setvbuf(c.fp, buf, _IOFBF, (1 << 20));
        // buf는 종료 시 OS가 회수(파일 close 시에도 free는 안 하지만, 캡처 횟수 적어서 OK)
    }

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
    if (!c.recording || !c.fp) return;

    std::fprintf(c.fp, "%s;", sm->addrStr.c_str());
    std::fputs(sm->funcName.c_str(), c.fp); std::fputc(';', c.fp);
    std::fputs(sm->assembly.c_str(), c.fp); std::fputc(';', c.fp);
    std::fprintf(c.fp, "%x,%x,%x,%x,%x,%x,%x,%x,%x,\n",
        eax, ebx, ecx, edx, esi, edi, esp, ebp, 0u);

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
    if (!c.recording || !c.fp) return;

    std::fprintf(c.fp, "%s;", sm->addrStr.c_str());
    std::fputs(sm->funcName.c_str(), c.fp); std::fputc(';', c.fp);
    std::fputs(sm->assembly.c_str(), c.fp); std::fputc(';', c.fp);
    std::fprintf(c.fp, "%x,%x,%x,%x,%x,%x,%x,%x,%x,\n",
        eax, ebx, ecx, edx, esi, edi, esp, ebp, (UINT32)ea);

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
    if (!c.recording || !c.fp) return;

    std::fprintf(c.fp, "%s;", sm->addrStr.c_str());
    std::fputs(sm->funcName.c_str(), c.fp); std::fputc(';', c.fp);
    std::fputs(sm->assembly.c_str(), c.fp); std::fputc(';', c.fp);
    std::fprintf(c.fp, "%x,%x,%x,%x,%x,%x,%x,%x,%x,\n",
        eax, ebx, ecx, edx, esi, edi, esp, ebp, (UINT32)ea);

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

    // 너무 먼 backward branch는 루프 후보에서 제외 (잡음 감소)
    if ((UINT32)(ip - target) > 0x200000) return;

    LoopKey key; key.header = header; key.backedge = backedge;

    LoopAgg& agg = td->loops[key];
    agg.iters++;

    // 캡처 중인 루프의 back-edge라면 iteration 종료 지점
    if (td->cap.recording && td->cap.key.header == header && td->cap.key.backedge == backedge) {
        StopAndCommitCapture(td, "iteration_end");
        ArmBestCandidateIfIdle(td);
        return;
    }

    // hot 후보 유지(최대 iters 후보 1개만)
    if (!agg.captured && agg.iters >= (UINT64)KnobHotIters.Value()) {
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

    // TRACE 단위 필터(IMG 판정 1회)
    if (KnobCryptoOnly.Value()) {
        if (!imgValid) return;
        string baseLower = BaseNameLower(imgName);
        if (!IsCryptoBaseLower(baseLower)) return;
    }
    else {
        if (KnobOnlyMain.Value()) {
            if (!imgValid || !IMG_IsMainExecutable(img)) return;
        }
    }

    // crypto exec reach(최초 1회/각 DLL)
    if (imgValid) {
        string baseLower = BaseNameLower(imgName);
        if (IsCryptoBaseLower(baseLower)) {
            bool first = false;

            PIN_GetLock(&gImgLock, 1);
            if (gCryptoExecLogged.find(baseLower) == gCryptoExecLogged.end()) {
                gCryptoExecLogged.insert(baseLower);
                first = true;
            }
            PIN_ReleaseLock(&gImgLock);

            if (first) {
                std::ostringstream oss;
                oss << "EXEC " << imgName << "  CRYPTO_EXEC";
                ImgLogLine_NoFlush(oss.str());
                if (KnobVerbose.Value()) {
                    cerr << "[pin-loop] CRYPTO_EXEC(reached): " << imgName << endl;
                }
            }
        }
    }

    // BBL/INS 계측
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

            StaticMeta* sm = GetOrCreateMeta(ins, INS_Address(ins), imgName, imgLow);

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

    ImgLogLine_NoFlush(oss.str());
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
}

static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*)
{
    TData* td = (TData*)PIN_GetThreadData(gTlsKey, tid);
    if (!td) return;

    if (td->cap.recording) {
        StopAndCommitCapture(td, "thread_fini");
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

    if (gSavedArgc > 0 && gSavedArgv) {
        CHILD_PROCESS_SetPinCommandLine(cProcess, gSavedArgc, gSavedArgv);
    }
    if (KnobVerbose.Value()) {
        cerr << "[pin-loop] following child PID=" << (unsigned long)CHILD_PROCESS_GetId(cProcess) << endl;
    }
    return TRUE;
}

// -------------------- Fini --------------------
static VOID OnFini(INT32, VOID*)
{
    cerr << "[pin-loop] process fini\n";

    if (gCsvFp) {
        std::fflush(gCsvFp);
        std::fclose(gCsvFp);
        gCsvFp = NULL;
    }

    if (gImgFp) {
        std::fflush(gImgFp);
        std::fclose(gImgFp);
        gImgFp = NULL;
    }

    if (gCsvBuf) { free(gCsvBuf); gCsvBuf = NULL; }
    if (gImgBuf) { free(gImgBuf); gImgBuf = NULL; }

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
    PIN_InitLock(&gImgLock);

    InitCryptoDllList();

    // run prefix: prefix + _P<pid>
    UINT32 pid = (UINT32)PIN_GetPid();
    {
        std::ostringstream oss;
        oss << KnobPrefix.Value() << "_P" << std::dec << pid;
        gRunPrefix = oss.str();
    }
    gCsvPath = gRunPrefix + "_loops.csv";
    gImgLogPath = gRunPrefix + "_images.txt";

    cerr << "[pin-loop] run_prefix: " << gRunPrefix << endl;
    cerr << "[pin-loop] csv_path  : " << gCsvPath << endl;
    cerr << "[pin-loop] img_path  : " << gImgLogPath << endl;
    cerr << "[pin-loop] only_main=" << (KnobOnlyMain.Value() ? "1" : "0")
        << " follow_child=" << (KnobFollowChild.Value() ? "1" : "0")
        << " hot_iters=" << KnobHotIters.Value()
        << " cap_max_ins=" << KnobCapMaxIns.Value()
        << " top=" << KnobTop.Value()
        << " log_images=" << (KnobLogImages.Value() ? "1" : "0")
        << " crypto_only=" << (KnobCryptoOnly.Value() ? "1" : "0")
        << endl;

    PIN_AddFollowChildProcessFunction(FollowChild, 0);
    IMG_AddInstrumentFunction(OnImgLoad, 0);

    // 핵심: TRACE 단위 계측
    TRACE_AddInstrumentFunction(OnTrace, 0);

    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_AddThreadFiniFunction(OnThreadFini, 0);
    PIN_AddFiniFunction(OnFini, 0);

    PIN_StartProgram();
    return 0;
}

// === MyPinTool.cpp (Pin 3.31 / IA-32 / VS2022) ===
// - per-thread IP trace -> prefix_<OS_TID>.bin


#ifdef _MSC_VER
// pinsync.hpp에서 뜨는 C5208 경고 무시
#pragma warning(disable:5208)
// fopen 등 CRT 보안 경고 무시가 필요하면 해제: #pragma warning(disable:4996)
#endif

#include "pin.H"
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>

// ===== Knobs =====
// cpu: 실행 Affinity 안내(실제 설정은 런처/배치에서 수행 권장)
// only_main: 메인 이미지 주소 범위만 로깅할지
// flush_every: N개의 레코드마다 강제 flush
// prefix: 출력 파일 접두사(절대 경로 포함 가능) -> prefix_<OS_TID>.bin
// bufcap: 스레드별 버퍼(capacity, #records)
KNOB<int>          KnobCpu(KNOB_MODE_WRITEONCE, "pintool", "cpu", "0", "CPU index (런처에서 /affinity로 고정 권장)");
KNOB<bool>         KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "1", "메인 실행파일만 로깅");
KNOB<unsigned>     KnobFlushEvery(KNOB_MODE_WRITEONCE, "pintool", "flush_every", "65536", "N개 기록 시 강제 flush");
KNOB<std::string>  KnobPrefix(KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace", "출력 파일 접두사");
KNOB<unsigned>     KnobBufCap(KNOB_MODE_WRITEONCE, "pintool", "bufcap", "1048576", "스레드별 버퍼(capacity, #records)");

// ===== IA-32 전용 보호 =====
#if !defined(TARGET_IA32)
#  error "This pintool is intended for IA-32 (32-bit) target only."
#endif

// ===== TLS =====
struct TData {
    std::ofstream out;
    std::vector<uint32_t> buf;
    uint32_t sinceFlush = 0;
    uint32_t os_tid = 0;     // Windows OS Thread ID (DWORD)
    uint64_t totalRecs = 0;     // 총 기록 개수(디버그용)
};

static TLS_KEY gTlsKey;
static IMG     gMainImg = IMG_Invalid();
static ADDRINT gMainLow = 0;
static ADDRINT gMainHigh = 0;

// ===== Utils =====
static std::string MakeThreadFileName(uint32_t os_tid, const std::string& prefix) {
    // prefix가 경로/파일접두사 모두 가능: C:\trace\trace  -> C:\trace\trace_<tid>.bin
    return prefix + "_" + std::to_string(static_cast<unsigned long long>(os_tid)) + ".bin";
}

static inline bool InMainRange(ADDRINT ip) {
    return (gMainLow && gMainHigh && ip >= gMainLow && ip < gMainHigh);
}

// ===== Image load: 메인 exe 범위 확인 =====
static VOID OnImgLoad(IMG img, VOID*) {
    if (IMG_IsMainExecutable(img)) {
        gMainImg = img;
        gMainLow = IMG_LowAddress(img);
        gMainHigh = IMG_HighAddress(img);
        std::cerr << "[instrace_tid] main img: " << IMG_Name(img)
            << " [" << std::hex << gMainLow << "," << gMainHigh << ")\n" << std::dec;
    }
}

// ===== Flush =====
static VOID FlushBuf(TData* td) {
    if (!td || !td->out.is_open()) return;
    if (!td->buf.empty()) {
        // vector::data() 대신 &buf[0] (빈 경우 접근 금지 → 위에서 empty 체크)
        const char* p = reinterpret_cast<const char*>(&td->buf[0]);
        std::streamsize nbytes = static_cast<std::streamsize>(td->buf.size() * sizeof(uint32_t));
        td->out.write(p, nbytes);
        td->totalRecs += td->buf.size();
        td->buf.clear();
    }
    td->sinceFlush = 0;
}

// ===== Record one IP =====
static VOID RecordIP(ADDRINT ip, THREADID tid) {
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td || !td->out.is_open()) return;

    // IA-32 가정: ADDRINT -> uint32_t
    uint32_t a = static_cast<uint32_t>(ip);

    // emplace_back 대신 push_back
    td->buf.push_back(a);
    td->sinceFlush++;

    // 용량 임계 또는 flush_every 도달 시 플러시
    if (td->buf.size() >= td->buf.capacity() || td->sinceFlush >= KnobFlushEvery.Value()) {
        FlushBuf(td);
    }
}

// ===== Instrument =====
static VOID OnIns(INS ins, VOID*) {
    if (KnobOnlyMain.Value()) {
        if (!InMainRange(INS_Address(ins))) return;
    }

    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)RecordIP,
        IARG_INST_PTR, IARG_THREAD_ID,
        IARG_END
    );
}

// ===== Thread start/finish =====
static VOID OnThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    TData* td = new TData();
    td->os_tid = static_cast<uint32_t>(PIN_GetTid());
    td->buf.reserve(KnobBufCap.Value());

    const std::string fname = MakeThreadFileName(td->os_tid, KnobPrefix.Value());
    // ofstream.open(string) 대신 .c_str() (구버전 호환/일부 환경 매크로 충돌 회피)
    td->out.open(fname.c_str(), std::ios::binary | std::ios::out);
    if (!td->out.is_open()) {
        std::cerr << "[instrace_tid] open failed: " << fname << "\n";
    }
    else {
        std::cerr << "[instrace_tid] start TID=" << td->os_tid
            << " -> " << fname << "\n";
    }

    PIN_SetThreadData(gTlsKey, td, tid);
}

static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (td) {
        FlushBuf(td);
        if (td->out.is_open()) td->out.close();
        std::cerr << "[instrace_tid] fini  TID=" << td->os_tid
            << " total_recs=" << td->totalRecs << "\n";
        delete td;
        PIN_SetThreadData(gTlsKey, 0, tid);
    }
}

// ===== Fini (프로세스 종료) =====
static VOID OnFini(INT32, VOID*) {
    std::cerr << "[instrace_tid] process fini\n";
}

// ===== Main =====
static INT32 Usage() {
    std::cerr
        << "instrace_tid: per-thread(IP) tracer for Windows, IA-32\n"
        << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    gTlsKey = PIN_CreateThreadDataKey(0);

    IMG_AddInstrumentFunction(OnImgLoad, 0);
    INS_AddInstrumentFunction(OnIns, 0);
    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_AddThreadFiniFunction(OnThreadFini, 0);
    PIN_AddFiniFunction(OnFini, 0);

    std::cerr << "[instrace_tid] cpu=" << KnobCpu.Value()
        << " only_main=" << (KnobOnlyMain.Value() ? "1" : "0")
        << " prefix=" << KnobPrefix.Value()
        << " bufcap=" << KnobBufCap.Value()
        << " flush_every=" << KnobFlushEvery.Value()
        << std::endl;

    PIN_StartProgram(); // never returns
    return 0;
}

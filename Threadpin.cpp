#ifdef _MSC_VER
#pragma warning(disable:5208)
#endif
#include "pin.H"
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>

// ===== Knobs =====
KNOB<int>          KnobCpu(KNOB_MODE_WRITEONCE, "pintool", "cpu", "0", "CPU index (런처에서 /affinity로 고정 권장)");
KNOB<bool>         KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "1", "메인 실행파일만 로깅");
KNOB<unsigned>     KnobFlushEvery(KNOB_MODE_WRITEONCE, "pintool", "flush_every", "65536", "N개 기록 시 강제 flush");
KNOB<std::string>  KnobPrefix(KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace", "출력 파일 접두사");
KNOB<unsigned>     KnobBufCap(KNOB_MODE_WRITEONCE, "pintool", "bufcap", "1048576", "스레드별 버퍼(capacity, #records)");

// ===== TLS =====
struct TData {
    std::ofstream out;
    std::vector<uint32_t> buf;
    uint32_t sinceFlush = 0;
    uint32_t os_tid = 0;
};

static TLS_KEY gTlsKey;
static IMG     gMainImg = IMG_Invalid();
static ADDRINT gMainLow = 0;
static ADDRINT gMainHigh = 0;

static std::string MakeThreadFileName(uint32_t os_tid, const std::string& prefix) {
    return prefix + "_" + std::to_string(static_cast<unsigned long long>(os_tid)) + ".bin";
}
static inline bool InMainRange(ADDRINT ip) {
    return (gMainLow && gMainHigh && ip >= gMainLow && ip < gMainHigh);
}

// ===== Image load =====
static VOID OnImgLoad(IMG img, VOID*) {
    if (IMG_IsMainExecutable(img)) {
        gMainImg = img;
        gMainLow = IMG_LowAddress(img);
        gMainHigh = IMG_HighAddress(img);
    }
}

// ===== Flush =====
static VOID FlushBuf(TData* td) {
    if (!td || !td->out.is_open()) return;
    if (!td->buf.empty()) {
        // (1) data() 대신 &buf[0] 사용
        const char* p = reinterpret_cast<const char*>(&td->buf[0]);
        td->out.write(p, static_cast<std::streamsize>(td->buf.size() * sizeof(uint32_t)));
        td->buf.clear();
    }
    td->sinceFlush = 0;
}

// ===== Record one IP =====
static VOID RecordIP(ADDRINT ip, THREADID tid) {
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td || !td->out.is_open()) return;

    uint32_t a = static_cast<uint32_t>(ip); // IA-32 전제
    // (2) emplace_back 대신 push_back
    td->buf.push_back(a);
    td->sinceFlush++;

    if (td->buf.size() >= td->buf.capacity() || td->sinceFlush >= KnobFlushEvery.Value()) {
        FlushBuf(td);
    }
}

// ===== Instrument =====
static VOID OnIns(INS ins, VOID*) {
    if (KnobOnlyMain.Value()) {
        if (!InMainRange(INS_Address(ins))) return;
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordIP,
        IARG_INST_PTR, IARG_THREAD_ID, IARG_END);
}

// ===== Thread start/finish =====
static VOID OnThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    TData* td = new TData();
    td->os_tid = static_cast<uint32_t>(PIN_GetTid());
    td->buf.reserve(KnobBufCap.Value());

    std::string fname = MakeThreadFileName(td->os_tid, KnobPrefix.Value());
    // (3) ofstream.open(string) → .c_str()
    td->out.open(fname.c_str(), std::ios::binary | std::ios::out);
    if (!td->out.is_open()) {
        std::cerr << "[instrace_tid] open failed: " << fname << "\n";
    }
    PIN_SetThreadData(gTlsKey, td, tid);
}
static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*) {
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (td) {
        FlushBuf(td);
        if (td->out.is_open()) td->out.close();
        delete td;
        PIN_SetThreadData(gTlsKey, 0, tid);
    }
}
static VOID OnFini(INT32, VOID*) {}

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

    PIN_StartProgram();
    return 0;
}

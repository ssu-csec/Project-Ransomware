// === MyPinTool.cpp ===
// Pin 3.31 / Windows / IA-32 / MSVC
// - main executable만 계측(only_main=1)
// - per-thread 동적 trace에서 루프 자동 탐지
// - 상위 N개 루프(body 구조 기준)만 파일로 덤프
// - 덤프 포맷:
//     addr;func;assembly;eax,ebx,ecx,edx,esi,edi,esp,ebp,memaddr,
//
//   예:
//     0040ba0e;gencryptrandom;mov dword ptr [esp-0x1c], 0x412600;
//       eb33f7c9,eb21968e,ea79d29d,ff45dae5,757f0000,00000038,019f49c,019f4b0,019f480,

#ifdef _MSC_VER
#  pragma warning(disable:5208)   // pinsync.hpp 경고 억제
#endif

#include "pin.H"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <iomanip>
#include <iterator>
#include <cstdint>
#include <algorithm>
#include <cstdlib>

using namespace std;

// ===== IA-32 전용 =====
#if !defined(TARGET_IA32)
#  error "This pintool is intended for IA-32 (32-bit) target only."
#endif

// ===== Knobs =====
KNOB<BOOL>    KnobOnlyMain(KNOB_MODE_WRITEONCE, "pintool", "only_main", "1",
    "메인 실행파일만 로깅");
KNOB<UINT32>  KnobMaxInsts(KNOB_MODE_WRITEONCE, "pintool", "max_insts", "200000",
    "스레드당 저장할 최대 인스트럭션 수");
KNOB<UINT32>  KnobTop(KNOB_MODE_WRITEONCE, "pintool", "top", "10",
    "루프 상위 N개만 덤프");
KNOB<string>  KnobPrefix(KNOB_MODE_WRITEONCE, "pintool", "prefix", "trace",
    "출력 파일 접두사");
KNOB<BOOL>    KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0",
    "상세 로그 출력");

// ===== 유틸 =====
static string Trim(const string& s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// ===== 정적 메타 정보 (IP별) =====
struct StaticMeta {
    ADDRINT          addrn;          // 정수 주소
    string           addrStr;        // "00401000"
    string           assembly;       // 전체 디스어셈
    string           opcstr;         // opcode 문자열
    vector<string>   oprs;           // operand 문자열들

    string           funcName;       // containing 함수 이름 (RTN 기준 / fallback 포함)
    string           imgName;        // 이 IP가 속한 이미지 이름 (모듈 경로)

    bool             isCall;         // call 인스트럭션인가?
    ADDRINT          callTargetAddr; // direct call 타깃 주소(있으면)
    string           callTargetFunc; // call 타깃 함수 이름
    string           callTargetImg;  // call 타깃 모듈 이름
};

// ===== 동적 인스트럭션 레코드 =====
struct Inst {
    int               id;        // trace 내에서의 순번
    string            addr;      // "00401000"
    unsigned int      addrn;     // 정수 주소
    string            assembly;  // 디스어셈
    string            opcstr;    // opcode 문자열
    int               opc;       // 정수 opcode (preprocess 후)
    vector<string>    oprs;      // operand 문자열들
    int               oprnum;    // operand 개수
    UINT32            ctxreg[8]; // EAX,EBX,ECX,EDX,ESI,EDI,ESP,EBP
    UINT32            memaddr;   // 메모리 RW 주소(없으면 0)

    string            funcName;       // containing 함수 이름
    string            imgName;        // containing 모듈 이름

    bool              isCall;         // call 인가?
    string            callTargetFunc; // call 타깃 함수 이름
    string            callTargetImg;  // call 타깃 모듈 이름
};

// ===== 루프 분석용 구조체 =====
struct LoopBody {
    bool                    good;
    list<Inst>::iterator    begin;
    list<Inst>::iterator    end;
};

struct Loop {
    unsigned int       startaddr;
    list<LoopBody>     loopbody;   // 동적 루프 바닥 인스턴스들
    vector<LoopBody>   instance;   // 중복 제거된 루프 body 패턴
};

// jmp 계열 opcode 이름 목록
static const char* jmpInstrName[33] = {
    "jo","jno","js","jns","je","jz","jne","jnz","jb","jnae","jc","jnb","jae",
    "jnc","jbe","jna","ja","jnbe","jl","jnge","jge","jnl","jle","jng","jg",
    "jnle","jp","jpe","jnp","jpo","jcxz","jecxz","jmp"
};

// ===== TLS =====
struct TData {
    list<Inst>  insts;       // 이 스레드의 동적 trace
    UINT64      total_insts; // 전체 실행된 인스트럭션 수(저장 여부와 무관)
    UINT32      os_tid;      // OS TID
    BOOL        recording;   // 더 이상 저장 금지 여부
};

static TLS_KEY gTlsKey;

// 메인 이미지 주소 범위
static IMG     gMainImg = IMG_Invalid();
static ADDRINT gMainLow = 0;
static ADDRINT gMainHigh = 0;

// 정적 메타: IP → StaticMeta
static map<ADDRINT, StaticMeta> gMeta;

// ===== 헬퍼 =====
static inline bool InMainRange(ADDRINT ip)
{
    return (gMainLow && gMainHigh && ip >= gMainLow && ip < gMainHigh);
}

// ===== Image load 콜백 =====
static VOID OnImgLoad(IMG img, VOID*)
{
    if (IMG_IsMainExecutable(img)) {
        gMainImg = img;
        gMainLow = IMG_LowAddress(img);
        gMainHigh = IMG_HighAddress(img);

        cerr << "[pin-loop] main img: " << IMG_Name(img)
            << " [" << hex << gMainLow << "," << gMainHigh << ")\n" << dec;
    }
}

// ===== 동적 레코딩 공통 로직 =====
static bool ShouldRecord(TData* td)
{
    if (!td) return false;

    td->total_insts++;

    if (!td->recording) {
        return false;
    }

    if (td->insts.size() >= KnobMaxInsts.Value()) {
        td->recording = FALSE;
        cerr << "[pin-loop] TID=" << td->os_tid
            << " instlist reached max_insts=" << KnobMaxInsts.Value()
            << ", stop recording further instructions\n";
        return false;
    }
    return true;
}

static void FillRegs(UINT32 regs[8], const CONTEXT* ctx)
{
    regs[0] = (UINT32)PIN_GetContextReg(ctx, REG_EAX);
    regs[1] = (UINT32)PIN_GetContextReg(ctx, REG_EBX);
    regs[2] = (UINT32)PIN_GetContextReg(ctx, REG_ECX);
    regs[3] = (UINT32)PIN_GetContextReg(ctx, REG_EDX);
    regs[4] = (UINT32)PIN_GetContextReg(ctx, REG_ESI);
    regs[5] = (UINT32)PIN_GetContextReg(ctx, REG_EDI);
    regs[6] = (UINT32)PIN_GetContextReg(ctx, REG_ESP);
    regs[7] = (UINT32)PIN_GetContextReg(ctx, REG_EBP);
}

// ===== 동적 콜백 =====
static VOID RecordNoMem(THREADID tid, ADDRINT ip, const CONTEXT* ctx)
{
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td) return;
    if (!ShouldRecord(td)) return;

    map<ADDRINT, StaticMeta>::const_iterator it = gMeta.find(ip);
    if (it == gMeta.end()) return;
    const StaticMeta& sm = it->second;

    Inst insRec;
    insRec.id = (int)td->insts.size() + 1;
    insRec.addr = sm.addrStr;
    insRec.addrn = (unsigned int)sm.addrn;
    insRec.assembly = sm.assembly;
    insRec.opcstr = sm.opcstr;
    insRec.oprs = sm.oprs;
    insRec.oprnum = (int)sm.oprs.size();
    insRec.memaddr = 0;

    insRec.funcName = sm.funcName;
    insRec.imgName = sm.imgName;
    insRec.isCall = sm.isCall;
    insRec.callTargetFunc = sm.callTargetFunc;
    insRec.callTargetImg = sm.callTargetImg;

    FillRegs(insRec.ctxreg, ctx);
    insRec.opc = 0; // preprocess에서 채움

    td->insts.push_back(insRec);
}

static VOID RecordMemR(THREADID tid, ADDRINT ip, const CONTEXT* ctx, ADDRINT ea)
{
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td) return;
    if (!ShouldRecord(td)) return;

    map<ADDRINT, StaticMeta>::const_iterator it = gMeta.find(ip);
    if (it == gMeta.end()) return;
    const StaticMeta& sm = it->second;

    Inst insRec;
    insRec.id = (int)td->insts.size() + 1;
    insRec.addr = sm.addrStr;
    insRec.addrn = (unsigned int)sm.addrn;
    insRec.assembly = sm.assembly;
    insRec.opcstr = sm.opcstr;
    insRec.oprs = sm.oprs;
    insRec.oprnum = (int)sm.oprs.size();
    insRec.memaddr = (UINT32)ea;

    insRec.funcName = sm.funcName;
    insRec.imgName = sm.imgName;
    insRec.isCall = sm.isCall;
    insRec.callTargetFunc = sm.callTargetFunc;
    insRec.callTargetImg = sm.callTargetImg;

    FillRegs(insRec.ctxreg, ctx);
    insRec.opc = 0;

    td->insts.push_back(insRec);
}

static VOID RecordMemW(THREADID tid, ADDRINT ip, const CONTEXT* ctx, ADDRINT ea)
{
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td) return;
    if (!ShouldRecord(td)) return;

    map<ADDRINT, StaticMeta>::const_iterator it = gMeta.find(ip);
    if (it == gMeta.end()) return;
    const StaticMeta& sm = it->second;

    Inst insRec;
    insRec.id = (int)td->insts.size() + 1;
    insRec.addr = sm.addrStr;
    insRec.addrn = (unsigned int)sm.addrn;
    insRec.assembly = sm.assembly;
    insRec.opcstr = sm.opcstr;
    insRec.oprs = sm.oprs;
    insRec.oprnum = (int)sm.oprs.size();
    insRec.memaddr = (UINT32)ea;

    insRec.funcName = sm.funcName;
    insRec.imgName = sm.imgName;
    insRec.isCall = sm.isCall;
    insRec.callTargetFunc = sm.callTargetFunc;
    insRec.callTargetImg = sm.callTargetImg;

    FillRegs(insRec.ctxreg, ctx);
    insRec.opc = 0;

    td->insts.push_back(insRec);
}

// ===== 정적 메타 구성 + 인스트루먼트 =====
static VOID OnIns(INS ins, VOID*)
{
    ADDRINT a = INS_Address(ins);

    if (KnobOnlyMain.Value() && !InMainRange(a)) {
        return;
    }

    // 정적 메타: 처음 보는 주소만 한 번 파싱
    if (gMeta.find(a) == gMeta.end()) {
        StaticMeta m;
        m.addrn = a;

        // 주소 문자열
        {
            ostringstream addrss;
            addrss << hex << setw(8) << setfill('0') << (unsigned int)a;
            m.addrStr = addrss.str();
        }

        m.assembly = INS_Disassemble(ins);

        // opcode + operand 파싱
        {
            istringstream disasbuf(m.assembly);
            getline(disasbuf, m.opcstr, ' ');

            string temp;
            while (getline(disasbuf, temp, ',')) {
                temp = Trim(temp);
                if (!temp.empty())
                    m.oprs.push_back(temp);
            }
        }

        // ===== containing 함수 이름 해석 =====
        string funcName;
        RTN rtn = INS_Rtn(ins);
        if (!RTN_Valid(rtn)) {
            // 간혹 INS_Rtn이 invalid인 경우가 있어서 주소로 다시 찾기
            rtn = RTN_FindByAddress(a);
        }

        IMG imgForFunc = IMG_Invalid();
        if (RTN_Valid(rtn)) {
            string rawName = RTN_Name(rtn);
            string undec = PIN_UndecorateSymbolName(rawName, UNDECORATION_NAME_ONLY);
            if (!undec.empty())
                funcName = undec;
            else
                funcName = rawName;

            SEC sec = RTN_Sec(rtn);
            imgForFunc = SEC_Img(sec);
        }
        else {
            imgForFunc = IMG_FindByAddress(a);
            if (IMG_Valid(imgForFunc)) {
                ostringstream oss;
                oss << IMG_Name(imgForFunc) << "+0x"
                    << hex << (a - IMG_LowAddress(imgForFunc));
                funcName = oss.str();
            }
            else {
                ostringstream oss;
                oss << "0x" << hex << a;
                funcName = oss.str();
            }
        }

        m.funcName = funcName;

        // 이미지 이름 (모듈 경로)
        if (IMG_Valid(imgForFunc)) {
            m.imgName = IMG_Name(imgForFunc);
        }
        else {
            IMG img = IMG_FindByAddress(a);
            if (IMG_Valid(img))
                m.imgName = IMG_Name(img);
            else
                m.imgName = "";
        }

        // ===== call 여부 및 call 타깃 정보 =====
        m.isCall = INS_IsCall(ins);
        m.callTargetAddr = 0;
        m.callTargetFunc.clear();
        m.callTargetImg.clear();

        if (m.isCall && INS_IsDirectControlFlow(ins)) {
            ADDRINT tgt = INS_DirectBranchOrCallTargetAddress(ins);
            m.callTargetAddr = tgt;

            RTN crtn = RTN_FindByAddress(tgt);
            if (RTN_Valid(crtn)) {
                string raw = RTN_Name(crtn);
                string undec = PIN_UndecorateSymbolName(raw, UNDECORATION_NAME_ONLY);
                m.callTargetFunc = undec.empty() ? raw : undec;

                SEC csec = RTN_Sec(crtn);
                IMG cimg = SEC_Img(csec);
                if (IMG_Valid(cimg))
                    m.callTargetImg = IMG_Name(cimg);
            }
            else {
                IMG cimg = IMG_FindByAddress(tgt);
                if (IMG_Valid(cimg)) {
                    ostringstream oss;
                    oss << IMG_Name(cimg) << "+0x"
                        << hex << (tgt - IMG_LowAddress(cimg));
                    m.callTargetFunc = oss.str();
                    m.callTargetImg = IMG_Name(cimg);
                }
            }
        }

        gMeta.insert(make_pair(a, m));
    }

    // 동적 콜백 삽입
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemW,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_CONST_CONTEXT,
            IARG_MEMORYWRITE_EA,
            IARG_END);
    }
    else if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemR,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_CONST_CONTEXT,
            IARG_MEMORYREAD_EA,
            IARG_END);
    }
    else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordNoMem,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_CONST_CONTEXT,
            IARG_END);
    }
}

// ===== 루프 분석 유틸 =====
static int getOpc(const string& s, map<string, int>& m)
{
    map<string, int>::iterator it = m.find(s);
    if (it != m.end())
        return it->second;
    return 0;
}

static void Preprocess(list<Inst>& L,
    map<string, int>& instenum,
    set<int>& jmpset)
{
    // opcode 문자열 → 정수 id
    for (list<Inst>::iterator it = L.begin(); it != L.end(); ++it) {
        if (instenum.find(it->opcstr) == instenum.end()) {
            int id = (int)instenum.size() + 1;
            instenum.insert(make_pair(it->opcstr, id));
        }
    }

    // Inst.opc 채우기
    for (list<Inst>::iterator it = L.begin(); it != L.end(); ++it) {
        it->opc = getOpc(it->opcstr, instenum);
    }

    // 점프 opcode 집합
    for (int i = 0; i < 33; ++i) {
        string s = jmpInstrName[i];
        int n = getOpc(s, instenum);
        if (n != 0)
            jmpset.insert(n);
    }
}

static bool isjump(int opc, const set<int>& jumpset)
{
    return jumpset.find(opc) != jumpset.end();
}

static bool isLoopBodyEq(const LoopBody& lp1, const LoopBody& lp2)
{
    list<Inst>::iterator it1 = lp1.begin;
    list<Inst>::iterator end1 = lp1.end;
    list<Inst>::iterator it2 = lp2.begin;
    list<Inst>::iterator end2 = lp2.end;

    for (;;) {
        if (it1->opc != it2->opc)
            return false;

        if (it1 == end1 || it2 == end2)
            break;

        ++it1;
        ++it2;
    }

    // 마지막 인스트럭션까지 동일해야 함
    return (it1->opc == it2->opc && it1 == end1 && it2 == end2);
}

// ===== 루프 분석 & 파일 출력 =====
static VOID AnalyzeLoops(list<Inst>& L,
    UINT32 os_tid,
    const string& prefix,
    UINT32 topN)
{
    map<string, int> instenum;
    set<int>        jmpset;

    Preprocess(L, instenum, jmpset);

    int nloop = 0;
    list<Loop> loops;

    // 1) 루프 바닥(뒤로 점프) 탐지
    for (list<Inst>::iterator it = L.begin(); it != L.end(); ++it) {
        if (!isjump(it->opc, jmpset))
            continue;

        if (it->oprs.empty())
            continue;

        string op0 = Trim(it->oprs[0]);
        if (op0.empty())
            continue;

        // 16진 immediate 주소로 가정 (뒤에 'h' 있을 수 있음)
        if (op0[op0.size() - 1] == 'h' || op0[op0.size() - 1] == 'H')
            op0 = op0.substr(0, op0.size() - 1);

        unsigned int targetaddr = (unsigned int)strtoul(op0.c_str(), 0, 16);

        list<Inst>::iterator ni = it;
        ++ni;
        if (ni == L.end())
            continue;

        if (targetaddr < it->addrn && it->addrn - targetaddr < 0xffff && ni->addrn == targetaddr) {
            LoopBody bd;
            bd.good = false;
            bd.end = it;

            list<Loop>::iterator li;
            for (li = loops.begin(); li != loops.end(); ++li) {
                if (li->startaddr == targetaddr)
                    break;
            }

            if (li == loops.end()) {
                Loop lp;
                lp.startaddr = targetaddr;
                lp.loopbody.push_back(bd);
                loops.push_back(lp);
            }
            else {
                li->loopbody.push_back(bd);
            }
            ++nloop;
        }
    }

    if (loops.empty()) {
        cerr << "[pin-loop] TID=" << os_tid << " no loops detected\n";
        return;
    }

    // 2) 각 loop body의 begin 찾기 (startaddr까지 역방향 탐색)
    for (list<Loop>::iterator it = loops.begin(); it != loops.end(); ++it) {
        for (list<LoopBody>::iterator ii = it->loopbody.begin(); ii != it->loopbody.end(); ++ii) {
            int n = 0;
            list<Inst>::iterator i = ii->end;
            for (; n < 0xffff; ++n) {
                if (i->addrn == it->startaddr) {
                    ii->begin = i;
                    ii->good = true;
                    break;
                }
                if (i == L.begin())
                    break;
                --i;
            }
        }
    }

    // 3) bad body 제거 + body 없는 loop 제거
    for (list<Loop>::iterator it = loops.begin(); it != loops.end(); ) {
        for (list<LoopBody>::iterator ii = it->loopbody.begin(); ii != it->loopbody.end(); ) {
            if (!ii->good) {
                ii = it->loopbody.erase(ii);
            }
            else {
                ++ii;
            }
        }
        if (it->loopbody.empty()) {
            it = loops.erase(it);
        }
        else {
            ++it;
        }
    }

    if (loops.empty()) {
        cerr << "[pin-loop] TID=" << os_tid << " all loop bodies dropped\n";
        return;
    }

    // 4) body 구조로 중복 제거 → instance 벡터 구성
    for (list<Loop>::iterator it = loops.begin(); it != loops.end(); ++it) {
        if (it->loopbody.empty()) continue;

        it->instance.push_back(it->loopbody.front());

        for (list<LoopBody>::iterator ii = ++(it->loopbody.begin()); ii != it->loopbody.end(); ++ii) {
            bool found = false;
            for (size_t idx = 0; idx < it->instance.size(); ++idx) {
                if (isLoopBodyEq(it->instance[idx], *ii)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                it->instance.push_back(*ii);
            }
        }
    }

    // 5) 루프 후보 스코어링 (body 길이 * 반복 수)
    struct LoopCand {
        Loop* loop;
        LoopBody    body;
        size_t      index;
        int         bodyLen;
        size_t      iterCount;
        double      score;
    };

    vector<LoopCand> cands;

    for (list<Loop>::iterator it = loops.begin(); it != loops.end(); ++it) {
        if (it->instance.empty()) continue;

        for (size_t idx = 0; idx < it->instance.size(); ++idx) {
            LoopBody& b = it->instance[idx];

            // body 길이 계산 (begin ~ end 포함)
            int len = 0;
            list<Inst>::iterator p = b.begin;
            list<Inst>::iterator pe = b.end;
            for (;;) {
                ++len;
                if (p == pe) break;
                ++p;
            }

            size_t iterCount = it->loopbody.size();
            double score = (double)len * (double)iterCount;

            LoopCand cand;
            cand.loop = &(*it);
            cand.body = b;
            cand.index = idx;
            cand.bodyLen = len;
            cand.iterCount = iterCount;
            cand.score = score;
            cands.push_back(cand);
        }
    }

    if (cands.empty()) {
        cerr << "[pin-loop] TID=" << os_tid << " no loop candidates after analysis\n";
        return;
    }

    sort(cands.begin(), cands.end(),
        [](const LoopCand& a, const LoopCand& b) {
            return a.score > b.score;
        });

    if (topN == 0 || topN > cands.size())
        topN = (UINT32)cands.size();

    cerr << "[pin-loop] TID=" << os_tid
        << " num_loops=" << loops.size()
        << " candidates=" << cands.size()
        << " dumping_top=" << topN << endl;

    // 6) 상위 topN 루프를 파일로 덤프
    for (UINT32 rank = 0; rank < topN; ++rank) {
        const LoopCand& c = cands[rank];

        ostringstream fn;
        fn << prefix << "_T" << dec << os_tid << "_L" << (rank + 1) << ".txt";

        ofstream fp(fn.str().c_str(), ios::out | ios::binary);
        if (!fp.is_open()) {
            cerr << "[pin-loop] cannot open " << fn.str() << " for write\n";
            continue;
        }

        list<Inst>::iterator p = c.body.begin;
        list<Inst>::iterator pe = c.body.end;

        for (;;) {
            fp << p->addr << ';'
                << p->funcName << ';'
                << p->assembly << ';';

            for (int j = 0; j < 8; ++j) {
                fp << hex << p->ctxreg[j] << ',';
            }
            fp << hex << p->memaddr << ",\n";

            if (p == pe) break;
            ++p;
        }

        fp.close();
    }
}

// ===== Thread start / finish =====
static VOID OnThreadStart(THREADID tid, CONTEXT*, INT32, VOID*)
{
    TData* td = new TData();
    td->os_tid = (UINT32)PIN_GetTid();
    td->total_insts = 0;
    td->recording = TRUE;

    PIN_SetThreadData(gTlsKey, td, tid);

    cerr << "[pin-loop] start TID=" << td->os_tid << endl;
}

static VOID OnThreadFini(THREADID tid, const CONTEXT*, INT32, VOID*)
{
    TData* td = static_cast<TData*>(PIN_GetThreadData(gTlsKey, tid));
    if (!td) return;

    cerr << "[pin-loop] fini  TID=" << td->os_tid
        << " total_insts=" << td->total_insts
        << " stored=" << td->insts.size()
        << (td->recording ? "" : " (TRUNCATED)") << endl;

    if (!td->insts.empty()) {
        AnalyzeLoops(td->insts, td->os_tid, KnobPrefix.Value(), KnobTop.Value());
    }

    delete td;
    PIN_SetThreadData(gTlsKey, 0, tid);
}

// ===== Fini =====
static VOID OnFini(INT32, VOID*)
{
    cerr << "[pin-loop] process fini\n";
}

// ===== Usage =====
static INT32 Usage()
{
    cerr <<
        "pin-loop: loop detector + trace dumper (per-thread)\n"
        "  - only_main=1 : 메인 이미지(실행파일)만 계측\n"
        "  - max_insts   : 스레드당 저장할 최대 인스트럭션 수\n"
        "  - top         : 상위 N개 루프만 파일로 덤프\n"
        "  - prefix      : 출력 파일 접두사 (예: C:\\trace\\wc)\n"
        << KNOB_BASE::StringKnobSummary()
        << endl;
    return -1;
}

// ===== main =====
int main(int argc, char* argv[])
{
    // 함수/심볼 이름 가져오려면 필수
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    gTlsKey = PIN_CreateThreadDataKey(0);

    IMG_AddInstrumentFunction(OnImgLoad, 0);
    INS_AddInstrumentFunction(OnIns, 0);
    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_AddThreadFiniFunction(OnThreadFini, 0);
    PIN_AddFiniFunction(OnFini, 0);

    cerr << "[pin-loop] only_main=" << (KnobOnlyMain.Value() ? "1" : "0")
        << " prefix=" << KnobPrefix.Value()
        << " max_insts=" << KnobMaxInsts.Value()
        << " top=" << KnobTop.Value()
        << endl;

    PIN_StartProgram(); // never returns
    return 0;
}

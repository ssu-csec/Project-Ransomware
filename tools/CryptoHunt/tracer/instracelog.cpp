// instracelog.cpp
/*
 * A pin tool to record all instructions in a binary execution.
 *  - 32-bit 대상(ia32)에서 사용
 *  - 실행 시 현재 작업 디렉터리에 instrace.txt 생성
 */

#include "pin.H"
#include <cstdio>
#include <string>
#include <map>
#include <iostream>

static const char* tracefile = "instrace.txt";

static std::map<ADDRINT, std::string> opcmap;
static FILE* fp = nullptr;

// IARG_CONST_CONTEXT 를 받으려면 const CONTEXT* 여야 합니다.
static VOID getctx(ADDRINT addr, const CONTEXT* fromctx, ADDRINT memaddr)
{
    std::fprintf(fp, "%x;%s;%x,%x,%x,%x,%x,%x,%x,%x,%x,\n",
        (unsigned)addr, opcmap[addr].c_str(),
        (unsigned)PIN_GetContextReg(fromctx, REG_EAX),
        (unsigned)PIN_GetContextReg(fromctx, REG_EBX),
        (unsigned)PIN_GetContextReg(fromctx, REG_ECX),
        (unsigned)PIN_GetContextReg(fromctx, REG_EDX),
        (unsigned)PIN_GetContextReg(fromctx, REG_ESI),
        (unsigned)PIN_GetContextReg(fromctx, REG_EDI),
        (unsigned)PIN_GetContextReg(fromctx, REG_ESP),
        (unsigned)PIN_GetContextReg(fromctx, REG_EBP),
        (unsigned)memaddr);
}

static VOID instruction(INS ins, VOID* /*v*/)
{
    const ADDRINT addr = INS_Address(ins);

    // 최초 한 번만 디스어셈 문자열 저장
    if (opcmap.find(addr) == opcmap.end())
        opcmap.emplace(addr, INS_Disassemble(ins));

    if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx,
            IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_END);
    } else if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx,
            IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYWRITE_EA, IARG_END);
    } else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)getctx,
            IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, (ADDRINT)0, IARG_END);
    }
}

static VOID on_fini(INT32 /*code*/, VOID* /*v*/)
{
    if (fp) std::fclose(fp);
}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) {
        std::fprintf(stderr, "command line error\n");
        return 1;
    }

    // 디스어셈블 사용 전 심볼 초기화 권장
    PIN_InitSymbols();

    fp = std::fopen(tracefile, "w");
    if (!fp) {
        std::fprintf(stderr, "cannot open %s\n", tracefile);
        return 1;
    }

    INS_AddInstrumentFunction(instruction, nullptr);
    PIN_AddFiniFunction(on_fini, nullptr);

    PIN_StartProgram(); // never returns
    return 0;
}

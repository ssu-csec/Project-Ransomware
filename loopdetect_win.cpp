// loopdetect_win.cpp
// 입력: trace_<TID>.bin (uint32 IP 열) -> 간단 백엣지(이전보다 낮은 주소) 기반 루프 헤더(진입 ip) 카운트
// 고급 loopdetect 대체가 아니라, TID 분리 효과 확인/필터링용 경량 도구.

#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>

struct LoopStat {
    uint64_t count = 0;       // back-edge 감지 횟수 (rough loop iters)
    uint32_t header = 0;      // 추정 루프 헤더 ip (back-edge target)
    uint32_t last_from = 0;   // 마지막 백엣지 from ip
};

static void analyze_file(const std::filesystem::path& p,
                         uint32_t min_iters,
                         uint32_t max_span,
                         uint32_t max_report) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "[loopdetect] failed to open " << p.string() << "\n";
        return;
    }
    std::vector<uint32_t> ips;
    in.seekg(0, std::ios::end);
    auto sz = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    ips.resize(sz / sizeof(uint32_t));
    if (sz % sizeof(uint32_t)) {
        std::cerr << "[loopdetect] warning: truncated bytes in " << p.filename().string() << "\n";
    }
    if (!ips.empty())
        in.read(reinterpret_cast<char*>(ips.data()),
                static_cast<std::streamsize>(ips.size() * sizeof(uint32_t)));

    std::unordered_map<uint32_t, LoopStat> stats; // header -> stat

    for (size_t i = 1; i < ips.size(); ++i) {
        uint32_t prev = ips[i - 1];
        uint32_t curr = ips[i];
        // 간단 백엣지 판정: 주소가 감소 && 감소폭이 너무 크지 않음(코드 영역 내 점프 가정)
        if (curr < prev) {
            uint32_t span = prev - curr;
            if (span <= max_span) {
                auto &st = stats[curr];
                st.header = curr;
                st.last_from = prev;
                st.count++;
            }
        }
    }

    // 필터링 및 정렬
    std::vector<LoopStat> vec;
    vec.reserve(stats.size());
    for (auto &kv : stats) {
        if (kv.second.count >= min_iters) vec.push_back(kv.second);
    }
    std::sort(vec.begin(), vec.end(), [](const LoopStat &a, const LoopStat &b){
        return a.count > b.count;
    });

    std::cout << "== " << p.filename().string() << " ==\n";
    std::cout << "header_ip,count\n";
    for (size_t i = 0; i < vec.size() && i < max_report; ++i) {
        std::cout << "0x" << std::hex << vec[i].header << std::dec << "," << vec[i].count << "\n";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr <<
        "Usage: loopdetect_win <trace_file or directory> [--min-iters N] [--max-span BYTES] [--max-report K]\n"
        "  trace_<TID>.bin 파일(또는 폴더)을 입력으로 받아 간단한 백엣지 기반 루프 후보를 요약 출력.\n";
        return 1;
    }

    std::filesystem::path input = argv[1];
    uint32_t min_iters = 8;
    uint32_t max_span = 4096;     // 너무 큰 역점프는 제외(함수단위 점프 등)
    uint32_t max_report = 50;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--min-iters" && i + 1 < argc) min_iters = std::stoul(argv[++i]);
        else if (a == "--max-span" && i + 1 < argc) max_span = std::stoul(argv[++i]);
        else if (a == "--max-report" && i + 1 < argc) max_report = std::stoul(argv[++i]);
    }

    if (std::filesystem::is_regular_file(input)) {
        analyze_file(input, min_iters, max_span, max_report);
    } else if (std::filesystem::is_directory(input)) {
        for (auto &ent : std::filesystem::directory_iterator(input)) {
            if (ent.is_regular_file()) {
                auto ext = ent.path().extension().string();
                if (ext == ".bin") {
                    analyze_file(ent.path(), min_iters, max_span, max_report);
                }
            }
        }
    } else {
        std::cerr << "No such file or directory: " << input.string() << "\n";
        return 2;
    }
    return 0;
}

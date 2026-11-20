// Reproducible RESEARCH MODEL only, not a production replay policy.
// Compares the actual 128-bit ReplayWindow to an independent set-based oracle.
#include "session.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <unordered_set>
#include <vector>

struct Arrival { unsigned tick, id; };
class Oracle {
    unsigned highest = 0;
    unsigned width;
    std::unordered_set<unsigned> accepted;
public:
    explicit Oracle(unsigned n): width(n) {}
    bool check(unsigned id) {
        if (id == 0 || (id <= highest && highest - id >= width)) return false;
        highest = std::max(highest, id);
        return accepted.insert(id).second;
    }
};

unsigned delay_for(unsigned model, unsigned cap, unsigned id, std::mt19937& rng) {
    if (!cap) return 0;
    switch (model) {
      case 0: return rng() % (cap + 1); // Uniform random jitter
      case 1: { // Clipped approximate normal jitter (mean cap/2, sd cap/6)
        std::normal_distribution<double> n(cap/2.0, cap/6.0);
        return static_cast<unsigned>(std::clamp(std::lround(n(rng)), 0L, static_cast<long>(cap)));
      }
      case 2: // 85% low delay, 15% heavy-tail bursts
        return (rng() % 100 < 85)
               ? rng() % (std::max(1u, cap/8) + 1)
               : cap/2 + rng() % (cap - cap/2 + 1);
      default: return (id % 2) ? cap : 0; // Alternating worst-pattern delay
    }
}

int main() {
    constexpr unsigned packets = 2048;
    constexpr const char* models[] = {"uniform", "normal", "bursty", "alternating"};
    std::cout << "profile,seed,max_delay_ticks,window,originals,late_originals,"
                 "accepted_immediate_duplicates,accepted_end_replays,bitmap_bytes,counter_bytes\n";
    for (unsigned model = 0; model < 4; ++model) {
      for (unsigned cap : {32u, 64u, 128u, 256u}) {
        for (unsigned seed = 1; seed <= 20; ++seed) {
            std::mt19937 rng(seed * 104729u + model * 8191u + cap);
            std::vector<Arrival> arrivals;
            arrivals.reserve(packets);
            for (unsigned id = 1; id <= packets; ++id)
                arrivals.push_back({id + delay_for(model, cap, id, rng), id});
            std::stable_sort(arrivals.begin(), arrivals.end(),
                             [](const Arrival& a, const Arrival& b) { return a.tick < b.tick; });
            for (unsigned width : {32u,64u,128u,256u,512u}) {
                Oracle oracle(width);
                ReplayWindow production;
                unsigned late = 0, dup = 0, end_replay = 0;
                auto deliver = [&](unsigned id) {
                    const bool expected = oracle.check(id);
                    if (width == 128 && production.accept(id) != expected)
                        throw std::runtime_error("production replay window diverged from oracle");
                    return expected;
                };
                for (const auto& a : arrivals) {
                    if (!deliver(a.id)) ++late;
                    if (deliver(a.id)) ++dup;
                }
                // Attack simulation: replay prior authenticated originals out of order.
                // A stale previously *rejected* original is not a replay; only
                // replay previously ACCEPTED originals here.
                for (const auto& a : arrivals) {
                    if (a.id % 17 != 0) continue;
                    if (deliver(a.id)) ++end_replay;
                }
                if (dup || end_replay) throw std::runtime_error("accepted replay");
                std::cout << models[model] << ',' << seed << ',' << cap << ',' << width
                          << ',' << packets << ',' << late << ',' << dup << ','
                          << end_replay << ',' << (width + 7)/8 << ",8\n";
            }
        }
      }
    }
}

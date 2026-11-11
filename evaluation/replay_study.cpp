#include "session.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <set>
#include <stdexcept>
#include <vector>

struct Arrival {
    unsigned tick;
    unsigned sequence;
};

// Independent specification: store every delivered ID explicitly.
class ReferenceWindow {
    unsigned highest = 0;
    unsigned width;
    std::set<unsigned> delivered;
public:
    explicit ReferenceWindow(unsigned width) : width(width) {}
    bool accept(unsigned id) {
        if (id == 0 || (id <= highest && highest - id >= width)) return false;
        highest = std::max(highest, id);
        return delivered.insert(id).second;
    }
};

int main() {
    constexpr unsigned packets = 4096;
    std::cout << "seed,max_delay_ticks,window,originals,late_originals,accepted_duplicates\n";
    for (unsigned seed = 1; seed <= 5; ++seed) {
        for (unsigned delay : {0u, 32u, 64u, 128u, 256u}) {
            std::mt19937 rng(seed);
            std::vector<Arrival> trace;
            for (unsigned id = 1; id <= packets; ++id)
                trace.push_back({id + static_cast<unsigned>(rng() % (delay + 1u)), id});
            std::stable_sort(trace.begin(), trace.end(), [](Arrival a, Arrival b) {
                return a.tick < b.tick;
            });
            for (unsigned width : {32u, 64u, 128u}) {
                ReferenceWindow reference(width);
                ReplayWindow actual;
                unsigned late = 0, duplicates = 0;
                auto deliver = [&](unsigned id) {
                    bool expected = reference.accept(id);
                    if (width == 64 && actual.accept(id) != expected)
                        throw std::runtime_error("production and reference decisions differ");
                    return expected;
                };
                for (auto arrival : trace) {
                    if (!deliver(arrival.sequence)) ++late;
                    if (deliver(arrival.sequence)) ++duplicates;
                }
                if (duplicates || (delay < width && late))
                    throw std::runtime_error("replay-window invariant failed");
                std::cout << seed << ',' << delay << ',' << width << ',' << packets
                          << ',' << late << ',' << duplicates << '\n';
            }
        }
    }
}

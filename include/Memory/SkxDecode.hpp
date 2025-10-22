#pragma once
#include <cstdint>
#include <optional>

struct DramTuple {
    int chan, rank, bg, bank, row, col;
};

// Return std::nullopt on error
std::optional<DramTuple> decode_pa_with_kernel(uint64_t phys);

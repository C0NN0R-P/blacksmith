#pragma once

#include <cstdint>
#include <optional>

// Simple POD carrying the decoded DRAM fields from the kernel module
struct DramTuple {
    int chan;
    int rank;
    int bg;
    int bank;
    int row;
    int col;
};

// Decode a *physical* address using the kernel module.
// Returns std::nullopt if the decode fails or the kernel mode is disabled.
std::optional<DramTuple> decode_pa_with_kernel(std::uint64_t phys_addr);

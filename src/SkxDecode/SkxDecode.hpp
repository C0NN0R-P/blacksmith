#pragma once
#include <cstdint>
#include <optional>
#include "SkxDecode/skx_ioctl.h"

struct SkxFields {
    uint32_t channel, imc, rank, bank, bank_group, row, col, status;
};

std::optional<SkxFields> skx_decode_address(uint64_t phys_addr);

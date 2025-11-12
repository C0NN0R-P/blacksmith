#pragma once
#include <stdint.h>
#include <linux/ioctl.h>

struct skx_dram_addr {
    uint64_t phys_addr;
    uint32_t channel;
    uint32_t imc;
    uint32_t rank;
    uint32_t bank;
    uint32_t bank_group;
    uint32_t row;
    uint32_t col;
    uint32_t status;
};

#define SKX_DECODE_IOCTL _IOWR('k', 1, struct skx_dram_addr)

#pragma once
#include <stdint.h>

/* Keep identical to kernel struct */
struct skx_decode_req {
    uint64_t phys_addr;   /* in */
    int32_t  channel;     /* out */
    int32_t  rank;        /* out */
    int32_t  bank_group;  /* out */
    int32_t  bank;        /* out */
    int64_t  row;         /* out */
    int64_t  col;         /* out */
};

/* Exact ioctl macro used by the kernel module */
#define SKX_IOCTL_DECODE _IOWR('k', 1, struct skx_decode_req)

/* Device path created by the module (misc device name) */
#define SKX_DECODER_DEV "/dev/skx_dram_decode"

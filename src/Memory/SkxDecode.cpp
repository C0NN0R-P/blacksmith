#include "SkxDecode.hpp"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdlib>

struct skx_decode_io {
    uint64_t phys;
    int chan, rank, bg, bank, row, col;
};

#ifndef SKX_DECODE_IOCTL
#define SKX_DECODE_IOCTL _IOWR('k', 0xD0, struct skx_decode_io)
#endif

static bool kernel_mode_enabled() {
    const char* v = std::getenv("BLACKSMITH_USE_KERNEL");
    return v && *v && *v != '0';
}

std::optional<DramTuple> decode_pa_with_kernel(uint64_t phys) {
    if (!kernel_mode_enabled()) return std::nullopt;
    int fd = open("/dev/skx_dram_decode_addr", O_RDONLY);
    if (fd < 0) return std::nullopt;
    skx_decode_io io{.phys = phys};
    if (ioctl(fd, SKX_DECODE_IOCTL, &io) != 0) {
        close(fd);
        return std::nullopt;
    }
    close(fd);
    return DramTuple{io.chan, io.rank, io.bg, io.bank, io.row, io.col};
}

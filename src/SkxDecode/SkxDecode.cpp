#include "SkxDecode/SkxDecode.hpp"
#include "Memory/skx_dram_decode_uapi.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdlib>
#include <optional>
#include <cstdint>

// Uses your kernel module via /dev/skx_dram_decode to decode PHYSICAL addresses

static bool kernel_mode_enabled() {
    const char *v = std::getenv("BLACKSMITH_USE_KERNEL");
    return v && *v && *v != '0';
}

std::optional<DramTuple> decode_pa_with_kernel(std::uint64_t phys_addr) {
    if (!kernel_mode_enabled()) {
        return std::nullopt;
    }

    int fd = ::open(SKX_DECODER_DEV, O_RDONLY);
    if (fd < 0) {
        return std::nullopt;
    }

    skx_decode_req req{};
    req.phys_addr = phys_addr;

    if (::ioctl(fd, SKX_IOCTL_DECODE, &req) != 0) {
        ::close(fd);
        return std::nullopt;
    }

    ::close(fd);

    DramTuple t;
    t.chan = req.channel;
    t.rank = req.rank;
    t.bg   = req.bank_group;
    t.bank = req.bank;
    t.row  = static_cast<int>(req.row);
    t.col  = static_cast<int>(req.col);

    return t;
}

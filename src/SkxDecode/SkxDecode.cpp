#include "SkxDecode/SkxDecode.hpp"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>

std::optional<SkxFields> skx_decode_address(uint64_t phys_addr) {
    int fd = ::open("/dev/skx_dram_decode", O_RDONLY);
    if (fd < 0) return std::nullopt;

    skx_dram_addr arg{};
    arg.phys_addr = phys_addr;

    if (::ioctl(fd, SKX_DECODE_IOCTL, &arg) != 0) {
        ::close(fd);
        return std::nullopt;
    }
    ::close(fd);

    SkxFields out{
       .channel = arg.channel,
       .imc = arg.imc,
       .rank = arg.rank,
       .bank = arg.bank,
       .bank_group = arg.bank_group,
       .row = arg.row,
       .col = arg.col,
       .status = arg.status,
    };
    return out;
}

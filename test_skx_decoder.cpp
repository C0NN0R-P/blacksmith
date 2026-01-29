#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

// Use the same UAPI as the kernel module
#include "Memory/skx_dram_decode_uapi.h"  // provides skx_decode_req, SKX_IOCTL_DECODE, SKX_DECODER_DEV

static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s <phys_addr> [phys_addr...]\n"
        "  phys_addr: physical address (decimal or 0x-prefixed hex)\n",
        prog);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    // Open the misc device created by the kernel module
    int fd = ::open(SKX_DECODER_DEV, O_RDWR);
    if (fd < 0) {
        std::fprintf(stderr,
            "ERROR: Failed to open %s: %s\n"
            "  - Is the skx_dram_decode_addr.ko module loaded?\n"
            "  - Do you have sufficient permissions (try sudo)?\n",
            SKX_DECODER_DEV, std::strerror(errno));
        return 1;
    }

    int exit_code = 0;

    for (int i = 1; i < argc; ++i) {
        const char* s = argv[i];

        // Convert string to uint64_t, auto-detecting base (0x... for hex, otherwise decimal)
        errno = 0;
        char* endp = nullptr;
        std::uint64_t phys = std::strtoull(s, &endp, 0);

        if (errno != 0 || endp == s || *endp != '\0') {
            std::fprintf(stderr, "ERROR: Invalid physical address: '%s'\n", s);
            exit_code = 1;
            continue;
        }

        skx_decode_req req{};
        req.phys_addr = phys;

        if (::ioctl(fd, SKX_IOCTL_DECODE, &req) < 0) {
            std::fprintf(stderr,
                         "IOCTL decode failed for %s (0x%llx): %s\n",
                         s,
                         static_cast<unsigned long long>(phys),
                         std::strerror(errno));
            exit_code = 1;
            continue;
        }

        // At this point, the kernel module decoded successfully – so it’s “working”
        std::printf("phys=%s (0x%llx)\n", s,
                    static_cast<unsigned long long>(phys));
        std::printf("  channel   = %d\n",  req.channel);
        std::printf("  rank      = %d\n",  req.rank);
        std::printf("  bank_group= %d\n",  req.bank_group);
        std::printf("  bank      = %d\n",  req.bank);
        std::printf("  row       = %lld\n",
                    static_cast<long long>(req.row));
        std::printf("  col       = %lld\n",
                    static_cast<long long>(req.col));
        std::printf("\n");
    }

    ::close(fd);
    return exit_code;
}

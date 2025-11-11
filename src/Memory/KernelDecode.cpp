#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdexcept>
#include "Memory/skx_dram_decode_uapi.h"

namespace mem {
class KernelDecoder {
  int fd_;
public:
  KernelDecoder() : fd_(-1) {
    fd_ = ::open(SKX_DECODER_DEV, O_RDWR);
    if (fd_ < 0) throw std::runtime_error("open(" SKX_DECODER_DEV ") failed");
  }
  ~KernelDecoder() { if (fd_ >= 0) ::close(fd_); }

  void decode(uint64_t phys, skx_decode_req &out) {
    out.phys_addr = phys;
    if (::ioctl(fd_, SKX_IOCTL_DECODE, &out) != 0) {
      throw std::runtime_error("ioctl(SKX_IOCTL_DECODE) failed");
    }
  }
};

static KernelDecoder g_decoder; // construct once

void decode_phys_to_fields(uint64_t phys,
                           int &chan, int &rank, int &bg, int &bank,
                           long long &row, long long &col) {
  skx_decode_req r{};
  g_decoder.decode(phys, r);
  chan = r.channel; rank = r.rank; bg = r.bank_group; bank = r.bank;
  row  = r.row;     col  = r.col;
}
} // namespace mem

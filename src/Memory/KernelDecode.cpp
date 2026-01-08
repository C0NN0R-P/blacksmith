/*
 * ANNOTATION (dev notes)
 * Thin wrapper around the kernel decode interface.
 * This is where we cross the user/kernel boundary to ask “what DRAM tuple does this PA map to?”
 * When the ioctl path fails, the code falls back to “unknown” rather than crashing.
 */
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdexcept>
#include <errno.h>
#include "Memory/skx_dram_decode_uapi.h"

#include "Utilities/Debug.hpp"

namespace mem {
class KernelDecoder {
  int fd_;
public:
  KernelDecoder() : fd_(-1) {
    BS_TRACE_SCOPE_NAMED("KernelDecoder::KernelDecoder");
    BS_DLOGF("opening device '%s'", SKX_DECODER_DEV);
    fd_ = ::open(SKX_DECODER_DEV, O_RDWR);
    if (fd_ < 0) throw std::runtime_error("open(" SKX_DECODER_DEV ") failed");
    BS_DLOGF("device opened fd=%d", fd_);
  }
  ~KernelDecoder() {
    BS_TRACE_SCOPE_NAMED("KernelDecoder::~KernelDecoder");
    if (fd_ >= 0) {
      BS_DLOGF("closing fd=%d", fd_);
      ::close(fd_);
    }
  }

  void decode(uint64_t phys, skx_decode_req &out) {
    BS_TRACE_SCOPE_NAMED("KernelDecoder::decode");
    BS_DLOGF("phys=0x%llx", (unsigned long long)phys);
    out.phys_addr = phys;
    if (::ioctl(fd_, SKX_IOCTL_DECODE, &out) != 0) {
      BS_DLOGF("ioctl failed errno=%d", errno);
      throw std::runtime_error("ioctl(SKX_IOCTL_DECODE) failed");
    }
    BS_DLOGF("decoded: chan=%d rank=%d bg=%d bank=%d row=%lld col=%lld",
             out.channel, out.rank, out.bank_group, out.bank, (long long)out.row, (long long)out.col);
  }
};

static KernelDecoder g_decoder; // construct once

void decode_phys_to_fields(uint64_t phys,
                           int &chan, int &rank, int &bg, int &bank,
                           long long &row, long long &col) {
  BS_TRACE_SCOPE_NAMED("decode_phys_to_fields");
  skx_decode_req r{};
  g_decoder.decode(phys, r);
  chan = r.channel; rank = r.rank; bg = r.bank_group; bank = r.bank;
  row  = r.row;     col  = r.col;
}
} // namespace mem

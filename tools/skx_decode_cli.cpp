#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include "SkxDecode/SkxDecode.hpp"

static void usage(const char* prog){
  std::fprintf(stderr, "Usage: %s <phys_addr> [phys_addr...]\n", prog);
  std::fprintf(stderr, "  phys_addr: physical address (e.g., 0x1234abcd)\n");
}

int main(int argc, char** argv){
  if (argc < 2){ usage(argv[0]); return 2; }

  for (int i=1; i<argc; ++i){
    const char* s = argv[i];
    uint64_t phys = std::strtoull(s, nullptr, 0); // auto hex/dec
    auto dec = skx_decode_address(phys);
    if (!dec){
      std::printf("%s -> decode FAILED\n", s);
      continue;
    }
    auto d = *dec;
    std::printf("%s -> imc=%u chan=%u rank=%u bank=%u bg=%u row=%u col=%u status=%u\n",
      s, d.imc, d.channel, d.rank, d.bank, d.bank_group, d.row, d.col, d.status);
  }
  return 0;
}

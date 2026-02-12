#include "Memory/DRAMAddr.hpp"
#include "GlobalDefines.hpp"
#include "Memory/SkxDecode.hpp"

#include <iostream>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>

// initialize static variable
std::map<size_t, MemConfiguration> DRAMAddr::Configs;

void DRAMAddr::initialize(uint64_t num_bank_rank_functions, volatile char *start_address) {
  // Shortcut: choose config based on #ranks (as original code did).
  size_t num_ranks;
  if (num_bank_rank_functions == 5) {
    num_ranks = RANKS(2);
  } else if (num_bank_rank_functions == 4) {
    num_ranks = RANKS(1);
  } else {
    Logger::log_error("Could not initialize DRAMAddr as #ranks seems not to be 1 or 2.");
    std::exit(1);
  }
  DRAMAddr::load_mem_config((CHANS(CHANNEL) | DIMMS(DIMM) | num_ranks | BANKS(NUM_BANKS)));
  DRAMAddr::set_base_msb((void *) start_address);
}

void DRAMAddr::set_base_msb(void *buff) {
  // Keep for compatibility (some code assumes this exists), but we no longer synthesize VAs.
  base_msb = (size_t) buff & (~((size_t) (1ULL << 30UL) - 1UL));
}

void DRAMAddr::load_mem_config(mem_config_t cfg) {
  DRAMAddr::initialize_configs();
  MemConfig = Configs[cfg];
}

DRAMAddr::DRAMAddr() = default;

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c) {
  bank = bk;
  row  = r;
  col  = c;
}

DRAMAddr::DRAMAddr(void *addr) {
  // Kernel-only mode:
  //   virt -> phys via /proc/self/pagemap
  //   phys -> DRAM via decode_pa_with_kernel()
  // Matrix mapping is intentionally disabled.
  this->virt = addr;

  const std::uint64_t virt_u64 = reinterpret_cast<std::uint64_t>(addr);
  const long page_size = ::getpagesize();

  bool decoded = false;
  std::uint64_t phys_addr = 0;

  FILE *pm = std::fopen("/proc/self/pagemap", "rb");
  if (pm != nullptr) {
    const std::uint64_t index =
        (virt_u64 / static_cast<std::uint64_t>(page_size)) * sizeof(std::uint64_t);

    if (std::fseek(pm, static_cast<long>(index), SEEK_SET) == 0) {
      std::uint64_t phys_entry = 0;
      if (std::fread(&phys_entry, sizeof(phys_entry), 1, pm) == 1) {
        // bit 63 == 1 -> page present
        if (phys_entry & (1ULL << 63)) {
          const std::uint64_t pfn = phys_entry & ((1ULL << 55) - 1);
          phys_addr =
              (pfn * static_cast<std::uint64_t>(page_size)) +
              (virt_u64 & (static_cast<std::uint64_t>(page_size) - 1));

          std::cout << phys_addr << ":phys\n";

          if (auto t = decode_pa_with_kernel(phys_addr)) {
            channel    = t->chan;
            rank       = t->rank;
            bank_group = t->bg;

            // Blacksmith uses a combined bank index; pack bg + bank here.
            bank = (static_cast<size_t>(t->bg) << 2) |
                   static_cast<size_t>(t->bank);

            row = static_cast<size_t>(t->row);
            col = static_cast<size_t>(t->col);

            decoded = true;
          }
        }
      }
    }

    std::fclose(pm);
  }

  if (decoded) {
    static int printed = 0;
    if (printed < 200) {
      std::printf(
          "[DRAMAddr] VA=%p PA=0x%llx chan=%d rank=%d bg=%d bank=%zu row=%zu col=%zu\n",
          addr,
          (unsigned long long) phys_addr,
          channel,
          rank,
          bank_group,
          bank,
          row,
          col);
      printed++;
    }
    return;
  }

  // No fallback allowed.
  Logger::log_error("[DRAMAddr] Kernel decode failed and matrix mapping is disabled.");
  std::abort();
}

size_t DRAMAddr::linearize() const {
  // Kept for compatibility with code that may call it (even though to_virt is disabled).
  return (this->bank << MemConfig.BK_SHIFT) |
         (this->row  << MemConfig.ROW_SHIFT) |
         (this->col  << MemConfig.COL_SHIFT);
}

void *DRAMAddr::to_virt() {
  return const_cast<const DRAMAddr *>(this)->to_virt();
}

void *DRAMAddr::to_virt() const {
  // No synthesis. Only return a real VA if we were constructed from one.
  if (virt != nullptr) {
    return virt;
  }
  Logger::log_error("[DRAMAddr] to_virt() called but no VA is stored (matrix mapping disabled).");
  std::abort();
}

void *DRAMAddr::get_virt() const {
  if (virt != nullptr) {
    return virt;
  }
  Logger::log_error("[DRAMAddr] get_virt() called but no VA is stored (matrix mapping disabled).");
  std::abort();
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  std::sprintf(buff, "DRAMAddr(b: %zu, r: %zu, c: %zu) = %p",
      this->bank,
      this->row,
      this->col,
      this->to_virt());
  return std::string(buff);
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  std::sprintf(buff, "(%ld,%ld,%ld)",
      this->bank,
      this->row,
      this->col);
  return std::string(buff);
}

DRAMAddr DRAMAddr::add(size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return {bank + bank_increment, row + row_increment, col + column_increment};
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  bank += bank_increment;
  row  += row_increment;
  col  += column_increment;
}

// Define the static DRAM configs
MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;

#ifdef ENABLE_JSON

nlohmann::json DRAMAddr::get_memcfg_json() {
  std::map<size_t, nlohmann::json> memcfg_to_json = {
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
       nlohmann::json{{"channels", 1}, {"dimms", 1}, {"ranks", 1}, {"banks", 16}}},
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
       nlohmann::json{{"channels", 1}, {"dimms", 1}, {"ranks", 2}, {"banks", 16}}}
  };
  return memcfg_to_json[MemConfig.IDENTIFIER];
}

#endif

void DRAMAddr::initialize_configs() {
  // IMPORTANT:
  // We keep MemConfiguration entries so the program compiles and DRAMAddr::linearize() has shifts/masks.
  // But DRAM_MTX / ADDR_MTX are deliberately zeroed and never used (kernel-only mode).

  struct MemConfiguration single_rank = {
      .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
      .BK_SHIFT   = 26,
      .BK_MASK    = 0xF,
      .ROW_SHIFT  = 0,
      .ROW_MASK   = 0x1FFF,
      .COL_SHIFT  = 13,
      .COL_MASK   = 0x1FFF,
      .DRAM_MTX   = {0},
      .ADDR_MTX   = {0}
  };

  struct MemConfiguration dual_rank = {
      .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
      .BK_SHIFT   = 25,
      .BK_MASK    = 0x1F,
      .ROW_SHIFT  = 0,
      .ROW_MASK   = 0xFFF,
      .COL_SHIFT  = 12,
      .COL_MASK   = 0x1FFF,
      .DRAM_MTX   = {0},
      .ADDR_MTX   = {0}
  };

  DRAMAddr::Configs = {
      {single_rank.IDENTIFIER, single_rank},
      {dual_rank.IDENTIFIER, dual_rank}
  };
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {{"bank", p.bank},
       {"row",  p.row},
       {"col",  p.col}};
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

#endif

#include "Memory/Memory.hpp"
#include "Memory/DRAMAddr.hpp"
#include "GlobalDefines.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <errno.h>

/// Allocates mem_size bytes of memory (we use regular heap memory, with an
/// optional transparent-hugepage hint instead of hugetlbfs/mmap).
void Memory::allocate_memory(size_t mem_size) {
  // Remember how much memory we manage.
  this->size = mem_size;

  // Allocate on the heap and (optionally) ask the kernel for transparent huge pages.
  const size_t pagesize   = static_cast<size_t>(getpagesize());
  const size_t alignment  = 2UL * 1024UL * 1024UL;  // 2 MiB alignment
  const size_t align_used = alignment > pagesize ? alignment : pagesize;

  void *buf = nullptr;
  int rc = posix_memalign(&buf, align_used, this->size);
  if (rc != 0 || buf == nullptr) {
    Logger::log_error("posix_memalign failed in Memory::allocate_memory");
    Logger::log_data(std::strerror(rc != 0 ? rc : errno));
    std::exit(EXIT_FAILURE);
  }

  start_address = reinterpret_cast<volatile char *>(buf);

  // If superpage mode is requested, just give THP a hint.
  if (superpage) {
    if (madvise(buf, this->size, MADV_HUGEPAGE) != 0) {
      Logger::log_info("madvise(MADV_HUGEPAGE) failed – continuing without hugepage hint.");
    }
  }

  // Initialize memory with the original pseudorandom pattern.
  initialize(DATA_PATTERN::RANDOM);
}

void Memory::initialize(DATA_PATTERN data_pattern) {
  Logger::log_info("Initializing memory with pseudorandom sequence.");

  // for each page in the address space [0, size)
  for (uint64_t cur_page = 0; cur_page < size; cur_page += getpagesize()) {
    // reseed rand to have a sequence of reproducible numbers
    srand(static_cast<unsigned int>(cur_page * getpagesize()));
    for (uint64_t cur_pageoffset = 0;
         cur_pageoffset < static_cast<uint64_t>(getpagesize());
         cur_pageoffset += sizeof(int)) {

      int fill_value = 0;
      if (data_pattern == DATA_PATTERN::RANDOM) {
        fill_value = rand();
      } else if (data_pattern == DATA_PATTERN::ZEROES) {
        fill_value = 0;
      } else if (data_pattern == DATA_PATTERN::ONES) {
        fill_value = 1;
      } else {
        Logger::log_error("Could not initialize memory with given (unknown) DATA_PATTERN.");
      }

      // write (pseudo)random 4 bytes
      uint64_t offset = cur_page + cur_pageoffset;
      *((int *) (start_address + offset)) = fill_value;
    }
  }
}

size_t Memory::check_memory(PatternAddressMapper &mapping,
                            bool reproducibility_mode,
                            bool verbose) {
  flipped_bits.clear();

  auto victim_rows = mapping.get_victim_rows();
  if (verbose)
    Logger::log_info(format_string("Checking %zu victims for bit flips.",
                                   victim_rows.size()));

  size_t sum_found_bitflips = 0;
  for (const auto &victim_row : victim_rows) {
    auto victim_dram_addr = DRAMAddr((char *) victim_row);
    victim_dram_addr.add_inplace(0, 1, 0);
    sum_found_bitflips += check_memory_internal(mapping,
                                                victim_row,
                                                (volatile char *) victim_dram_addr.to_virt(),
                                                reproducibility_mode,
                                                verbose);
  }
  return sum_found_bitflips;
}

size_t Memory::check_memory(const volatile char *start,
                            const volatile char *end) {
  flipped_bits.clear();
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  return check_memory_internal(pattern_mapping, start, end, false, true);
}

size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     const volatile char *end,
                                     bool reproducibility_mode,
                                     bool verbose) {
  // counter for the number of found bit flips in the memory region [start, end]
  size_t found_bitflips = 0;

  if (start == nullptr || end == nullptr || ((uint64_t) start >= (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: %s",
                                   DRAMAddr((void *) start).to_string().c_str()));
    Logger::log_data(format_string("End addr.: %s",
                                   DRAMAddr((void *) end).to_string().c_str()));
    return found_bitflips;
  }

  auto start_offset = (uint64_t) (start - start_address);

  const auto pagesize = static_cast<size_t>(getpagesize());
  start_offset = (start_offset / pagesize) * pagesize;

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset / pagesize) * pagesize;

  void *page_raw = std::malloc(pagesize);
  if (page_raw == nullptr) {
    Logger::log_error("Could not create temporary page for memory comparison.");
    std::exit(EXIT_FAILURE);
  }
  std::memset(page_raw, 0, pagesize);
  int *page = (int *) page_raw;

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += pagesize) {
    // reseed rand to have the desired sequence of reproducible numbers
    srand(static_cast<unsigned int>(i * pagesize));

    // fill comparison page with expected values generated by rand()
    for (size_t j = 0; j < (unsigned long) pagesize / sizeof(int); ++j)
      page[j] = rand();

    uint64_t addr = ((uint64_t) start_address + i);

    // fast path: memcmp; if equal, no bitflip in this page
    if ((addr + pagesize) < ((uint64_t) start_address + size) &&
        std::memcmp((void *) addr, (void *) page, pagesize) == 0)
      continue;

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) pagesize; j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;

      // if this address is outside our region, skip to avoid segfault
      if ((uint64_t) cur_addr >= ((uint64_t) start_address + size))
        continue;

      // clear the cache to make sure we do not access a cached value
      clflushopt(cur_addr);
      mfence();

      // if the bit did not flip -> continue checking next block
      int expected_rand_value = page[j / sizeof(int)];
      if (*((int *) cur_addr) == expected_rand_value)
        continue;

      // if the bit flipped -> compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        volatile char *flipped_address = cur_addr + c;
        if (*flipped_address != ((char *) &expected_rand_value)[c]) {
          const auto flipped_addr_dram = DRAMAddr((void *) flipped_address);
          assert(flipped_address ==
                 (volatile char *) flipped_addr_dram.to_virt());
          const auto flipped_addr_value = *(unsigned char *) flipped_address;
          const auto expected_value =
              ((unsigned char *) &expected_rand_value)[c];
          if (verbose) {
            Logger::log_bitflip(flipped_address, flipped_addr_dram.row,
                                expected_value, flipped_addr_value,
                                (size_t) time(nullptr), true);
          }
          // store detailed information about the bit flip
          BitFlip bitflip(flipped_addr_dram,
                          (expected_value ^ flipped_addr_value),
                          flipped_addr_value);
          // .in the mapping that triggered this bit flip
          if (!reproducibility_mode) {
            if (mapping.bit_flips.empty()) {
              Logger::log_error(
                  "Cannot store bit flips found in given address mapping.\n"
                  "You need to create an empty vector in "
                  "PatternAddressMapper::bit_flips before calling "
                  "check_memory.");
            }
            mapping.bit_flips.back().push_back(bitflip);
          }
          // ..and in an attribute of this class so that it can be retrieved
          // by the caller
          flipped_bits.push_back(bitflip);
          found_bitflips += bitflip.count_bit_corruptions();
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flush this address so that value is committed before hammering again
      clflushopt(cur_addr);
      mfence();
    }
  }

  std::free(page_raw);
  return found_bitflips;
}

Memory::Memory(bool use_superpage)
    : start_address(nullptr),
      size(0),
      superpage(use_superpage) {
}

Memory::~Memory() {
  // We allocated via posix_memalign → free() is correct, not munmap().
  if (start_address != nullptr) {
    std::free((void *) start_address);
    start_address = nullptr;
    size = 0;
  }
}

volatile char *Memory::get_starting_address() const {
  return start_address;
}

std::string Memory::get_flipped_rows_text_repr() {
  // first extract all rows, otherwise it will not be possible to know in advance
  // whether we still need to add a separator (comma) to the string as upcoming
  // DRAMAddr instances might refer to the same row
  std::set<size_t> flipped_rows;
  for (const auto &da : flipped_bits) {
    flipped_rows.insert(da.address.row);
  }

  std::stringstream ss;
  for (const auto &row : flipped_rows) {
    ss << row;
    if (row != *flipped_rows.rbegin())
      ss << ",";
  }
  return ss.str();
}

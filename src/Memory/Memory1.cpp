#include "Memory/Memory.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Fuzzer/PatternAddressMapper.hpp"
#include "Utilities/Logger.hpp"
#include "Fuzzer/BitFlip.hpp"
#include "Utilities/AsmPrimitives.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <cassert>
#include <vector>
#include <set>
#include <sstream>
#include <cstdlib>

inline void clflushopt(void* addr) {
  asm volatile("clflushopt (%0)" :: "r"(addr));
}

char* find_matching_address_pair(size_t mem_size, char*& match_out) {
  size_t pagesize = getpagesize();
  size_t num_pages = mem_size / pagesize;
  char* region;
  assert(posix_memalign((void**)&region, pagesize, mem_size) == 0);
  memset((char*)region, 'A', mem_size);

  for (size_t i = 0; i < num_pages; ++i) {
    void* a1 = (void*)(region + i * pagesize);
    DRAMAddr d1(a1);
    for (size_t j = i + 1; j < num_pages; ++j) {
      void* a2 = (void*)(region + j * pagesize);
      DRAMAddr d2(a2);
      if (d1.channel == d2.channel && d1.rank == d2.rank && d1.bank == d2.bank) {
        match_out = region + j * pagesize;
        return region + i * pagesize;
      }
    }
  }
  std::cerr << "Could not find address pair in same bank." << std::endl;
  exit(EXIT_FAILURE);
}

Memory::Memory(bool allocate) : superpage(false) {
  if (allocate) {
    allocate_memory((256L * 1024 * 1024)); // Default size if not otherwise specified
  }
}

Memory::~Memory() = default;

void Memory::allocate_memory(size_t mem_size) {
  this->size = mem_size;
  Logger::log_info("Waiting for khugepaged.");
  sleep(10);

  char* match = nullptr;
  start_address = find_matching_address_pair(mem_size, match);

  Logger::log_info(format_string("Start address: %p", start_address));
  Logger::log_info(format_string("Matching address: %p", match));

  DRAMAddr ref((void*)start_address);
  Logger::log_info(format_string("Ref ch:%d rank:%d bank:%d", ref.channel, ref.rank, ref.bank));

  initialize(DATA_PATTERN::RANDOM);
}

volatile char* Memory::get_starting_address() const {
  return start_address;
}

void Memory::initialize(DATA_PATTERN data_pattern) {
  Logger::log_info("Initializing memory with pseudorandom sequence.");
  for (uint64_t cur_page = 0; cur_page < size; cur_page += getpagesize()) {
    srand(static_cast<unsigned int>(cur_page * getpagesize()));
    for (uint64_t offset = 0; offset < (uint64_t)getpagesize(); offset += sizeof(int)) {
      int fill_value = 0;
      if (data_pattern == DATA_PATTERN::RANDOM) {
        fill_value = rand();
      } else if (data_pattern == DATA_PATTERN::ZEROES) {
        fill_value = 0;
      } else if (data_pattern == DATA_PATTERN::ONES) {
        fill_value = 1;
      }
      *((int*)(start_address + cur_page + offset)) = fill_value;
    }
  }
}

std::string Memory::get_flipped_rows_text_repr() {
  std::set<size_t> flipped_rows;
  for (const auto& da : flipped_bits) {
    flipped_rows.insert(da.address.row);
  }
  std::stringstream ss;
  for (const auto& row : flipped_rows) {
    ss << row;
    if (row != *flipped_rows.rbegin()) ss << ",";
  }
  return ss.str();
}

size_t Memory::check_memory(PatternAddressMapper& mapping, bool reproducibility_mode, bool verbose) {
  return check_memory_internal(mapping, start_address, start_address, verbose, reproducibility_mode);
}

size_t Memory::check_memory(const volatile char* prev, const volatile char* current) {
  PatternAddressMapper dummy;
  return check_memory_internal(dummy, prev, current, false, false);
}

size_t Memory::check_memory_internal(PatternAddressMapper& /*mapper*/, const volatile char* prev, const volatile char* current, bool log_changes, bool count_flips_only) {
  size_t flips = 0;
  for (size_t offset = 0; offset < size; offset++) {
    if (prev[offset] != current[offset]) {
      DRAMAddr addr((void*)(start_address + offset));
      BitFlip flip(addr, prev[offset], current[offset]);
      flips++;
      if (!count_flips_only) {
        flipped_bits.push_back(flip);
        if (log_changes)
          Logger::log_error("Bit flip found in given address mapping.");
      }
    }
  }
  return flips;
}

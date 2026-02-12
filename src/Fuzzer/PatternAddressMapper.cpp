#include "Fuzzer/PatternAddressMapper.hpp"

#include <algorithm>
#include <cstdlib>

#include "GlobalDefines.hpp"
#include "Utilities/Uuid.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Memory/Memory.hpp"

// initialize the bank_counter (static var)
int PatternAddressMapper::bank_counter = 0;

PatternAddressMapper::PatternAddressMapper()
    : instance_id(uuid::gen_uuid()) { /* NOLINT */
  code_jitter = std::make_unique<CodeJitter>();

  // standard mersenne_twister_engine seeded with rd()
  std::random_device rd;
  gen = std::mt19937(rd());
}

PatternAddressMapper::PatternAddressMapper(const PatternAddressMapper& other) {
  // deep-copy-ish: CodeJitter is re-created, mapping state is copied
  instance_id = other.instance_id;
  gen = other.gen;

  code_jitter = std::make_unique<CodeJitter>();

  min_row = other.min_row;
  max_row = other.max_row;
  bank_no = other.bank_no;

  aggressor_to_addr = other.aggressor_to_addr;
  victim_rows = other.victim_rows;

  decoded_row_to_va = other.decoded_row_to_va;
  decoded_bank_to_rows = other.decoded_bank_to_rows;

  bit_flips = other.bit_flips;
  reproducibility_score = other.reproducibility_score;
}

PatternAddressMapper& PatternAddressMapper::operator=(const PatternAddressMapper& other) {
  if (this == &other) return *this;

  instance_id = other.instance_id;
  gen = other.gen;

  code_jitter = std::make_unique<CodeJitter>();

  min_row = other.min_row;
  max_row = other.max_row;
  bank_no = other.bank_no;

  aggressor_to_addr = other.aggressor_to_addr;
  victim_rows = other.victim_rows;

  decoded_row_to_va = other.decoded_row_to_va;
  decoded_bank_to_rows = other.decoded_bank_to_rows;

  bit_flips = other.bit_flips;
  reproducibility_score = other.reproducibility_score;

  return *this;
}

void PatternAddressMapper::randomize_addresses(FuzzingParameterSet &fuzzing_params,
                                               const std::vector<AggressorAccessPattern> &agg_access_patterns,
                                               bool verbose) {
  (void)fuzzing_params;
  (void)agg_access_patterns;
  (void)verbose;

  // This overload relied on DRAMAddr(bank,row,col) + to_virt() (matrix mapping).
  Logger::log_error(
      "[PatternAddressMapper] randomize_addresses(fuzzing_params, ...) is disabled (matrix mapping removed). "
      "Use randomize_addresses(memory, fuzzing_params, ...) instead.");
  std::abort();
}

void PatternAddressMapper::randomize_addresses(Memory &memory,
                                               FuzzingParameterSet &fuzzing_params,
                                               const std::vector<AggressorAccessPattern> &agg_access_patterns,
                                               bool verbose) {
  aggressor_to_addr.clear();
  victim_rows.clear();
  decoded_row_to_va.clear();
  decoded_bank_to_rows.clear();

  auto pack_bank = [](int chan, int rank, int bg, int bank) -> uint64_t {
    return (uint64_t)(chan & 0xff) << 24 |
           (uint64_t)(rank & 0xff) << 16 |
           (uint64_t)(bg   & 0xff) << 8  |
           (uint64_t)(bank & 0xff);
  };

  volatile char *base = memory.get_starting_address();
  const uint64_t size = memory.get_size();
  const size_t stride = (size_t)getpagesize();

  // 1) Scan buffer, decode each page VA via kernel module (DRAMAddr(void*) is kernel-only in your tree now).
  for (uint64_t off = 0; off + stride <= size; off += stride) {
    volatile char *va = base + off;
    DRAMAddr d((void *)va);

    // DRAMAddr(va) will abort if kernel decode fails (by design).
    const int chan = d.channel;
    const int rank = d.rank;
    const int bg   = d.bank_group;
    const int bank = (int)(d.bank & 0x3); // because bank is packed as (bg<<2)|bank

    const uint32_t row = (uint32_t)d.row;
    const uint64_t bk = pack_bank(chan, rank, bg, bank);
    const uint64_t rk = (bk << 32) | (uint64_t)row;

    if (decoded_row_to_va.find(rk) == decoded_row_to_va.end()) {
      decoded_row_to_va[rk] = va;
      decoded_bank_to_rows[bk].push_back((int)row);
    }
  }

  for (auto &kv : decoded_bank_to_rows) {
    auto &rows = kv.second;
    std::sort(rows.begin(), rows.end());
    rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
  }

  if (decoded_bank_to_rows.empty()) {
    Logger::log_error("[PatternAddressMapper] No decodable addresses found in Memory buffer.");
    std::abort();
  }

  if (verbose) {
    Logger::log_info(format_string("[PatternAddressMapper] decoded banks=%zu decoded rows=%zu",
                                   decoded_bank_to_rows.size(),
                                   decoded_row_to_va.size()));
  }

  // 2) Choose aggressors from same (chan,rank,bg,bank) and adjacent rows
  const int intra = fuzzing_params.get_agg_intra_distance(); // typically 1 for adjacent rows

  std::vector<uint64_t> bank_keys;
  bank_keys.reserve(decoded_bank_to_rows.size());
  for (auto &kv : decoded_bank_to_rows) bank_keys.push_back(kv.first);

  auto find_pair = [&](uint64_t bk, int &r0) -> bool {
    auto &rows = decoded_bank_to_rows[bk];
    for (int a : rows) {
      int b = a + intra;
      if (std::binary_search(rows.begin(), rows.end(), b)) { r0 = a; return true; }
    }
    return false;
  };

  for (auto &acc_pattern : agg_access_patterns) {
    if (acc_pattern.aggressors.empty()) continue;

    bool ok = false;

    for (int tries = 0; tries < 500 && !ok; tries++) {
      // Cycle deterministically across available decoded banks.
      uint64_t bk = bank_keys[static_cast<size_t>(PatternAddressMapper::bank_counter) % bank_keys.size()];
      PatternAddressMapper::bank_counter = (PatternAddressMapper::bank_counter + 1) % (int)bank_keys.size();

      int r0 = 0;
      if (!find_pair(bk, r0)) continue;

      // Record mapping stats for downstream helpers (e.g., get_random_nonaccessed_rows).
      bank_no = (int)(bk & 0xff); // low byte is the "bank" field from pack_bank()
      {
        auto &rows_vec = decoded_bank_to_rows[bk];
        if (!rows_vec.empty()) {
          min_row = (size_t)rows_vec.front();
          max_row = (size_t)rows_vec.back();
        }
      }

      ok = true;
      for (size_t i = 0; i < acc_pattern.aggressors.size(); i++) {
        const int rr = r0 + (int)i * intra;
        const uint64_t rk = (bk << 32) | (uint32_t)rr;

        auto it = decoded_row_to_va.find(rk);
        if (it == decoded_row_to_va.end()) { ok = false; break; }

        volatile char *va = it->second;
        aggressor_to_addr[acc_pattern.aggressors[i].id] = DRAMAddr((void *)va);
      }
    }

    if (!ok) {
      Logger::log_error("[PatternAddressMapper] Failed to assign aggressors from decoded pool.");
      std::abort();
    }
  }

  // 3) Victims from decoded pool
  determine_victims(agg_access_patterns);
}

void PatternAddressMapper::remap_aggressors(DRAMAddr &new_location) {
  // Kernel-only: we cannot "synthesise" addresses, so we only support remapping if
  // new_location already carries a real VA (i.e., constructed from a pointer).
  void *va = new_location.get_virt();
  for (auto &kv : aggressor_to_addr) {
    kv.second = DRAMAddr(va);
  }
}

void PatternAddressMapper::export_pattern_internal(std::vector<Aggressor> &aggressors,
                                                  int base_period,
                                                  std::vector<volatile char *> &addresses,
                                                  std::vector<int> &rows) {
  addresses.clear();
  rows.clear();

  addresses.reserve(aggressors.size());
  rows.reserve(aggressors.size());

  for (auto &agg : aggressors) {
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find DRAMAddr mapping for Aggressor %d", agg.id));
      std::abort();
    }

    const auto &dram_addr = aggressor_to_addr.at(agg.id);
    addresses.push_back(static_cast<volatile char *>(dram_addr.get_virt()));
    rows.push_back((int)dram_addr.row);

    agg.base_period = base_period;
  }
}

void PatternAddressMapper::export_pattern(std::vector<Aggressor> &aggressors,
                                         int base_period,
                                         std::vector<volatile char *> &addresses) {
  std::vector<int> rows_dummy;
  export_pattern_internal(aggressors, base_period, addresses, rows_dummy);
}

void PatternAddressMapper::export_pattern(std::vector<Aggressor> &aggressors,
                                         size_t base_period,
                                         int *rows,
                                         size_t max_rows) {
  std::vector<volatile char *> addresses_dummy;
  std::vector<int> rows_vec;

  export_pattern_internal(aggressors, (int)base_period, addresses_dummy, rows_vec);

  const size_t n = std::min(rows_vec.size(), max_rows);
  for (size_t i = 0; i < n; i++) rows[i] = rows_vec[i];
}

const std::string &PatternAddressMapper::get_instance_id() const {
  return instance_id;
}

std::string &PatternAddressMapper::get_instance_id() {
  return instance_id;
}

const std::unordered_set<volatile char *> & PatternAddressMapper::get_victim_rows() const {
  return victim_rows;
}

std::vector<volatile char *> PatternAddressMapper::get_random_nonaccessed_rows(int row_upper_bound) {
  (void)row_upper_bound;

  std::vector<volatile char *> addresses;
  addresses.reserve(1024);

  if (decoded_row_to_va.empty()) {
    Logger::log_error("[PatternAddressMapper] get_random_nonaccessed_rows() called but no decoded pool is available.");
    return addresses;
  }

  // Build a set of addresses to avoid (aggressors + victims).
  std::unordered_set<volatile char *> avoid;
  avoid.reserve(aggressor_to_addr.size() + victim_rows.size());

  for (const auto &kv : aggressor_to_addr) {
    avoid.insert(static_cast<volatile char *>(kv.second.get_virt()));
  }
  for (auto *v : victim_rows) {
    avoid.insert(v);
  }

  // Sample random pages from the decoded pool.
  std::vector<volatile char *> pool;
  pool.reserve(decoded_row_to_va.size());
  for (const auto &kv : decoded_row_to_va) {
    pool.push_back(kv.second);
  }

  if (pool.empty()) return addresses;

  std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);

  // We don't mind duplicates, but try to avoid aggressor/victim rows.
  for (int i = 0; i < 1024; ++i) {
    volatile char *va = pool[dist(gen)];
    for (int t = 0; t < 8 && avoid.count(va) > 0; ++t) {
      va = pool[dist(gen)];
    }
    addresses.push_back(va);
  }

  return addresses;
}

void PatternAddressMapper::determine_victims(const std::vector<AggressorAccessPattern> &agg_access_patterns) {
  // check ROW_THRESHOLD rows around the aggressors for flipped bits
  const int ROW_THRESHOLD = 5;

  if (decoded_row_to_va.empty() || decoded_bank_to_rows.empty()) {
    Logger::log_error("[PatternAddressMapper] determine_victims() called without a decoded address pool.");
    std::abort();
  }

  auto pack_bank = [](int chan, int rank, int bg, int bank) -> uint64_t {
    return (uint64_t)(chan & 0xff) << 24 |
           (uint64_t)(rank & 0xff) << 16 |
           (uint64_t)(bg   & 0xff) << 8  |
           (uint64_t)(bank & 0xff);
  };

  victim_rows.clear();

  for (auto &acc_pattern : agg_access_patterns) {
    for (auto &agg : acc_pattern.aggressors) {
      const auto &a = aggressor_to_addr.at(agg.id);

      const int bank = (int)(a.bank & 0x3);
      const uint64_t bk = pack_bank(a.channel, a.rank, a.bank_group, bank);

      for (int d = -ROW_THRESHOLD; d <= ROW_THRESHOLD; ++d) {
        if (d == 0) continue;
        const int rr = (int)a.row + d;
        if (rr < 0) continue;

        const uint64_t rk = (bk << 32) | (uint32_t)rr;
        auto it = decoded_row_to_va.find(rk);
        if (it != decoded_row_to_va.end()) {
          victim_rows.insert(it->second);
        }
      }
    }
  }
}

std::string PatternAddressMapper::get_mapping_text_repr() {
  std::stringstream ss;
  ss << "Mapping " << instance_id << "\n";
  ss << "Aggressors:\n";
  for (auto &kv : aggressor_to_addr) {
    ss << "  id=" << kv.first << " " << kv.second.to_string_compact() << "\n";
  }
  ss << "Victims:\n";
  for (auto *v : victim_rows) {
    ss << "  " << (void *)v << "\n";
  }
  return ss.str();
}

CodeJitter & PatternAddressMapper::get_code_jitter() const {
  return *code_jitter;
}

void PatternAddressMapper::compute_mapping_stats(std::vector<AggressorAccessPattern> &agg_access_patterns,
                                                int &agg_intra_distance,
                                                int &agg_inter_distance,
                                                bool uses_seq_addresses) {
  (void)uses_seq_addresses;

  // Compute intra/inter distances based on actual decoded rows (best-effort).
  // If mapping is empty, return zeros.
  agg_intra_distance = 0;
  agg_inter_distance = 0;

  std::vector<int> rows;
  rows.reserve(aggressor_to_addr.size());

  for (auto &acc_pattern : agg_access_patterns) {
    for (auto &agg : acc_pattern.aggressors) {
      if (aggressor_to_addr.count(agg.id) == 0) continue;
      rows.push_back((int)aggressor_to_addr.at(agg.id).row);
    }
  }

  if (rows.size() < 2) return;

  std::sort(rows.begin(), rows.end());

  int min_gap = INT32_MAX;
  for (size_t i = 1; i < rows.size(); i++) {
    min_gap = std::min(min_gap, rows[i] - rows[i - 1]);
  }
  if (min_gap != INT32_MAX) agg_intra_distance = min_gap;

  agg_inter_distance = rows.back() - rows.front();
}

void PatternAddressMapper::shift_mapping(int rows, const std::unordered_set<AggressorAccessPattern> &aggs_to_move) {
  (void)rows;
  (void)aggs_to_move;

  // Kernel-only: shifting requires finding alternative decoded rows for the same bank key.
  // This project-specific policy is better handled at the caller / fuzzing level.
  Logger::log_error("[PatternAddressMapper] shift_mapping() is not supported in kernel-only mode.");
  std::abort();
}

size_t PatternAddressMapper::count_bitflips() const {
  size_t sum = 0;
  for (const auto &v : bit_flips) sum += v.size();
  return sum;
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p) {
  j = nlohmann::json{
      {"instance_id", p.get_instance_id()},
      {"reproducibility_score", p.reproducibility_score}
  };
}

void from_json(const nlohmann::json &j, PatternAddressMapper &p) {
  j.at("instance_id").get_to(p.get_instance_id());
  j.at("reproducibility_score").get_to(p.reproducibility_score);
}

#endif

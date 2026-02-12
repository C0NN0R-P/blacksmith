#include "Forges/ReplayingHammerer.hpp"

#include <Fuzzer/PatternBuilder.hpp>
#include <Fuzzer/FuzzingParameterSet.hpp>
#include <algorithm>
#include <chrono>
#include <numeric>

#include "Forges/FuzzyHammerer.hpp"

#ifdef ENABLE_JSON
#include <Blacksmith.hpp>
#include <Utilities/TimeHelper.hpp>
#endif

#define M(VAL) (VAL##000000)

// initialize static variable
double ReplayingHammerer::last_reproducibility_score = 0;

PatternAddressMapper::PatternAddressMapper(const PatternAddressMapper& other) {
  // TODO: copy constructor does not exist in the original program due to copying unique pointers.
  //  In this context, we need it to copy the mapping in determine_most_effective_mapping.

  // std::string is copied
  instance_id = other.instance_id;

  // std::mt19937 is copied
  gen = other.gen;

  // set new unique_ptr to new CodeJitter
  code_jitter = std::make_unique<CodeJitter>();

  // copy simple fields
  min_row = other.min_row;
  max_row = other.max_row;
  bank_no = other.bank_no;

  // copy maps/sets/vectors
  aggressor_to_addr = other.aggressor_to_addr;
  victim_rows = other.victim_rows;
  bit_flips = other.bit_flips;
  reproducibility_score = other.reproducibility_score;
}

ReplayingHammerer::ReplayingHammerer(Memory &mem) : mem(mem) {
  std::random_device rd;
  gen = std::mt19937(rd());
}

void ReplayingHammerer::set_params(const FuzzingParameterSet &fuzzParams) {
  params = fuzzParams;
}

void ReplayingHammerer::replay_patterns(const std::string& json_filename,
                                        const std::unordered_set<std::string> &pattern_ids) {
  auto patterns = load_patterns_from_json(json_filename, pattern_ids);

  int pattern_index = 1;
  for (auto &pattern : patterns) {
    Logger::log_highlight(format_string("Replaying pattern %s (%d/%d)",
        pattern.instance_id.c_str(), pattern_index++, patterns.size()));
    Logger::log_timestamp();

    // Determine which mapping to use
    auto &mapper = determine_most_effective_mapping(pattern, true, false);
    derive_FuzzingParameterSet_values(pattern, mapper);

    // Load code jitter settings from the mapping
    CodeJitter &jitter = mapper.get_code_jitter();

    // Hammer
    hammer_pattern(params, jitter, pattern, mapper, jitter.flushing_strategy, jitter.fencing_strategy,
                   jitter.hammering_repetitions, jitter.num_aggs_for_sync, jitter.total_activations,
                   false, jitter.pattern_sync_each_ref, false, false, false, false, false, true);
  }
}

size_t ReplayingHammerer::replay_patterns_brief(const std::string& json_filename,
                                                const std::unordered_set<std::string> &pattern_ids, size_t sweep_bytes,
                                                bool running_on_original_dimm) {
  auto patterns = load_patterns_from_json(json_filename, pattern_ids);
  return replay_patterns_brief(patterns, sweep_bytes, 1, running_on_original_dimm);
}

size_t ReplayingHammerer::replay_patterns_brief(std::vector<HammeringPattern> hammering_patterns,
                                                size_t sweep_bytes,
                                                size_t num_locations,
                                                bool running_on_original_dimm) {
#ifdef ENABLE_JSON
  nlohmann::json runs;
  auto start = std::chrono::system_clock::now();
#endif

  size_t bitflips_count = 0;

  int pattern_index = 1;
  for (auto &pattern : hammering_patterns) {
    // If we're just sweeping, we don't care too much about the address mapping.
    // Instead of selecting the most effective mapping, simply select the first.
    hammering_num_reps = 10;

    // check the HammeringPattern's data for the most effective pattern instead of rerunning
    PatternAddressMapper &mapper = (running_on_original_dimm)
        ? pattern.get_most_effective_mapping()
        : determine_most_effective_mapping(pattern, false, false);

    Logger::log_highlight(
        format_string("Sweeping pattern %s (%d/%d) using mapping %s",
            pattern.instance_id.c_str(), pattern_index++,
            hammering_patterns.size(), mapper.get_instance_id().c_str()));
    Logger::log_timestamp();

    // this is important to fill up the FuzzingParameterSet with the correct values as this object is not exported 1:1
    // as object in the JSON file
    derive_FuzzingParameterSet_values(pattern, mapper);

    std::unordered_set<AggressorAccessPattern> direct_effective_aggs;
    if (pattern.is_location_dependent) {
      find_direct_effective_aggs(pattern, mapper, direct_effective_aggs);
    }

    for (size_t i = 0; i < num_locations; ++i) {
      // do the sweep
      struct SweepSummary summary = sweep_pattern(pattern, mapper, 10, sweep_bytes, direct_effective_aggs);
      bitflips_count += summary.observed_bitflips.size();

      // save the data about the sweep
#ifdef ENABLE_JSON
      nlohmann::json entry;
      entry["pattern"] = pattern.instance_id;
      entry["mapping"] = mapper.get_instance_id();

      nlohmann::json flips;
      flips["zero_to_one"] = summary.num_flips_z2o;
      flips["one_to_zero"] = summary.num_flips_o2z;
      flips["total"] = summary.num_flips_z2o + summary.num_flips_o2z;
      flips["details"] = summary.observed_bitflips;
      entry["flips"] = flips;

      runs.push_back(entry);
#endif

      if (i + 1 < num_locations) {
        // move pattern to another location and then continue sweeping from there (we don't do this at the beginning of
        // the for loop because we want to include the sweep that starts at the start location of the best mapping
        mapper.randomize_addresses(mem, params, pattern.agg_access_patterns, false);
      }
    }
  }
  Logger::log_timestamp();

#ifdef ENABLE_JSON
  auto end = std::chrono::system_clock::now();

  nlohmann::json meta;
  meta["start"] = std::chrono::duration_cast<std::chrono::seconds>(start.time_since_epoch()).count();
  meta["end"] = std::chrono::duration_cast<std::chrono::seconds>(end.time_since_epoch()).count();
  meta["num_patterns"] = hammering_patterns.size();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;

  nlohmann::json root;
  root["metadata"] = meta;
  root["sweeps"] = runs;

  std::ostringstream filename;
  filename << "sweep-summary-" << num_locations << "x" << sweep_bytes/1024/1024 << "MB.json";
  std::ofstream stream(filename.str());
  stream << root << std::endl;
  stream.close();
#endif

  return bitflips_count;
}

std::vector<HammeringPattern> ReplayingHammerer::load_patterns_from_json(const std::string& json_filename,
                                                        const std::unordered_set<std::string> &pattern_ids) {
#ifdef ENABLE_JSON
  Logger::log_info("Loading patterns from JSON file.");

  std::ifstream file(json_filename);
  if (!file.is_open()) {
    Logger::log_error("Could not open JSON file.");
    std::exit(EXIT_FAILURE);
  }

  nlohmann::json j;
  file >> j;

  std::vector<HammeringPattern> patterns;

  for (const auto &pattern_json : j["patterns"]) {
    HammeringPattern pattern = pattern_json.get<HammeringPattern>();

    if (!pattern_ids.empty() && pattern_ids.find(pattern.instance_id) == pattern_ids.end()) {
      continue;
    }

    // build mapping index for later lookup
    for (auto &mapping : pattern.mappings) {
      map_mapping_id_to_pattern[mapping.get_instance_id()] = pattern;
    }

    patterns.push_back(std::move(pattern));
  }

  Logger::log_info(format_string("Loaded %zu patterns.", patterns.size()));
  return patterns;
#else
  (void) json_filename;
  (void) pattern_ids;
  Logger::log_error("ENABLE_JSON is not enabled; cannot load patterns from JSON.");
  std::abort();
#endif
}

PatternAddressMapper &ReplayingHammerer::determine_most_effective_mapping(HammeringPattern &patt,
                                                                         bool optimize_hammering_num_reps,
                                                                         bool offline_mode) {
  // if hammeringPattern is not location dependent, just take the best mapping
  if (!patt.is_location_dependent) {
    return patt.get_most_effective_mapping();
  }

  // Otherwise, test all mappings by replaying them and selecting the best one at this location.
  size_t max_num_bitflips = 0;
  PatternAddressMapper *best_mapping = nullptr;

  // We might need to adjust hammering repetitions if optimization is enabled.
  if (optimize_hammering_num_reps) {
    hammering_num_reps = initial_hammering_num_reps;
  }

  for (auto &mapper : patt.mappings) {
    derive_FuzzingParameterSet_values(patt, mapper);

    CodeJitter &jitter = mapper.get_code_jitter();

    if (offline_mode) {
      // In offline mode, we don't hammer; just accept stored value
      size_t observed = mapper.count_bitflips();
      if (observed > max_num_bitflips) {
        max_num_bitflips = observed;
        best_mapping = &mapper;
      }
      continue;
    }

    size_t num_bitflips = hammer_pattern(params, jitter, patt, mapper,
                                         jitter.flushing_strategy, jitter.fencing_strategy,
                                         jitter.hammering_repetitions, jitter.num_aggs_for_sync,
                                         jitter.total_activations, false, jitter.pattern_sync_each_ref,
                                         false, false, false, false, false, true);

    if (num_bitflips > max_num_bitflips) {
      max_num_bitflips = num_bitflips;
      best_mapping = &mapper;
    }
  }

  if (best_mapping == nullptr) {
    Logger::log_error("[ReplayingHammerer] Could not determine best mapping.");
    std::abort();
  }

  // Optionally learn a smaller hammering repetition count.
  if (optimize_hammering_num_reps) {
    // if we found flips, we can try reducing repetitions later; otherwise keep as-is
    last_reproducibility_score = best_mapping->reproducibility_score;
  }

  return *best_mapping;
}

size_t ReplayingHammerer::hammer_pattern(FuzzingParameterSet &fuzz_params,
                                        CodeJitter &code_jitter,
                                        HammeringPattern &pattern,
                                        PatternAddressMapper &mapper,
                                        FLUSHING_STRATEGY flushing_strategy,
                                        FENCING_STRATEGY fencing_strategy,
                                        unsigned long num_reps,
                                        int aggressors_for_sync,
                                        int num_activations,
                                        bool early_stopping,
                                        bool sync_each_ref,
                                        bool verbose_sync,
                                        bool verbose_memcheck,
                                        bool verbose_params,
                                        bool wait_before_hammering,
                                        bool check_flips_after_each_rep) {
  (void) verbose_params;

  // export aggressors from mapping
  std::vector<volatile char *> aggressor_addrs;
  for (auto &aap : pattern.agg_access_patterns) {
    std::vector<volatile char *> addrs;
    mapper.export_pattern(aap.aggressors, code_jitter.base_period, addrs);
    aggressor_addrs.insert(aggressor_addrs.end(), addrs.begin(), addrs.end());
  }

  if (wait_before_hammering) {
    Logger::log_info("Waiting 1s before hammering.");
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  size_t num_bitflips_total = 0;

  for (unsigned long rep = 0; rep < num_reps; ++rep) {
    if (early_stopping && rep > 0 && num_bitflips_total > 0) {
      break;
    }

    // hammer all patterns
    size_t num_bitflips_this_rep = 0;
    for (auto &patt : pattern.agg_access_patterns) {
      // hammer pattern
      num_bitflips_this_rep += ReplayingHammerer::hammer_pattern(fuzz_params, code_jitter, patt, mapper,
          flushing_strategy, fencing_strategy, 1, aggressors_for_sync,
          num_activations, false,
          sync_each_ref, verbose_sync, verbose_memcheck, false,
          false, check_flips_after_each_rep);
    }

    num_bitflips_total += num_bitflips_this_rep;
  }

  return num_bitflips_total;
}

size_t ReplayingHammerer::hammer_pattern(FuzzingParameterSet &fuzz_params,
                                        CodeJitter &code_jitter,
                                        AggressorAccessPattern &patt,
                                        PatternAddressMapper &mapper,
                                        FLUSHING_STRATEGY flushing_strategy,
                                        FENCING_STRATEGY fencing_strategy,
                                        unsigned long num_reps,
                                        int aggressors_for_sync,
                                        int num_activations,
                                        bool early_stopping,
                                        bool sync_each_ref,
                                        bool verbose_sync,
                                        bool verbose_memcheck,
                                        bool verbose_params,
                                        bool wait_before_hammering,
                                        bool check_flips_after_each_rep) {
  (void) wait_before_hammering;
  (void) verbose_params;

  // If this AggressorAccessPattern is location dependent, we re-randomize the mapping here.
  // NOTE: This is the location dependent re-mapping case: the mapping gets invalidated when the
  // aggressor list is changed (e.g. frequency-based probing). That is why we always call the
  // memory-based overload.
  if (patt.is_location_dependent) {
    mapper.randomize_addresses(mem, params, patt.agg_access_patterns, false);
  }

  // export aggressors from mapping
  std::vector<volatile char *> aggressor_addrs;
  mapper.export_pattern(patt.aggressors, code_jitter.base_period, aggressor_addrs);

  // prepare aggressor synchronization if enabled
  if (sync_each_ref) {
    mapper.sync_aggressor_access_pattern(patt, aggressor_addrs, aggressors_for_sync);
  }

  size_t num_bitflips_total = 0;

  for (unsigned long rep = 0; rep < num_reps; ++rep) {
    if (early_stopping && rep > 0 && num_bitflips_total > 0) {
      break;
    }

    // hammer the addresses for this aggressor access pattern
    ReplayingHammerer::hammer(patt, aggressor_addrs, num_activations,
                              flushing_strategy, fencing_strategy,
                              code_jitter, verbose_sync);

    // check for flips
    if (check_flips_after_each_rep || rep + 1 == num_reps) {
      num_bitflips_total += mem.check_memory(mapper, false, verbose_memcheck);
    }
  }

  return num_bitflips_total;
}

void ReplayingHammerer::hammer(AggressorAccessPattern &patt,
                               std::vector<volatile char *> &aggressor_addrs,
                               int num_activations,
                               FLUSHING_STRATEGY flushing_strategy,
                               FENCING_STRATEGY fencing_strategy,
                               CodeJitter &code_jitter,
                               bool verbose_sync) {
  // This function is unchanged; it performs the actual hammering work.

  // generate the custom hammering function (code jitter)
  auto hammer_func = code_jitter.jit_hammer(patt, aggressor_addrs, flushing_strategy, fencing_strategy, verbose_sync);

  // call the hammering function
  hammer_func(num_activations);
}

struct SweepSummary ReplayingHammerer::sweep_pattern(HammeringPattern &pattern,
                                                     PatternAddressMapper &mapper,
                                                     unsigned long num_reps,
                                                     size_t sweep_bytes,
                                                     std::unordered_set<AggressorAccessPattern> &direct_effective_aggs) {
  struct SweepSummary summary;

  // 1) Hammer the pattern once at this location
  derive_FuzzingParameterSet_values(pattern, mapper);
  CodeJitter &jitter = mapper.get_code_jitter();

  // hammer
  auto num_bitflips = ReplayingHammerer::hammer_pattern(params, jitter, pattern, mapper,
      jitter.flushing_strategy, jitter.fencing_strategy,
      num_reps, jitter.num_aggs_for_sync,
      jitter.total_activations, false,
      jitter.pattern_sync_each_ref, false, false, false,
      false, false, true);

  if (num_bitflips == 0) {
    Logger::log_failure("No bit flips found.");
  } else {
    Logger::log_success(format_string("Found %lu bit flips.", num_bitflips));
  }

  // 2) Determine sweep location
  std::uniform_int_distribution<size_t> dist(0, sweep_bytes - 1);

  // shift aggressors randomly inside sweep region
  size_t sweep_offset = dist(gen);
  Logger::log_info(format_string("Sweep offset: %zu bytes.", sweep_offset));

  // 3) Execute sweep (move the pattern by sweep_offset)
  if (pattern.is_location_dependent) {
    // For location dependent patterns, we need to preserve direct effective aggs.
    if (!direct_effective_aggs.empty()) {
      mapper.shift_mapping((int)(sweep_offset / getpagesize()), direct_effective_aggs);
    } else {
      mapper.shift_mapping((int)(sweep_offset / getpagesize()), {});
    }
  }

  // 4) Re-hammer at the new location
  num_bitflips = ReplayingHammerer::hammer_pattern(params, jitter, pattern, mapper,
      jitter.flushing_strategy, jitter.fencing_strategy,
      num_reps, jitter.num_aggs_for_sync,
      jitter.total_activations, false,
      jitter.pattern_sync_each_ref, false, false, false,
      false, false, true);

  // gather results
  summary.observed_bitflips = mapper.get_found_bitflips();

  summary.num_flips_z2o = 0;
  summary.num_flips_o2z = 0;
  for (const auto &bf : summary.observed_bitflips) {
    if (bf.before == 0 && bf.after == 1) summary.num_flips_z2o++;
    if (bf.before == 1 && bf.after == 0) summary.num_flips_o2z++;
  }

  return summary;
}

void ReplayingHammerer::find_direct_effective_aggs(HammeringPattern &pattern,
                                                   PatternAddressMapper &mapper,
                                                   std::unordered_set<AggressorAccessPattern> &direct_effective_aggs) {
  // determine direct effective aggressor access patterns for location dependent patterns
  for (auto &aap : pattern.agg_access_patterns) {
    for (auto &agg : aap.aggressors) {
      if (mapper.get_num_bitflips(agg.id) > 0) {
        direct_effective_aggs.insert(aap);
        break;
      }
    }
  }
}

void ReplayingHammerer::derive_FuzzingParameterSet_values(HammeringPattern &pattern,
                                                         PatternAddressMapper &mapper) {
  // derive values for fuzzing parameter set from the HammeringPattern and PatternAddressMapper
  params.set_random_bank_no(mapper.bank_no);
  params.set_random_start_row((int)mapper.min_row);
  params.set_random_end_row((int)mapper.max_row);
  params.set_random_agg_intra_distance(pattern.agg_intra_distance);
  params.set_random_agg_inter_distance(pattern.agg_inter_distance);
  params.set_random_num_aggs(pattern.num_aggressors);
  params.set_random_num_ref(pattern.num_refs);
  params.set_random_use_seq_addresses(pattern.uses_seq_addresses);
}

std::vector<std::string> ReplayingHammerer::get_all_pattern_ids(const std::string& json_filename) {
#ifdef ENABLE_JSON
  std::ifstream file(json_filename);
  if (!file.is_open()) {
    Logger::log_error("Could not open JSON file.");
    std::exit(EXIT_FAILURE);
  }

  nlohmann::json j;
  file >> j;

  std::vector<std::string> ids;
  ids.reserve(j["patterns"].size());

  for (const auto &pattern_json : j["patterns"]) {
    ids.push_back(pattern_json["instance_id"].get<std::string>());
  }

  return ids;
#else
  (void) json_filename;
  Logger::log_error("ENABLE_JSON is not enabled; cannot load pattern IDs.");
  std::abort();
#endif
}

std::vector<HammeringPattern> ReplayingHammerer::load_patterns_from_json(const std::string& json_filename) {
  return load_patterns_from_json(json_filename, {});
}

#ifdef ENABLE_JSON
std::map<std::string, HammeringPattern> ReplayingHammerer::map_mapping_id_to_pattern = {};
#endif

size_t ReplayingHammerer::replay_frequency_based_pattern_append(const std::string &json_filename,
                                                                const std::unordered_set<std::string> &pattern_ids,
                                                                int fpa_probing_num_reps,
                                                                int base_period) {
#ifdef ENABLE_JSON
  auto patterns = load_patterns_from_json(json_filename, pattern_ids);

  size_t total_bitflips = 0;

  int pattern_index = 1;
  for (auto &pattern : patterns) {
    Logger::log_highlight(format_string("Replaying pattern %s (%d/%d)",
        pattern.instance_id.c_str(), pattern_index++, patterns.size()));
    Logger::log_timestamp();

    // Determine which mapping to use
    auto &mapper = determine_most_effective_mapping(pattern, true, false);

    // we need to re-run the frequency based probing to determine which aggs are effective
    // (and then include these in the new pattern)
    if (pattern.uses_seq_addresses) {
      params.set_random_use_seq_addresses(true);
    } else {
      params.set_random_use_seq_addresses(false);
    }
    params.set_random_agg_intra_distance(pattern.agg_intra_distance);
    params.set_random_agg_inter_distance(pattern.agg_inter_distance);
    params.set_random_num_aggs(pattern.num_aggressors);
    params.set_random_num_ref(pattern.num_refs);
    params.set_random_start_row((int)mapper.min_row);
    params.set_random_end_row((int)mapper.max_row);
    params.set_random_bank_no(mapper.bank_no);

    // 1) find direct effective AggressorAccessPatterns
    std::unordered_set<AggressorAccessPattern> direct_effective_aggs;
    if (pattern.is_location_dependent) {
      find_direct_effective_aggs(pattern, mapper, direct_effective_aggs);
    }

    // 2) append new aggs based on frequency-based probing
    for (auto &patt : direct_effective_aggs) {
      Logger::log_highlight("Probing new aggressors using frequency-based probing.");

      CodeJitter &jitter = mapper.get_code_jitter();

      // We are appending new aggressors to this direct effective AggressorAccessPattern.
      // If this happens, the old aggressor id -> address mapping becomes invalid, so we
      // must regenerate it (and in the kernel-only setup that means using the overload
      // that takes the Memory&).
      PatternBuilder builder(patt);
      auto &aggs = patt.aggressors;

      // prefill with existing aggressors
      builder.prefill_pattern(patt.total_activations, aggs);

      // NOTE: We don't include the FuzzingParameterSet that found the HammeringPattern in the JSON yet, so
      //  passing a new FuzzingParameterSet instance 'params' here could actually break things, e.g., if
      //  parameter ranges are too narrow and we cannot fill up the remaining slots
      builder.generate_frequency_based_pattern(params, patt.total_activations, patt.base_period);

      // as we changed the AggressorAccessPattern, the existing Agg ID -> DRAM Address mapping is not valid
      // anymore and we need to generate a new mapping
      // TODO: Maybe we should randomize fpa_probing_num_reps times to be sure that it just doesn't work because
      //  we are hammering at a unfavourable location? Alternatively, we could let the direct effective
      //  AggressorAccessPatterntarget always a target known-to-be vulnerable row so we can be sure that if we
      //  don't see any bit flips, it's not because of a bad location
      mapper.randomize_addresses(mem, params, patt.agg_access_patterns, false);
      auto num_bitflips = ReplayingHammerer::hammer_pattern(params, jitter, patt, mapper,
          jitter.flushing_strategy, jitter.fencing_strategy, fpa_probing_num_reps, jitter.num_aggs_for_sync,
          jitter.total_activations, false,
          jitter.pattern_sync_each_ref, false, false, false, true, true);
      if (num_bitflips==0) {
        Logger::log_failure("No bit flips found.");
      } else {
        Logger::log_success(format_string(
            "Found %lu bit flips, on average %2.f per hammering rep (%d). Flipped row(s): %s.",
            num_bitflips,
            static_cast<float>(num_bitflips)/static_cast<float>(fpa_probing_num_reps),
            fpa_probing_num_reps,
            patt.get_flipped_rows().c_str()));
      }

      // append to HammeringPattern and mappings
      if (base_period != -1) {
        patt.base_period = base_period;
      }

      // update pattern's aggressor access patterns
      for (auto &aap : pattern.agg_access_patterns) {
        if (aap.instance_id == patt.instance_id) {
          aap = patt;
          break;
        }
      }

      // we keep the mapping that found the flips but update its id
      mapper.instance_id = uuid::gen_uuid();
      pattern.mappings.push_back(mapper);

      // update pattern's base period if specified
      if (base_period != -1) {
        pattern.base_period = base_period;
      }

      // update pattern's frequency-based probing repetitions
      pattern.fpa_probing_num_reps = fpa_probing_num_reps;
    }

    // 3) export and append pattern to JSON
    append_pattern_to_json(json_filename, pattern);
    total_bitflips += mapper.count_bitflips();
  }

  return total_bitflips;
#else
  (void) json_filename;
  (void) pattern_ids;
  (void) fpa_probing_num_reps;
  (void) base_period;
  Logger::log_error("ENABLE_JSON is not enabled; cannot replay and append patterns.");
  std::abort();
#endif
}

#ifdef ENABLE_JSON
void ReplayingHammerer::append_pattern_to_json(const std::string &json_filename, HammeringPattern &pattern) {
  // Load existing JSON
  std::ifstream file(json_filename);
  if (!file.is_open()) {
    Logger::log_error("Could not open JSON file for reading.");
    std::abort();
  }

  nlohmann::json j;
  file >> j;
  file.close();

  // Append pattern
  j["patterns"].push_back(pattern);

  // Save JSON
  std::ofstream out(json_filename);
  if (!out.is_open()) {
    Logger::log_error("Could not open JSON file for writing.");
    std::abort();
  }

  out << j.dump(2) << std::endl;
  out.close();
}
#endif

/*
 * Copyright (c) 2026.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_DEBUG_HPP_
#define BLACKSMITH_INCLUDE_DEBUG_HPP_

#include <chrono>
#include <cstdint>
#include <sstream>
#include <thread>

#include "Utilities/Logger.hpp"

// Debug logging helpers.
//
// Usage:
//   BS_DLOG("message");
//   BS_DLOGF("x=%d", x);
//   BS_TRACE_SCOPE();
//   BS_TRACE_SCOPE_NAMED("my_scope");

namespace bs_debug {
inline uint64_t now_ns_monotonic() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline uint64_t tid_u64() {
  // std::thread::id is not guaranteed numeric; hash is stable within process.
  return static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

inline std::string prefix(const char *file, int line, const char *func) {
  std::stringstream ss;
  ss << "ts_ns=" << now_ns_monotonic() << " tid=" << tid_u64() << " "
     << file << ":" << line << " " << func << "()";
  return ss.str();
}

class ScopeTrace {
 public:
  ScopeTrace(const char *name, const char *file, int line, const char *func)
      : name_(name), file_(file), line_(line), func_(func), start_ns_(now_ns_monotonic()) {
    Logger::log_debug(prefix(file_, line_, func_) + " ENTER " + name_);
  }

  ~ScopeTrace() {
    const uint64_t end_ns = now_ns_monotonic();
    std::stringstream ss;
    ss << prefix(file_, line_, func_) << " EXIT " << name_ << " duration_ns=" << (end_ns - start_ns_);
    Logger::log_debug(ss.str());
  }

  ScopeTrace(const ScopeTrace &) = delete;
  ScopeTrace &operator=(const ScopeTrace &) = delete;

 private:
  const char *name_;
  const char *file_;
  int line_;
  const char *func_;
  uint64_t start_ns_;
};
}  // namespace bs_debug

#define BS_DLOG(MSG) \
  do { \
    Logger::log_debug(bs_debug::prefix(__FILE__, __LINE__, __func__) + std::string(" | ") + (MSG)); \
  } while (0)

#define BS_DLOGF(FMT, ...) \
  do { \
    Logger::log_debug(bs_debug::prefix(__FILE__, __LINE__, __func__) + std::string(" | ") + format_string((FMT), __VA_ARGS__)); \
  } while (0)

#define BS_TRACE_SCOPE() bs_debug::ScopeTrace bs_scope_trace(__func__, __FILE__, __LINE__, __func__)
#define BS_TRACE_SCOPE_NAMED(NAME) bs_debug::ScopeTrace bs_scope_trace(NAME, __FILE__, __LINE__, __func__)

#endif  // BLACKSMITH_INCLUDE_DEBUG_HPP_

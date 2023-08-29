#ifndef LLDB_INCLUDE_C3_C3_LLVM_H
#define LLDB_INCLUDE_C3_C3_LLVM_H

#include "c3/crypto/cc_encoding.h"
#include "c3/malloc/cc_globals.h"

#include <iomanip>
#include <sstream>
#include <string>

#define C3_DEBUGGING_SUPPORT

// #define C3_DEBUG
#ifdef C3_DEBUG
#define dbgprint(f, ...)                                                       \
  fprintf(stderr, "(%s:%d) %s: " f "\n", __FILE__, __LINE__, __func__,         \
          ##__VA_ARGS__)
#else
#define dbgprint(f, ...)
#endif

static constexpr size_t c3_ptr_key_size = KEY_SIZE(CC_POINTER_CIPHER);
static constexpr size_t c3_data_key_size = KEY_SIZE(CC_DATA_CIPHER);

static inline std::string buf_to_hex_string(const uint8_t *buf, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
      ss << std::setw(2) << std::setfill('0') << std::hex
         << static_cast<int>(buf[i]);
    }
    return ss.str();
}

/**
 * @brief
 *
 * @param buf key buffer
 * @param chars string
 * @param len length of string
 */
static inline void string_to_hex_buf(uint8_t *buf, const char *chars,
                                     size_t len) {
  const std::string str = chars;

  for (size_t i = 0; i < len; i += 2) {
    buf[i / 2] = (uint8_t)strtol(str.substr(i, 2).c_str(), NULL, 16);
  }
}

static inline uint64_t hex_string_to_uint64(const char *str) {
  uint64_t num;
  std::stringstream ss;
  ss << std::hex << str;
  ss >> num;
  return num;
}

#endif // LLDB_INCLUDE_C3_C3_LLVM_H

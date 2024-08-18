//===-- hex_string.h ------------------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef C3_HEX_STRING_H
#define C3_HEX_STRING_H

#include <iomanip>
#include <sstream>
#include <string>

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

#endif // C3_C3_LLVM_H
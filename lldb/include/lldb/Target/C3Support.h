//===-- C3Support.h -------------------------------------------------------===//
//
// Copyright (C) 2023 Intel Corporation
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef LLDB_TARGET_C3SUPPORT_H
#define LLDB_TARGET_C3SUPPORT_H

#include <memory>

#include "c3/llvm_c3_cc_encoding.h"
#include "c3/llvm_c3_cc_globals.h"
#include <lldb/Utility/DataExtractor.h>

class CCDataEncryption;

namespace c3_lldb {

class c3_lldbPointerEncoder;

class C3Support {
public:
  static constexpr size_t c3_ptr_key_size = C3_KEY_SIZE(CC_POINTER_CIPHER);
  static constexpr size_t c3_data_key_size = C3_KEY_SIZE(CC_DATA_CIPHER);

  static constexpr uint64_t bad_ca = UINT64_MAX;

  C3Support() = delete;
  C3Support(lldb_private::Thread *thread);
  ~C3Support();

  void ReadElfCoreNote(const lldb_private::DataExtractor *data);

  const uint8_t *get_data_key() const { return (const uint8_t *)&c3_data_key; }
  const uint8_t *get_ptr_key() const { return (const uint8_t *)&c3_ptr_key; }

  const std::string get_data_key_str() const;
  const std::string get_ptr_key_str() const;

  void set_data_key(const uint8_t *key);
  void set_ptr_key(const uint8_t *key);

  uint64_t decode_ptr(uint64_t ptr);
  uint64_t decode_ptr_if_ca(const uint64_t ptr);

  uint64_t encode_ptr(const uint64_t ptr, const uint64_t size,
                      const uint64_t version);

  bool encrypt_decrypt_bytes(const uint64_t ca, uint8_t *buf, size_t len);

  const struct cc_context *get_ctx() const { return &ctx; }

  void log(const char *fmt, ...);

  uint64_t find_ca(uint64_t la);

private:
  lldb_private::Thread *thread;

  uint8_t c3_ptr_key[c3_ptr_key_size];
  uint8_t c3_data_key[c3_data_key_size];

  struct cc_context ctx;

  std::shared_ptr<c3_lldbPointerEncoder> ptrenc;
  std::shared_ptr<CCDataEncryption> dataenc;

  uint64_t rlimit_stack_cur = 0;

  std::pair<uint64_t, uint64_t> stack_range;

  void init_stack_range(const uint64_t stack_size);

  bool is_in_stack_range(const uint64_t la);

  uint64_t get_stack_pointer(const uint64_t la);
};

} // namespace c3_lldb

#endif // LLDB_TARGET_C3SUPPORT_H

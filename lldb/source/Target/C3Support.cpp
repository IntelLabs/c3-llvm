//===-- C3Support.cpp -----------------------------------------------------===//
//
// Copyright (C) 2023 Intel Corporation
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#include "lldb/Target/C3Support.h"

#include "lldb/Target/C3LldbCon.h"
#include "lldb/Target/C3LldbCtx.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/SystemRuntime.h"
#include "lldb/Target/Thread.h"
#include "lldb/Utility/LLDBAssert.h"
#include "lldb/Utility/LLDBLog.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/VASPrintf.h"

#include <algorithm>
#include <lldb/Utility/DataExtractor.h>
#include <llvm/Support/ErrorHandling.h>
#include <memory>

#include "c3/hex_string.h"
#include "c3/llvm_c3_cc_encoding.h"
#include "c3/llvm_c3_cc_globals.h"

using namespace lldb_private;

// This directly includes crypto sources to compile them into C3Support.o.
#define C3_CRYPTO_CPP_INCLUDE_CPP
#include "c3/llvm_c3_crypto_cpp.h"
#undef C3_CRYPTO_CPP_INCLUDE_CPP

namespace c3_lldb {

static constexpr size_t c3_ptr_key_size = C3_KEY_SIZE(CC_POINTER_CIPHER);
static constexpr size_t c3_data_key_size = C3_KEY_SIZE(CC_DATA_CIPHER);

static inline bool is_in_range(const std::pair<uint64_t, uint64_t> &range,
                               uint64_t ptr) {
  return (range.first <= ptr && ptr < range.second);
}

class C3Support;

#define POINTER_ENCODER_BASE_TYPE CCPointerEncodingBase

using PointerEncoderBase = POINTER_ENCODER_BASE_TYPE;

class c3_lldbPointerEncoder final : public PointerEncoderBase {
public:
  c3_lldbPointerEncoder(C3Support *c3, C3LldbCon *, C3LldbCtx *)
      : c3(c3), con(nullptr), ctx(nullptr) {}

  static std::shared_ptr<c3_lldbPointerEncoder> create(C3Support *c3) {
    return std::make_shared<c3_lldbPointerEncoder>(c3, new C3LldbCon(c3),
                                                   new C3LldbCtx(c3));
  }

  ~c3_lldbPointerEncoder() {
    if (con != nullptr)
      delete con;
    if (ctx != nullptr)
      delete ctx;
  }

  uint64_t decode_pointer(uint64_t ptr) final {
    const uint64_t decoded_ptr = PointerEncoderBase::decode_pointer(ptr);
    return decoded_ptr;
  }

private:
  C3Support *c3;
  C3LldbCon *con;
  C3LldbCtx *ctx;
};

static constexpr uint8_t def_ptr_key[c3_ptr_key_size] = {
    0xd1, 0xbe, 0x2c, 0xdb, 0xb5, 0x82, 0x4d, 0x03, 0x17, 0x5c, 0x25,
    0x2a, 0x20, 0xb6, 0xf2, 0x93, 0xfd, 0x01, 0x96, 0xe7, 0xb5, 0xe6,
    0x88, 0x1c, 0xb3, 0x69, 0x22, 0x60, 0x38, 0x09, 0xf6, 0x68};
static constexpr uint8_t def_data_key[c3_data_key_size] = {
    0xb5, 0x82, 0x4d, 0x03, 0x17, 0x5c, 0x25, 0x2a,
    0xfc, 0x71, 0x1e, 0x01, 0x02, 0x60, 0x87, 0x91};

C3Support::C3Support(lldb_private::Thread *thread)
    : thread(thread), ptrenc(c3_lldbPointerEncoder::create(this)) {
  dataenc = std::make_shared<CCDataEncryption>();
  set_ptr_key(def_ptr_key);
  set_data_key(def_data_key);
  stack_range = std::make_pair(UINT64_MAX, UINT64_MAX);
}

C3Support::~C3Support() {}

void C3Support::ReadElfCoreNote(const lldb_private::DataExtractor *data) {
  log("Loading C3 configuration from ElfCoreNote");
  assert(sizeof(cc_core_info_t) == data->GetByteSize());

  const auto *cc_core =
      reinterpret_cast<const cc_core_info_t *>(data->GetDataStart());

  memcpy(&ctx, &cc_core->cc_context, sizeof(cc_context_t));

  // Extract the keys form the raw context
  set_ptr_key((const uint8_t *)&ctx.addr_key_bytes_);
  set_data_key((const uint8_t *)&ctx.dp_key_bytes_);

  rlimit_stack_cur = (uint64_t)cc_core->stack_rlimit_cur;
}

const std::string C3Support::get_data_key_str() const {
  return buf_to_hex_string(get_data_key(), c3_data_key_size);
}

const std::string C3Support::get_ptr_key_str() const {
  return buf_to_hex_string(get_ptr_key(), c3_ptr_key_size);
}

void C3Support::set_data_key(const uint8_t *key) {
  memcpy(c3_data_key, key, c3_data_key_size);
  dataenc->set_key(c3_data_key);
  log("Setting data key to %s",
      buf_to_hex_string(c3_data_key, c3_data_key_size).c_str());
}

void C3Support::set_ptr_key(const uint8_t *key) {
  memcpy(c3_ptr_key, key, c3_ptr_key_size);
  ptrenc->init_pointer_key(c3_ptr_key, c3_ptr_key_size);
  log("Setting ptr key to %s",
      buf_to_hex_string(c3_ptr_key, c3_ptr_key_size).c_str());
}

uint64_t C3Support::decode_ptr(uint64_t ptr) {
  assert(is_encoded_cc_ptr(ptr));
  uint64_t new_ptr = ptrenc->decode_pointer(ptr);
  log("Decoding CA: 0x%016lx -> 0x%016lx", ptr, new_ptr);
  return new_ptr;
}

uint64_t C3Support::decode_ptr_if_ca(const uint64_t ptr) {
  return is_encoded_cc_ptr(ptr) ? decode_ptr(ptr) : ptr;
}

uint64_t C3Support::encode_ptr(const uint64_t ptr, const uint64_t size,
                               const uint64_t version) {
  assert(!is_encoded_cc_ptr(ptr));

  if (!cc_can_box(ptr, size)) {
    log("Cannot box 0x%016lx to CA-slot of size %ld, skipping pointer encoding",
        ptr, size);
    return ptr;
  }

  ptr_metadata_t md;
  try_box(ptr, size, &md);
  md.version_ = version;

  const uint64_t new_ptr = ptrenc->encode_pointer(ptr, &md);
  log("Encoding LA: 0x%016lx -> 0x%016lx", ptr, new_ptr);
  return new_ptr;
}

bool C3Support::encrypt_decrypt_bytes(const uint64_t ca, uint8_t *buf,
                                      size_t len) {
  if (!is_encoded_cc_ptr(ca)) {
    return false;
  }
  const auto mask = get_tweak_mask(ca);
  const auto masked_addr = mask ^ ca;
  const auto max_size = (1UL + ~mask) - masked_addr;
  const auto bytes_in_ps = std::min(len, max_size);

  auto *tmp_buf = (uint8_t *)malloc(len);
  memcpy(tmp_buf, buf, len);
  dataenc->encrypt_decrypt_bytes(ca, tmp_buf, (uint8_t *)buf, bytes_in_ps);
  log("Decrypted %lu bytes at %p (tweak: 0x%016lx)\n\t\t   %s\n\t\t-> %s",
      bytes_in_ps, (void *)decode_ptr(ca), ca,
      buf_to_hex_string(tmp_buf, bytes_in_ps).c_str(),
      buf_to_hex_string(buf, bytes_in_ps).c_str());

  free(tmp_buf);
  return true;
}

void C3Support::log(const char *fmt, ...) {
  Log *log = GetLog(lldb_private::LLDBLog::C3);
  if (!log)
    return;

  va_list args;
  va_start(args, fmt);

  llvm::SmallString<0> logmsg;
  if (VASprintf(logmsg, fmt, args)) {
    LLDB_LOGF(log, "[C3] %s", logmsg.c_str());
  }
  va_end(args);
}

uint64_t C3Support::find_ca(uint64_t la) {
  if (is_in_stack_range(la)) {
    return get_stack_pointer(la);
  }
  log("find_ca: Cannot determine CA for 0x%016lx", la);
  return UINT64_MAX;
}

void C3Support::init_stack_range(uint64_t stack_size) {
  if (stack_range.first != UINT64_MAX || stack_range.second != UINT64_MAX) {
    log("init_stack_range: Already initialized");
    return;
  }

  // auto *rt = thread->GetProcess()->GetSystemRuntime();

  log("init_stack_range: Finding bottom of stack");
  auto frame = thread->GetStackFrameAtIndex(0);

  Scalar frame_base;
  if (!frame->GetFrameBaseValue(frame_base, nullptr)) {
    log("init_stack_range: failed to get frame base value for frame 0");
    stack_range = std::make_pair(0ULL, 0ULL);
    return;
  }

  uint64_t base = (uint64_t)frame_base.ULongLong();
  if (is_encoded_cc_ptr(base)) {
    log("init_stack_range: base is CA 0x%016lx, decoding", base);
    base = decode_ptr(base);
  }

  log("init_stack_range: base at 0x%016lx, size: 0x%lx", base, stack_size);
  stack_range = std::make_pair(base - stack_size, base); // Stack grows down!
  log("init_stack_range: stack_range set to [0x%016lx, 0x%016lx)",
      stack_range.first, stack_range.second);
  assert(stack_range.first <= stack_range.second);
}

bool C3Support::is_in_stack_range(const uint64_t la) {
  init_stack_range(rlimit_stack_cur);
  if (is_in_range(stack_range, la)) {
    log("is_in_stack_range: 0x%016lx is in stack range [0x%016lx, 0x%016lx)",
        la, stack_range.first, stack_range.second);
    return true;
  }
  log("find_ca: 0x%016lx not in stack range [0x%016lx, 0x%016lx)", la,
      stack_range.first, stack_range.second);
  return false;
}

uint64_t C3Support::get_stack_pointer(const uint64_t la) {
  init_stack_range(rlimit_stack_cur);
  assert(is_in_range(stack_range, la));
  assert(stack_range.second >= stack_range.first);

  // Stack grows down!
  const uint64_t la_s_end = stack_range.first;
  assert(la > la_s_end);

  const uint64_t slot_byte_size = stack_range.second - la_s_end;

  // Encode the SP end (i.e., lowest address)
  const uint64_t ca_s_end = encode_ptr(la_s_end, slot_byte_size, 0);
  log("get_stack_pointer: Generated frame base CA 0x%016lx (byte_size: %lu, "
      "version: %lu)",
      ca_s_end, slot_byte_size, 0);

  // Generate encoded SP with same offset as input LA.
  const uint64_t ca = ca_s_end + (la - la_s_end);
  log("returning CA 0x%016lx (for LA 0x%016lx)", ca, la);

  return ca;
}

} // namespace c3_lldb

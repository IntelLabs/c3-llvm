//===-- C3LldbCtx.h -------------------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef LLDB_TARGET_C3_LLDB_CTX_H
#define LLDB_TARGET_C3_LLDB_CTX_H

#include "c3/llvm_c3_cc_globals.h"

namespace c3_lldb {

/**
 * @brief Interface for some CCPointerEncodings to access CPU C3 * configuration
 */
class C3LldbCtx {
public:
  C3LldbCtx(C3Support *c3) : c3(c3) {}

private:
  C3Support *c3;
};

} // namespace c3_lldb

#endif // LLDB_TARGET_C3_LLDB_CTX_H

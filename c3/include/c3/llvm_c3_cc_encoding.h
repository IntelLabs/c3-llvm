//===-- llvm_c3_cc_encoding.h ---------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_C3_INCLUDE_C3_LLVM_C3_CC_ENCODING_H
#define LLVM_C3_INCLUDE_C3_LLVM_C3_CC_ENCODING_H

#include "c3_llvm.h"
#include "llvm_c3_cc_globals.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"

#if __has_include("../../../../crypto/cc_encoding.h")
// Building as c3-simulator submodule
#include "../../../../crypto/cc_encoding.h"
#elif __has_include("../../cc/crypto/cc_encoding.h")
// Building with c3-simulator in llvm repo at ./cc
#include "../../cc/crypto/cc_encoding.h"
#elif __has_include("../../../cc/crypto/cc_encoding.h")
// Building with c3-simulator and c3-llvm in same folder
#include "../../../cc/crypto/cc_encoding.h"
#else
#error "Cannot find malloc/cc_encoding.h"
#endif

#pragma clang diagnostic pop

#endif // LLVM_C3_INCLUDE_C3_LLVM_C3_CC_ENCODING_H

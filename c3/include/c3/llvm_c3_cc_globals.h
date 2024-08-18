//===-- llvm_c3_cc_globals.h ----------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef C3_LLVM_C3_CC_GLOBALS_H
#define C3_LLVM_C3_CC_GLOBALS_H

#include "c3_llvm.h"

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wpedantic"

// Building as c3-simulator submodule
#if __has_include("../../../../malloc/cc_globals.h")
#include "../../../../malloc/cc_globals.h"
// Building with c3-simulator in llvm repo at ./cc
#elif __has_include("../../../cc/malloc/cc_globals.h")
#include "../../../cc/malloc/cc_globals.h"
// Building with c3-simulator and c3-llvm in same folder
#elif __has_include("../../../../cc/malloc/cc_globals.h")
#include "../../../../cc/malloc/cc_globals.h"
#else
#error "Cannot find malloc/cc_globals.h"
#endif

#pragma GCC diagnostic pop
#pragma clang diagnostic pop

#endif // LLVM_C3_INCLUDE_C3_LLVM_C3_CC_GLOBALS_H

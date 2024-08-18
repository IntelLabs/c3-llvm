//===-- llvm_c3_crypto_cpp.h ----------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef C3_LLVM_C3_CRYPTO_CPP_H
#define C3_LLVM_C3_CRYPTO_CPP_H

/*
 * If C3_CRYPTO_CPP_INCLUDE_CPP is defined, then this will directly include the
 * .cpp files from c3-simulator in order to build the including object file.
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wlanguage-extension-token"

// Building as c3-simulator submodule
#if __has_include("../../../../crypto/ascon_cipher.h")
#include "../../../../crypto/ascon_cipher.h"
#include "../../../../crypto/bipbip.h"
// Building with c3-simulator in llvm repo at ./cc
#elif __has_include("../../../cc/crypto/ascon_cipher.h")
#include "../../../cc/crypto/ascon_cipher.h"
#include "../../../cc/crypto/bipbip.h"
// Building with c3-simulator and c3-llvm in same folder
#elif __has_include("../../../../cc/crypto/ascon_cipher.h")
#include "../../../../cc/crypto/ascon_cipher.h"
#include "../../../../cc/crypto/bipbip.h"
#else
#error "Cannot find crypto/ascon_cipher.h"
#endif

#pragma clang diagnostic pop

#endif // C3_LLVM_C3_CRYPTO_CPP_H

#ifdef C3_CRYPTO_CPP_INCLUDE_CPP
#undef BITMASK
#if __has_include("../../../../crypto/ascon_cipher.cpp")
// Building as c3-simulator submodule
#include "../../../../crypto/ascon_cipher.cpp"
#undef BITMASK
#include "../../../../crypto/bipbip.cpp"
#elif __has_include("../../cc/crypto/ascon_cipher.cpp")
// Building with c3-simulator in llvm repo at ./cc
#include "../../cc/crypto/ascon_cipher.cpp"
#include "../../cc/crypto/bipbip.cpp"
#elif __has_include("../../../cc/crypto/ascon_cipher.cpp")
// Building with c3-simulator and c3-llvm in same folder
#include "../../../cc/crypto/ascon_cipher.cpp"
#undef BITMASK
#include "../../../cc/crypto/bipbip.cpp"
#else
// No longer supported old path...
#include "c3/crypto/ascon_cipher.cpp"
#undef BITMASK
#include "c3/crypto/bipbip.cpp"
#endif
#endif // C3_CRYPTO_CPP_INCLUDE_CPP

//===-- C3LldbCon.h -------------------------------------------------------===//
//
// Copyright (C) 2024 Intel Corporation
//
// Under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception OR MIT
//
//===----------------------------------------------------------------------===//
#ifndef LLDB_TARGET_C3_LLDB_CON_H
#define LLDB_TARGET_C3_LLDB_CON_H

#include "c3/llvm_c3_cc_globals.h"
#include <cassert>

namespace c3_lldb {

/**
 * @brief Interface needed by some CCPointerEncodings to access CPU state
 */
class C3LldbCon {
public:
  C3LldbCon(C3Support *c3) : c3(c3) {}

  inline void gp_fault(uint16_t sel_vec, bool is_vec, const char *desc) {
    // Make sure prior faults were checked if triggered.
    // (This is needed because we are reusing code from the functional
    // simulator where it would raise a run-time #GP in these conditions.)
    assert((cleared) && "Possible faults need check_fault_and_reset");
    c3->log("CA encoding/decoding or data encryption failed");
    fault = true;
    cleared = false;
  }

  /**
   * @brief Check that the raise fault callback hasn't been called.
   *
   * @return true if no fault has been issued.
   * @return false if a fault has been raised (e.g., on pointer decode fail).
   */
  bool check_fault_and_reset() {
    bool okay = !fault;
    fault = false;
    cleared = true;
    return okay;
  }

  // These are just used for debug messages in live simulation
  uint64_t read_rsp() {
    llvm_unreachable("not usable");
    return 0x0;
  }
  uint64_t read_rip() {
    llvm_unreachable("not usable");
    return 0x0;
  }

private:
  C3Support *c3;

  bool fault = false;
  bool cleared = true;
};

} // namespace c3_lldb

#endif // LLDB_TARGET_C3_LLDB_CON_H

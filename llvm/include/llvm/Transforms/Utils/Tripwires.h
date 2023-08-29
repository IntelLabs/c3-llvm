//===-- Tripwires.h - Intra-obj Tripwire Transformations ------------------*-
//C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_UTILS_TRIPWIRES_H
#define LLVM_TRANSFORMS_UTILS_TRIPWIRES_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class TripwiresPass : public PassInfoMixin<TripwiresPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }

private:
  void runOnFunc(Function &F, FunctionAnalysisManager &AM);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_UTILS_TRIPWIRES_H

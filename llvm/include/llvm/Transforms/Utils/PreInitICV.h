//===-- PreInitICV.h - Malloc-related Init ICV Transformations --*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_UTILS_PREINITICV_H
#define LLVM_TRANSFORMS_UTILS_PREINITICV_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class PreInitICVPass : public PassInfoMixin<PreInitICVPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }

private:
  void runOnFunc(Function &F, FunctionAnalysisManager &AM);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_UTILS_PREINITICV_H

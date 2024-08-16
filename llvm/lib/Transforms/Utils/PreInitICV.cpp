//===- PreInitICV.cpp - Insert PreInitICV after allocations ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/PreInitICV.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/IntrinsicInst.h"

#include <map>

using namespace llvm;

const llvm::DenseSet<llvm::StringRef> allocCalls = {"malloc", "calloc",
                                                    "realloc"};

void emitInitICV(CallInst *CallSrc, SmallSet<size_t, 32> &SkipOffsets) {
  // Prepare the Builder
  IRBuilder<> Builder(CallSrc->getNextNode());
  IntegerType *IntPtrTy =
      Builder.getIntPtrTy(CallSrc->getModule()->getDataLayout());
  IntegerType *Int64Ty = Type::getInt64Ty(CallSrc->getContext());

  // The malloc call being act upon has already returned an allocation.
  Value *Allocation = Builder.CreatePtrToInt(CallSrc, IntPtrTy);

  // Depending on the specific allocation function, e.g.: malloc, calloc,
  // realloc, etc, the size of the allocation is encoded in different operands.
  Value *AllocationSize = NULL;
  StringRef functionName = CallSrc->getCalledFunction()->getName();
  if (functionName.equals(StringRef("malloc")))
    AllocationSize = CallSrc->getOperand(0);
  if (functionName.equals(StringRef("calloc")) ||
      functionName.equals(StringRef("realloc")))
    AllocationSize = CallSrc->getOperand(1);

  // When realloc shrinks an allocation, the data that remains could have been
  // previously initialized. Emitting PreInitICV instructions after realloc
  // would loose the data's actual initialization state, potentially leading to
  // false positives. This suggests that PreInitICV instructions should NOT be
  // emitted.
  //
  // Conversely, when realloc expands an allocation, new memory is sure to not
  // have been initialized, so they should have their initialization state set
  // to PREINIT. This suggests that PreInitICV instructions should be emitted
  // for the expanded area of the allocation. However, the compiler does not
  // keep track of the previous allocation size.
  //
  // PreInitICV instructions should be emitted for the new granules if static
  // analysis can determine the previous size of the allocation. Currently, we
  // skip it altogether, thus leaving room for false negatives. This is in
  // alignment with uninitialize use detection being a best-effort approach.
  //
  // FIXME: Emit PreInitICV instructions for the new granules if static
  // analysis can determine the previous size of the allocation.
  if (functionName.equals(StringRef("realloc")))
    return;

  // Calloc initializes the data to a specific value, thus it doesn't require
  // PREINIT semantics.
  //
  // NOTE on InitICV: Since the INIT state has inverted polarity, in other
  // words: since 0 means INITIALIZED, there's no need to issue InitICV
  // instructions, either.
  if (functionName.equals(StringRef("calloc")))
    return;

  // The Allocation address and the size of the allocation are the arguments to
  // the ICV initialization code being emitted.
  std::vector<llvm::Value *> args = {Allocation, AllocationSize};

  // If full allocation is initialized, skip PreInitICV emmission.
  if (ConstantInt* CI = dyn_cast<ConstantInt>(AllocationSize)) {
    if (SkipOffsets.size() == CI->getZExtValue()) {
      return;
    }
  }

  // The inline assembly code snippet:
  StringRef AsmString = StringRef(
      "${:private}${:uid}_loophead:\n"
      // PreInitICV instruction (assumes the granule is pointed to by rax)
      "    .byte 0xF0\n"
      "    .byte 0x48\n"
      "    .byte 0x21\n"
      "    .byte 0xC0\n"
      "    add $0, 8\n"
      "    sub $1, 8\n"
      "    jge ${:private}${:uid}_loophead\n");

  // The assembly code snippet above takes the allocation address as input, but
  // also updates rax in a loop to cover the whole allocation, hence rax is
  // listed both as output (={rax}) and input (0). Likewise for the allocation
  // size, which is taken as input but used as the control variable for the
  // loop, hence it is also listed as both output (=r) and input (1).
  StringRef AsmConstr = StringRef("={ax},=r,0,1,~{dirflag},~{fpsr},~{flags}");
  bool hasSideEffects = true;
  bool isAlignStack = false;
  bool canThrow = false;

  // The InlineAssembly class constructor has a return type, because it is
  // treated as a function call, and since the assembly code snippet has two
  // outputs, we need a struct to consolidate them in a representation of the
  // return type. Inputs are more naturally represented as an array of types.
  FunctionType *AsmFunction = FunctionType::get(
      // Inline Assembly Outputs (see Constraints above)
      llvm::StructType::get(Int64Ty, Int64Ty),
      // Inline Assembly Inputs (see Constraints above)
      {Int64Ty, Int64Ty}, false /* isVarArg */
  );

  // Create the Inline Assembly
  llvm::InlineAsm *IA =
      llvm::InlineAsm::get(AsmFunction, AsmString, AsmConstr, hasSideEffects,
                           isAlignStack, llvm::InlineAsm::AD_Intel, canThrow);

  // Actually emit the Inline Assembly
  Builder.CreateCall(IA, args);
}

bool collectDirectDependency(const DataLayout &DL, Instruction *I, CallInst *CI, SmallSet<size_t, 32> &Offsets) {
  //V = V->stripPointerCastsForAliasAnalysis();
  if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    if (Instruction *POI = dyn_cast<Instruction>(SI->getPointerOperand())) {
      if (POI->stripPointerCastsForAliasAnalysis() == CI) {
        // Direct store to allocation pointer
        auto TySz = DL.getTypeStoreSize(SI->getValueOperand()->getType());
        for (size_t i = 0; i < TySz; i++) {
          Offsets.insert(i);
        }
        // Exit, we found a direct store
        return true;
      }
      // Check if StoreInst stores to GEP of allocation
      if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(POI)) {
        if (GEP->getPointerOperand()->stripPointerCastsForAliasAnalysis() == CI) {
          auto TySz = DL.getTypeAllocSize(GEP->getResultElementType());
          for (auto &index : GEP->indices()) {
            if (ConstantInt *CI = dyn_cast<ConstantInt>(index)) {
              auto offset = CI->getZExtValue();
              for (size_t i = 0; i < TySz; i++) {
                Offsets.insert(offset * TySz + i);
              }
            }
          }
          return true;
        }
      }
    }
  } else if (MemSetInst *MSI = dyn_cast<MemSetInst>(I)) {
    Instruction *POI = dyn_cast<Instruction>(MSI->getOperand(0));
    ConstantInt *valueOperand = dyn_cast<ConstantInt>(MSI->getOperand(1));
    ConstantInt *szOperand = dyn_cast<ConstantInt>(MSI->getOperand(2));
    if (POI && valueOperand && szOperand) {
      if (POI->stripPointerCastsForAliasAnalysis() == CI) {
        auto TySz = DL.getTypeStoreSize(valueOperand->getType());
        auto sz = szOperand->getZExtValue();
        for (size_t i = 0; i < TySz * sz; i++) {
          Offsets.insert(i);
        }
        return true;
      }
    }
  }
  return false;
}

bool hasPossiblePreceedingMemoryUse(MemoryUseOrDef *access, MemoryUseOrDef *stop) {
  // Checks if there is a possible memory access between stop and access.
  MemoryUseOrDef *cur = access;
  while (cur != stop) {
    auto definingAccess = cur->getDefiningAccess();
    if (!definingAccess) {
      break;
    }
    if (isa<MemoryUse>(definingAccess)) {
      return true;
    } else if (isa<MemoryPhi>(definingAccess)) {
      // We don't handle memory phi nodes for now.
      // Consider it a possiblr use
      return true;
    }
    cur = dyn_cast<MemoryUseOrDef>(definingAccess);
  }
  return false;
}

bool collectMemoryDependency(MemorySSA &MSSA, const DataLayout &DL, Instruction *I, CallInst *CI, SmallSet<size_t, 32> &Offsets) {
  auto walker = MSSA.getWalker();

  if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    // Direct store
    if (auto storeAccess = MSSA.getMemoryAccess(SI)) {
      auto memloc = MemoryLocation::get(SI);
      auto allocAccess = MSSA.getMemoryAccess(CI);
      if (auto clobberAccess = walker->getClobberingMemoryAccess(storeAccess, memloc)) {
        auto clobberUseOrDef = dyn_cast<MemoryUseOrDef>(clobberAccess);
        if (clobberUseOrDef->getDefiningAccess() == allocAccess && !hasPossiblePreceedingMemoryUse(clobberUseOrDef, allocAccess)) {
          auto TySz = DL.getTypeStoreSize(SI->getValueOperand()->getType());
          for (size_t i = 0; i < TySz; i++) {
            Offsets.insert(i);
          }
          return true;
        }
      }
    }
    // GEP store
    if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(SI->getPointerOperand())) {
      if (Instruction *loadInst = dyn_cast<Instruction>(GEP->getPointerOperand()->stripPointerCastsForAliasAnalysis())) {
        auto memloc = MemoryLocation::get(loadInst);
        auto allocAccess = MSSA.getMemoryAccess(CI);
        auto loadAccess = MSSA.getMemoryAccess(loadInst);
        if (auto clobberAccess = walker->getClobberingMemoryAccess(loadAccess, memloc)) {
          auto clobberUseOrDef = dyn_cast<MemoryUseOrDef>(clobberAccess);
          if (clobberUseOrDef->getDefiningAccess() == allocAccess && !hasPossiblePreceedingMemoryUse(clobberUseOrDef, allocAccess)) {
            auto TySz = DL.getTypeAllocSize(GEP->getResultElementType());
            for (auto &index : GEP->indices()) {
              if (ConstantInt *CI = dyn_cast<ConstantInt>(index)) {
                auto offset = CI->getZExtValue();
                for (size_t i = 0; i < TySz; i++) {
                  Offsets.insert(offset * TySz + i);
                }
              }
            }
          }
        }
      }
    }
  }

  if (MemSetInst *MSI = dyn_cast<MemSetInst>(I)) {
    // Direct memset
    Instruction *POI = dyn_cast<Instruction>(MSI->getOperand(0));
    ConstantInt *valueOperand = dyn_cast<ConstantInt>(MSI->getOperand(1));
    ConstantInt *szOperand = dyn_cast<ConstantInt>(MSI->getOperand(2));

    if (POI && valueOperand && szOperand) {
      if (auto storeAccess = MSSA.getMemoryAccess(POI)) {
        auto memloc = MemoryLocation::get(MSI);
        auto allocAccess = MSSA.getMemoryAccess(CI);
        if (auto clobberAccess = walker->getClobberingMemoryAccess(storeAccess, memloc)) {
          auto clobberUseOrDef = dyn_cast<MemoryUseOrDef>(clobberAccess);
          if (clobberUseOrDef->getDefiningAccess() == allocAccess && !hasPossiblePreceedingMemoryUse(clobberUseOrDef, allocAccess)) {
            auto TySz = DL.getTypeStoreSize(valueOperand->getType());
            auto sz = szOperand->getZExtValue();
            for (size_t i = 0; i < TySz * sz; i++) {
              Offsets.insert(i);
            }
            return true;
          }
        }
      }
    }
  }
  return false;
}

SmallSet<size_t, 32>
findInitializedRange(MemorySSA &MSSA, PostDominatorTree &PDT,
                     const DataLayout &DL, CallInst *allocInst,
                     std::vector<StoreInst *> stores,
                     std::vector<CallInst *> calls) {
  SmallSet<size_t, 32> res;

  for (auto SI : stores) {

    // Check that the store post-dominates the allocation
    if (PDT.dominates(SI, allocInst)) {
      SmallSet<size_t, 32> Offsets;

      // Collect simple cases with direct depencency
      collectDirectDependency(DL, SI, allocInst, Offsets);

      // Memory aliasing cases
      collectMemoryDependency(MSSA, DL, SI, allocInst, Offsets);

      // Add offsets to result
      for (auto e: Offsets) {
        res.insert(e);
      }
    }
  }

  for (auto CI : calls) {
    SmallSet<size_t, 32> Offsets;
    if (MemSetInst *MSI = dyn_cast<MemSetInst>(CI)) {
      // Collect memsets with direct depencency
      collectDirectDependency(DL, MSI, allocInst, Offsets);
      // Collect memsets with memory depencency
      collectMemoryDependency(MSSA, DL, MSI, allocInst, Offsets);
    }
    // Add offsets to result
    for (auto e: Offsets) {
      res.insert(e);
    }
  }

  return res;
}

void findMallocs(Function &F, FunctionAnalysisManager &AM) {
  // Build list of all calls
  auto &PDT = AM.getResult<PostDominatorTreeAnalysis>(F);
  auto &MSSA = AM.getResult<MemorySSAAnalysis>(F).getMSSA();
  auto &DL = F.getParent()->getDataLayout();
  std::vector<CallInst *> calls;
  std::vector<StoreInst *> stores;
  std::map<CallInst *, SmallSet<size_t, 32>> toInstrument;

  // Make sure to optimize MemorySSA
  MSSA.ensureOptimizedUses();

  // Collect relevant instructions
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (CallInst *C = llvm::dyn_cast<CallInst>(&I)) {
        calls.push_back(C);
      }
      if (StoreInst *SI = llvm::dyn_cast<StoreInst>(&I)) {
        stores.push_back(SI);
      }
    }
  }

  // Look for malloc-related calls and emit InitICVs for them
  for (CallInst *C : calls) {
    Function *callTarget = C->getCalledFunction();
    if (!callTarget)
      continue;
    std::string name = callTarget->getName().str();
    if (allocCalls.contains(name)) {
      auto skipOffsets =
          findInitializedRange(MSSA, PDT, DL, C, stores, calls);
      // Insert CallInst and range that is initalized.
      toInstrument.insert(std::pair<CallInst *,SmallSet<size_t, 32>>(C, skipOffsets));
    }
  }

  // Do actual instrumentation of mallocs
  for (auto e: toInstrument) {
    emitInitICV(e.first, e.second);
  }
}

void PreInitICVPass::runOnFunc(Function &F, FunctionAnalysisManager &AM) {
  if (F.hasFnAttribute(Attribute::CCPreInitICV))
    findMallocs(F, AM);
}

PreservedAnalyses PreInitICVPass::run(Module &M, ModuleAnalysisManager &MAM) {
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

  for (Function &F : M) {
    if (!F.isDeclaration())
      runOnFunc(F, FAM);
  }

  return PreservedAnalyses::none();
}

//===-- Tripwires.cpp - Intra-obj Tripwire Transformations
//--------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/Tripwires.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "c3/malloc/cc_globals.h"

using namespace llvm;

// LLVM metadata flag to ignore instrumenting our own instrumentation
#define C3_LLVM_METADATA "c3llvm"

#define DEBUG_PRINTS 0

// e.g.: c3_memcpy
const std::string C3FunctionPrefix = "c3_";
const llvm::DenseSet<llvm::StringRef> functionsToIntercept = {
    "memcpy", "memset", "memmove"};

const llvm::DenseSet<llvm::StringRef> allocCalls = {"malloc", "calloc",
                                                    "realloc"};

void replaceMemIntrinsicsWithCalls(Function &F) {
  SmallVector<MemIntrinsic *, 16> intrinToInstrument;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      // if we use mem* operations in LLVM we can skip them through metadata
      if (I.hasMetadata(C3_LLVM_METADATA)) {
        continue;
      }
      if (MemIntrinsic *MI = dyn_cast<MemIntrinsic>(&I)) {
        intrinToInstrument.push_back(MI);
      }
    }
  }
  for (auto *MI : intrinToInstrument) {
    Module &M = *(F.getParent());
    IntegerType *IntptrTy = Type::getIntNTy(
        M.getContext(), M.getDataLayout().getPointerSizeInBits());
    IRBuilder<> IRB(MI);

    // these three can be global variables to avoid repetition
    FunctionCallee C3Memmove =
        M.getOrInsertFunction(C3FunctionPrefix + "memmove", IRB.getInt8PtrTy(),
                              IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
    FunctionCallee C3Memcpy =
        M.getOrInsertFunction(C3FunctionPrefix + "memcpy", IRB.getInt8PtrTy(),
                              IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
    FunctionCallee C3Memset =
        M.getOrInsertFunction(C3FunctionPrefix + "memset", IRB.getInt8PtrTy(),
                              IRB.getInt8PtrTy(), IRB.getInt32Ty(), IntptrTy);

    if (isa<MemTransferInst>(MI)) {
      IRB.CreateCall(
          isa<MemMoveInst>(MI) ? C3Memmove : C3Memcpy,
          {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
           IRB.CreatePointerCast(MI->getOperand(1), IRB.getInt8PtrTy()),
           IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    } else if (isa<MemSetInst>(MI)) {
      IRB.CreateCall(
          C3Memset,
          {IRB.CreatePointerCast(MI->getOperand(0), IRB.getInt8PtrTy()),
           IRB.CreateIntCast(MI->getOperand(1), IRB.getInt32Ty(), false),
           IRB.CreateIntCast(MI->getOperand(2), IntptrTy, false)});
    } else {
      llvm_unreachable("Neither MemSet nor MemTransfer?");
    }
    MI->eraseFromParent();
  }
}

void replaceMemFamilyCalls(Function &F) {
  std::vector<CallInst *> calls;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (CallInst *C = llvm::dyn_cast<CallInst>(&I)) {
        calls.push_back(C);
      }
    }
  }

  Module *M = F.getParent();
  for (CallInst *C : calls) {
    Function *callTarget = C->getCalledFunction();
    // indirect call
    if (!callTarget)
      continue;

    // filter out functions not intended to be intercepted
    std::string name = callTarget->getName().str();
    if (!functionsToIntercept.contains(name)) {
      continue;
    }

    std::string replacementName = C3FunctionPrefix + name;
    FunctionCallee replacement =
        M->getOrInsertFunction(replacementName, callTarget->getFunctionType());
    {
      IRBuilder<> builder(C);
      std::vector<Value *> args;
      for (Value *arg : C->args()) {
        args.push_back(arg);
      }
      CallInst *replacedCall = builder.CreateCall(replacement, args);
      assert(replacedCall);
      C->replaceAllUsesWith(replacedCall);
      C->eraseFromParent();
    }
  }
}

void invalidateTripwire(CallInst *CallSrc, uint64_t Offset) {
  const DataLayout &DL = CallSrc->getModule()->getDataLayout();
  // insert invalidate-icv _after_ the allocation call
  IRBuilder<> Builder(CallSrc->getNextNode());
  IntegerType *t = Builder.getIntPtrTy(DL);
  Value *Allocation = Builder.CreatePtrToInt(CallSrc, t);
  Value *TripwireTarget = Builder.CreateAdd(
      Allocation, Builder.getIntN(DL.getPointerSizeInBits(), Offset));

  // store the magic value inside the tripwire data field
  Value *TripwirePoisonValue8B = ConstantInt::get(
      Type::getInt64Ty(CallSrc->getContext()), MAGIC_VAL_INTRA); // 8 bytes
  Value *TripwireTargetPtr =
      Builder.CreateIntToPtr(TripwireTarget, Builder.getInt8PtrTy()); // i8*
  Builder.CreateStore(TripwirePoisonValue8B, TripwireTargetPtr);

  // invalidate the ICVs
  llvm::InlineAsm *IA =
      llvm::InlineAsm::get(llvm::FunctionType::get(
                               Type::getVoidTy(CallSrc->getContext()),
                               {Type::getInt64Ty(CallSrc->getContext())},
                               false),
                           StringRef(".byte 0xf0\n .byte 0x48\n .byte 0x2B\n "
                                     ".byte 0xc0\n"), // cc_isa_invicv
                           StringRef("{ax},~{dirflag},~{fpsr},~{flags}"),
                           /*hasSideEffects=*/true,
                           /*isAlignStack*/ false, llvm::InlineAsm::AD_ATT,
                           /*canThrow*/ false);
  std::vector<llvm::Value *> args = {TripwireTarget};
  Builder.CreateCall(IA, args);
}

bool arrayHasTripwires(StructType *s, uint64_t ElementOffset,
                       uint64_t DistanceToRightTripwire) {
  // DistanceToRightTripwire: this can be unequal to sizeof(element) because the
  // tripwire needs to align at 8
  // TODO: cache the file data to avoid reading it multiple times
  FILE *fp = fopen("/tmp/llvmtripwires", "r");
  if (fp) {
    char *line = nullptr;
    size_t len = 0;
    ssize_t read = 0;
    while ((read = getline(&line, &len, fp)) != -1) {

      char *StructName = strtok(line, ",");
      uint64_t LeftTripwireOffset = strtoull(strtok(NULL, ","), NULL, 10);
      uint64_t RightTripwireOffset = strtoull(strtok(NULL, ","), NULL, 10);

      const char *IRStructName = s->getName().data();
      // TODO: improve heuristics?
      const char *IRprefix = "struct.";
      size_t IRprefixLen = strlen(IRprefix);
      if (strncmp(IRStructName, IRprefix, IRprefixLen) == 0) {
        const char *IRStrippedName = IRStructName + IRprefixLen;

        // now evaluate whether the struct names are equal
        if (strncmp(IRStrippedName, StructName, strlen(IRStrippedName)) == 0) {
          if (LeftTripwireOffset == ElementOffset - 8 &&
              RightTripwireOffset == ElementOffset + DistanceToRightTripwire) {
#if DEBUG_PRINTS == 1
            errs() << "> STRUCT MATCH: " << s->getName() << " " << StructName
                   << " " << LeftTripwireOffset << " " << RightTripwireOffset
                   << "\n";
#endif
            return true;
          }
        }
      }
    }

    free(line);
    fclose(fp);
  }
  return false;
}

bool evaluateForStructUses(CallInst *CallSrc, Instruction *Target,
                           llvm::DenseSet<Instruction *> visited) {
  const DataLayout &DL = CallSrc->getModule()->getDataLayout();
  bool handled = false;
  for (auto U : Target->users()) { // U is of type User*
    if (auto I = dyn_cast<Instruction>(U)) {
      // avoid infinite recursion
      if (visited.contains(I))
        continue;
      // avoid instrumenting more than once
      if (handled)
        return true;

      // an instruction uses the src
      if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(I)) {
        /*
          GEP:   %b = getelementptr inbounds %struct.f2, ptr %struct1, i64 0,
          i32 2 getPointerOperand:    %struct1 = alloca %struct.f1, align 4
          getSourceElementType: %struct.f2 = type { i32, i32, i32, i32, i32, i32
          }
        */
        if (StructType *TypeTarget =
                dyn_cast<StructType>(GEP->getSourceElementType())) {
#if DEBUG_PRINTS == 1
          errs() << "Found StructType: " << *TypeTarget
                 << " NAME: " << TypeTarget->getName() << "\n";
#endif

          unsigned NumElements = TypeTarget->getNumElements();
          for (unsigned i = 0; i < NumElements; i++) {
            Type *ElementTy = TypeTarget->getElementType(i);
#if DEBUG_PRINTS == 1
            errs() << "\tStruct Element Type: " << *ElementTy << "\n";
#endif

            // TODO: do we need to account for nested struct sizes? we may need
            // to call getStructLayout on the nested structs?
            const StructLayout *SL = DL.getStructLayout(TypeTarget);
            uint64_t ElementOffset = SL->getElementOffset(i);
#if DEBUG_PRINTS == 1
            errs() << "\tElement Offset NEW: " << i << " " << ElementOffset
                   << "\n";
#endif

            // if there is no element on the right, then there are no tripwires
            // anyway
            if (i + 1 < NumElements) {
              uint64_t NextOffset = SL->getElementOffset(i + 1);
              uint64_t LeftTripwire = ElementOffset - 8;
              uint64_t RightTripwire = NextOffset;

              if (RightTripwire % 8) {
                // Align the right tripwire to multiple of 8
                RightTripwire += 8 - (RightTripwire % 8);
              }

              if (ElementTy->isArrayTy() &&
                  arrayHasTripwires(TypeTarget, ElementOffset,
                                    RightTripwire - ElementOffset)) {
#if DEBUG_PRINTS == 1
                errs() << "> Array Size " << NextOffset - ElementOffset
                       << " Set Tripwires At: " << LeftTripwire << " and "
                       << RightTripwire << "\n";
#endif
                invalidateTripwire(CallSrc, LeftTripwire);
                invalidateTripwire(CallSrc, RightTripwire);
                handled = true;
              }
            }
          }
          if (handled)
            return true;
        }
      } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
        // on -O0 the result of malloc gets stored in a stack variable. Look for
        // the uses of that variable.
        if (Instruction *AllocStore =
                dyn_cast<Instruction>(SI->getPointerOperand())) {
          // recurse (propagate)
          visited.insert(SI);
          if (evaluateForStructUses(CallSrc, AllocStore, visited) == true) {
            return true;
          }
        }
      } else if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
        // recurse (propagate)
        visited.insert(LI);
        if (evaluateForStructUses(CallSrc, LI, visited) == true) {
          return true;
        }
      }
    }
  }
  return false;
}

void initializeStructTripwires(Function &F) {
  std::vector<CallInst *> calls;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (CallInst *C = llvm::dyn_cast<CallInst>(&I)) {
        calls.push_back(C);
      }
    }
  }

  // Module *M = F.getParent();
  for (CallInst *C : calls) {
    Function *callTarget = C->getCalledFunction();
    // indirect call
    if (!callTarget)
      continue;

    // filter out functions not intended to be intercepted
    std::string name = callTarget->getName().str();
    if (!allocCalls.contains(name)) {
      continue;
    }

    llvm::DenseSet<Instruction *> visited;
    evaluateForStructUses(C, C, visited);
  }
}

void TripwiresPass::runOnFunc(Function &F, FunctionAnalysisManager &AM) {
  if (F.hasFnAttribute(Attribute::CCTripwires)) {
#if DEBUG_PRINTS == 1
    errs() << "[Running C3 Tripwires Pass on]: " << F.getName() << "\n";
#endif
    // LLVM mem intrinsics can get inlined. We replace them with direct
    // calls to ensure instrumentation.
    replaceMemIntrinsicsWithCalls(F);

    // Replace calls to mem* family functions to C3 custom variants: call memcpy
    // -> call c3_memcpy
    replaceMemFamilyCalls(F);

    // Struct array-member ICV invalidation
    initializeStructTripwires(F);
  }
}

PreservedAnalyses TripwiresPass::run(Module &M, ModuleAnalysisManager &MAM) {
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

  for (Function &F : M) {
    if (!F.isDeclaration())
      runOnFunc(F, FAM);
  }

  // hack: clear the '/tmp/llvmtripwires' file
  FILE *fp = fopen("/tmp/llvmtripwires", "w");
  if (fp)
    fclose(fp);

  return PreservedAnalyses::none();
}

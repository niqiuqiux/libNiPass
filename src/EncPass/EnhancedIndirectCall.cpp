#include "EncPass/EnhancedIndirectCall.h"
#include "EncPass/EncryptUtils.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/Debug.h"
#include "CryptoUtils.h"

#define DEBUG_TYPE "enhancedindirectcall"

#if LLVM_VERSION_MAJOR > 10
#include "compat/CallSite.h"
#else
#include "llvm/IR/CallSite.h"
#endif

using namespace llvm;

namespace ni_pass {

// === Pass 入口 ===

PreservedAnalyses EnhancedIndirectCallPass::run(Function &F,
                                                 FunctionAnalysisManager &FAM) {
  if (readObfuscationMetadata(&F, "envmf.applied"))
    return PreservedAnalyses::all();

  if (toObfuscate(flag, &F, "eicall")) {
    LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectCall] Function : " << F.getName()
                      << "\033[0m\n");
    doEnhancedIndirectCall(F);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

// === 收集被调用函数 ===

void EnhancedIndirectCallPass::NumberCallees(Function &F) {
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (dyn_cast<CallInst>(&I)) {
        CallSite CS(&I);
        Function *Callee = CS.getCalledFunction();
        if (Callee == nullptr)
          continue;
        if (Callee->isIntrinsic())
          continue;
        CallSites.push_back((CallInst *)&I);
        if (CalleeNumbering.count(Callee) == 0) {
          CalleeNumbering[Callee] = Callees.size();
          Callees.push_back(Callee);
        }
      }
    }
  }
}

// === 构建加密函数指针表（per-entry 独立密钥，多层加密）===
// 编译时直接用 ConstantExpr 计算加密值，无需 constructor

GlobalVariable *EnhancedIndirectCallPass::getIndirectCallees(Function &F,
                                                              IntegerType *intType) {
  std::string GVName = createObfuscatedName(*F.getParent());

  LLVMContext &Ctx = F.getContext();
  Module *M = F.getParent();
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

  std::vector<unsigned> Slots;
  for (unsigned i = 0; i < Callees.size(); ++i)
    Slots.push_back(i);
  for (size_t i = Slots.size(); i > 1; --i)
    std::swap(Slots[i - 1], Slots[cryptoutils->get_range(i)]);

  std::vector<Constant *> Elements;
  Elements.reserve(Callees.size());
  for (unsigned i = 0; i < Callees.size(); ++i) {
    Constant *Garbage = ConstantExpr::getIntToPtr(
        ConstantInt::get(intType, cryptoutils->get_uint64_t()), i8ptr);
    Elements.push_back(Garbage);
  }

  for (unsigned logicalIdx = 0; logicalIdx < Callees.size(); ++logicalIdx) {
    Function *Callee = Callees[logicalIdx];
    unsigned physicalSlot = Slots[logicalIdx];
    CalleeSlots[Callee] = physicalSlot;

    // 为每个 callee 生成 4 个独立密钥
    CalleeEncInfo Info;
    Info.key1 = cryptoutils->get_uint64_t();
    Info.key2 = cryptoutils->get_uint64_t();
    Info.key3 = cryptoutils->get_uint64_t();
    Info.key4 = cryptoutils->get_uint64_t();
    Info.variant = cryptoutils->get_range(0, 3);
    CalleeKeys[Callee] = Info;

    (void)physicalSlot;
  }

  ArrayType *ATy = ArrayType::get(i8ptr, Elements.size());
  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GlobalVariable *GV = new GlobalVariable(*M, ATy, false,
                           GlobalValue::LinkageTypes::PrivateLinkage, CA, GVName);
  writeObfuscationMetadata(GV, "nipass.generated");
  appendToCompilerUsed(*M, {GV});

  return GV;
}

static void insertLazyCalleeTableInitializer(
    Function &Fn, GlobalVariable *Targets, ArrayRef<Function *> Callees,
    const std::map<Function *, unsigned> &CalleeSlots,
    const std::map<Function *, CalleeEncInfo> &CalleeKeys,
    IntegerType *intType) {
  if (Callees.empty())
    return;

  Module *M = Fn.getParent();
  LLVMContext &Ctx = Fn.getContext();
  auto *i8Ty = Type::getInt8Ty(Ctx);
  auto *i8ptr = i8Ty->getPointerTo();
  ConstantInt *Zero = ConstantInt::get(intType, 0);

  GlobalVariable *InitState = new GlobalVariable(
      *M, i8Ty, false, GlobalValue::PrivateLinkage,
      ConstantInt::get(i8Ty, 0), createObfuscatedName(*M));
  writeObfuscationMetadata(InitState, "nipass.generated");

  BasicBlock &Entry = Fn.getEntryBlock();
  Instruction *SplitPt = &*Entry.getFirstInsertionPt();
  BasicBlock *ContBB = Entry.splitBasicBlock(SplitPt->getIterator(), "");
  BasicBlock *InitBB = BasicBlock::Create(Ctx, "", &Fn, ContBB);

  Entry.getTerminator()->eraseFromParent();
  IRBuilder<NoFolder> EntryIRB(&Entry);
  LoadInst *State = EntryIRB.CreateLoad(i8Ty, InitState);
  State->setAtomic(AtomicOrdering::Acquire);
  State->setAlignment(Align(1));
  Value *NeedInit =
      EntryIRB.CreateICmpEQ(State, ConstantInt::get(i8Ty, 0));
  EntryIRB.CreateCondBr(NeedInit, InitBB, ContBB);

  IRBuilder<NoFolder> InitIRB(InitBB);
  for (Function *Callee : Callees) {
    auto SlotIt = CalleeSlots.find(Callee);
    auto KeyIt = CalleeKeys.find(Callee);
    if (SlotIt == CalleeSlots.end() || KeyIt == CalleeKeys.end())
      continue;

    const CalleeEncInfo &Info = KeyIt->second;
    uint64_t CombinedKey = (Info.key1 ^ Info.key2) + (Info.key3 ^ Info.key4);

    Value *Slot = ConstantInt::get(intType, SlotIt->second);
    Value *GEP =
        InitIRB.CreateGEP(Targets->getValueType(), Targets, {Zero, Slot});
    Value *FnPtr = InitIRB.CreateBitCast(Callee, i8ptr);
    Value *AsInt = InitIRB.CreatePtrToInt(FnPtr, intType);
    Value *EncInt =
        InitIRB.CreateAdd(AsInt, emitSplitKey(InitIRB, CombinedKey, intType));
    Value *EncPtr = InitIRB.CreateIntToPtr(EncInt, i8ptr);
    InitIRB.CreateStore(EncPtr, GEP);
  }

  StoreInst *Ready =
      InitIRB.CreateStore(ConstantInt::get(i8Ty, 1), InitState);
  Ready->setAtomic(AtomicOrdering::Release);
  Ready->setAlignment(Align(1));
  InitIRB.CreateBr(ContBB);
}

// === 核心替换逻辑 ===

bool EnhancedIndirectCallPass::doEnhancedIndirectCall(Function &Fn) {
  if (Options && Options->skipFunction(Fn.getName()))
    return false;

  LLVMContext &Ctx = Fn.getContext();

  CalleeNumbering.clear();
  Callees.clear();
  CallSites.clear();
  CalleeKeys.clear();
  CalleeSlots.clear();

  NumberCallees(Fn);

  if (Callees.empty())
    return false;

  const DataLayout &DL = Fn.getParent()->getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  ConstantInt *Zero = ConstantInt::get(intType, 0);
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();

  // 构建加密表（内部生成 per-entry 密钥）
  GlobalVariable *Targets = getIndirectCallees(Fn, intType);
  insertLazyCalleeTableInitializer(Fn, Targets, Callees, CalleeSlots,
                                   CalleeKeys, intType);

  // 每函数独立的索引混淆密钥
  uint64_t indexKey = cryptoutils->get_uint64_t();

  for (auto CI : CallSites) {
    CallBase *CB = CI;
    Function *Callee = CB->getCalledFunction();
    FunctionType *FTy = CB->getFunctionType();
    IRBuilder<NoFolder> IRB(CB);

    // --- 索引混淆 ---
    unsigned realIdx = CalleeSlots[Callee];
    uint64_t encodedIdx = realIdx ^ indexKey;
    Value *EncodedIdxVal = ConstantInt::get(intType, encodedIdx);
    Value *IdxKeyVal = emitSplitKey(IRB, indexKey, intType);
    Value *RealIdxVal = IRB.CreateXor(EncodedIdxVal, IdxKeyVal);

    Value *GEP = IRB.CreateGEP(Targets->getValueType(), Targets,
                                {Zero, RealIdxVal});
    LoadInst *EncPtr = IRB.CreateLoad(i8ptr, GEP, CI->getName());

    // --- 多层解密（随机变体）---
    const CalleeEncInfo &Info = CalleeKeys[Callee];
    Value *DecPtr = emitDecrypt4Key(IRB, EncPtr, Info, intType, Ctx);

    // --- 替换调用目标 ---
    Value *FnPtr = IRB.CreateBitCast(DecPtr, FTy->getPointerTo());
    FnPtr->setName("");
    CB->setCalledOperand(FnPtr);
  }

  return true;
}

} // namespace ni_pass

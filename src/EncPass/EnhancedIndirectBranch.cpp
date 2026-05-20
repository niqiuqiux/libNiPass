#include "EncPass/EnhancedIndirectBranch.h"
#include "EncPass/EncryptUtils.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "enhancedindirectbranch"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

// 命令行选项：是否使用基于栈的间接跳转方式
static cl::opt<bool>
    EIBRUseStack("eibr-use-stack", cl::init(true), cl::NotHidden,
                 cl::desc("[EnhancedIndirectBranch]Stack-based indirect jumps"));

namespace ni_pass {

static uint64_t modularInverseOdd(uint64_t value, unsigned bits) {
  uint64_t inv = 1;
  for (unsigned i = 0; i < bits; ++i)
    inv *= 2 - value * inv;
  if (bits < 64)
    inv &= ((1ULL << bits) - 1);
  return inv;
}

static BranchIndexCodec makeBranchIndexCodec(unsigned bits) {
  BranchIndexCodec C;
  C.xorKey = cryptoutils->get_uint64_t();
  C.addKey = cryptoutils->get_uint64_t();
  C.mulKey = cryptoutils->get_uint64_t() | 1;
  C.invMulKey = modularInverseOdd(C.mulKey, bits);
  return C;
}

static uint64_t encodeBranchIndex(uint64_t realIdx,
                                  const BranchIndexCodec &Codec,
                                  unsigned bits) {
  uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
  uint64_t encoded = ((realIdx + Codec.addKey) * Codec.mulKey) & mask;
  encoded ^= Codec.xorKey;
  return encoded & mask;
}

static Value *emitDecodeBranchIndex(IRBuilder<NoFolder> &IRB,
                                    uint64_t encodedIdx,
                                    const BranchIndexCodec &Codec,
                                    IntegerType *intType) {
  Value *V = ConstantInt::get(intType, encodedIdx);
  V = IRB.CreateXor(V, emitSplitKey(IRB, Codec.xorKey, intType));
  V = IRB.CreateMul(V, emitSplitKey(IRB, Codec.invMulKey, intType));
  V = IRB.CreateSub(V, emitSplitKey(IRB, Codec.addKey, intType));
  return V;
}

static void redirectPHIIncomingBlock(BasicBlock *Target,
                                     BasicBlock *OldPred,
                                     BasicBlock *NewPred) {
  for (Instruction &I : *Target) {
    PHINode *PN = dyn_cast<PHINode>(&I);
    if (!PN)
      break;
    for (unsigned i = 0; i < PN->getNumIncomingValues(); ++i)
      if (PN->getIncomingBlock(i) == OldPred)
        PN->setIncomingBlock(i, NewPred);
  }
}

static Value *emitEncryptedBlockAddress(IRBuilder<NoFolder> &IRB,
                                        BasicBlock *BB,
                                        const BBEncInfo &Info,
                                        IntegerType *intType,
                                        LLVMContext &Ctx) {
  auto *Int8PtrTy = Type::getInt8Ty(Ctx)->getPointerTo();
  uint64_t CombinedKey = (Info.key1 ^ Info.key2) + (Info.key3 ^ Info.key4);
  Value *BA = BlockAddress::get(BB->getParent(), BB);
  Value *AsPtr = IRB.CreateBitCast(BA, Int8PtrTy);
  Value *AsInt = IRB.CreatePtrToInt(AsPtr, intType);
  Value *EncInt =
      IRB.CreateAdd(AsInt, emitSplitKey(IRB, CombinedKey, intType));
  return IRB.CreateIntToPtr(EncInt, Int8PtrTy);
}

static void insertLazyGlobalBranchTableInitializer(
    Function &F, GlobalVariable *GlobalTable,
    const std::unordered_map<BasicBlock *, unsigned> &IndexMap,
    const std::map<BasicBlock *, BBEncInfo> &BBKeys, IntegerType *intType) {
  if (!GlobalTable)
    return;

  SmallVector<BasicBlock *, 16> Blocks;
  for (BasicBlock &BB : F) {
#if LLVM_VERSION_MAJOR <= 12
    if (&BB == &F.getEntryBlock())
      continue;
#else
    if (BB.isEntryBlock())
      continue;
#endif
    if (IndexMap.find(&BB) != IndexMap.end() && BBKeys.find(&BB) != BBKeys.end())
      Blocks.push_back(&BB);
  }
  if (Blocks.empty())
    return;

  Module *M = F.getParent();
  LLVMContext &Ctx = F.getContext();
  auto *i8Ty = Type::getInt8Ty(Ctx);
  ConstantInt *Zero = ConstantInt::get(intType, 0);

  GlobalVariable *InitState = new GlobalVariable(
      *M, i8Ty, false, GlobalValue::PrivateLinkage,
      ConstantInt::get(i8Ty, 0), createObfuscatedName(*M));
  writeObfuscationMetadata(InitState, "nipass.generated");

  BasicBlock &Entry = F.getEntryBlock();
  Instruction *SplitPt = &*Entry.getFirstInsertionPt();
  BasicBlock *ContBB = Entry.splitBasicBlock(SplitPt->getIterator(), "");
  BasicBlock *InitBB = BasicBlock::Create(Ctx, "", &F, ContBB);

  Entry.getTerminator()->eraseFromParent();
  IRBuilder<NoFolder> EntryIRB(&Entry);
  LoadInst *State = EntryIRB.CreateLoad(i8Ty, InitState);
  State->setAtomic(AtomicOrdering::Acquire);
  State->setAlignment(Align(1));
  Value *NeedInit =
      EntryIRB.CreateICmpEQ(State, ConstantInt::get(i8Ty, 0));
  EntryIRB.CreateCondBr(NeedInit, InitBB, ContBB);

  IRBuilder<NoFolder> InitIRB(InitBB);
  for (BasicBlock *BB : Blocks) {
    Value *Idx = ConstantInt::get(intType, IndexMap.at(BB));
    Value *GEP =
        InitIRB.CreateGEP(GlobalTable->getValueType(), GlobalTable, {Zero, Idx});
    Value *EncPtr =
        emitEncryptedBlockAddress(InitIRB, BB, BBKeys.at(BB), intType, Ctx);
    InitIRB.CreateStore(EncPtr, GEP);
  }

  StoreInst *Ready =
      InitIRB.CreateStore(ConstantInt::get(i8Ty, 1), InitState);
  Ready->setAtomic(AtomicOrdering::Release);
  Ready->setAlignment(Align(1));
  InitIRB.CreateBr(ContBB);
}

// === 模块初始化：收集 BB、创建全局加密表 ===

bool EnhancedIndirectBranchPass::initialize(Module &M) {
  // 先对所有待混淆函数运行 LowerSwitchPass
  PassBuilder PB;
  FunctionAnalysisManager FAM;
  FunctionPassManager FPM;
  PB.registerFunctionAnalyses(FAM);
  FPM.addPass(LowerSwitchPass());

  LLVMContext &Ctx = M.getContext();
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();
  const DataLayout &DL = M.getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  // 收集所有非入口 BB
  SmallVector<BasicBlock *, 64> AllBBs;
  unsigned idx = 0;

  for (Function &F : M) {
#if LLVM_VERSION_MAJOR >= 18
    if (F.getSection().starts_with(".init.text") ||
        F.getSection().starts_with(".exit.text"))
      continue;
#else
    if (F.getSection().startswith(".init.text") ||
        F.getSection().startswith(".exit.text"))
      continue;
#endif
    if (!toObfuscate(flag, &F, "eibr"))
      continue;

    to_obf_funcs.insert(&F);
    FPM.run(F, FAM);

    for (BasicBlock &BB : F) {
#if LLVM_VERSION_MAJOR <= 12
      bool isFirst = (&BB == &F.getEntryBlock());
#else
      bool isFirst = BB.isEntryBlock();
#endif
      if (!isFirst) {
        indexmap[&BB] = idx++;
        AllBBs.push_back(&BB);
      }
    }
  }

  if (AllBBs.empty()) {
    this->initialized = true;
    return false;
  }

  // 创建全局表（编译时直接用 ConstantExpr 计算加密值）
  std::string GVName = createObfuscatedName(M);
  std::vector<Constant *> Elements;
  for (BasicBlock *BB : AllBBs) {
    // 为每个 BB 生成 4 个独立密钥
    BBEncInfo Info;
    Info.key1 = cryptoutils->get_uint64_t();
    Info.key2 = cryptoutils->get_uint64_t();
    Info.key3 = cryptoutils->get_uint64_t();
    Info.key4 = cryptoutils->get_uint64_t();
    Info.variant = cryptoutils->get_range(0, 3);
    BBKeys[BB] = Info;

    Constant *Garbage = ConstantExpr::getIntToPtr(
        ConstantInt::get(intType, cryptoutils->get_uint64_t()), i8ptr);
    Elements.push_back(Garbage);
  }

  ArrayType *ATy = ArrayType::get(i8ptr, Elements.size());
  Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
  GlobalTable = new GlobalVariable(M, ATy, false,
                                   GlobalValue::LinkageTypes::PrivateLinkage,
                                   CA, GVName);
  writeObfuscationMetadata(GlobalTable, "nipass.generated");
  appendToCompilerUsed(M, {GlobalTable});

  // 为每个函数生成独立索引编码参数
  unsigned indexBits = intType->getBitWidth();
  for (Function *F : to_obf_funcs)
    funcIndexCodecs[F] = makeBranchIndexCodec(indexBits);

  this->initialized = true;
  return true;
}

// === Pass 入口 ===

PreservedAnalyses EnhancedIndirectBranchPass::run(Function &F,
                                                   FunctionAnalysisManager &FAM) {
  Module *M = F.getParent();

  if (!this->initialized)
    initialize(*M);

  if (to_obf_funcs.find(&F) == to_obf_funcs.end())
    return PreservedAnalyses::all();
  if (readObfuscationMetadata(&F, "envmf.applied"))
    return PreservedAnalyses::all();

  LLVM_DEBUG(dbgs() << "\033[1;36m[EnhancedIndirectBranch] Function : " << F.getName()
                    << "\033[0m\n");

  LLVMContext &Ctx = M->getContext();
  const DataLayout &DL = M->getDataLayout();
  unsigned pointerSize = DL.getPointerSize();
  IntegerType *intType = Type::getInt32Ty(Ctx);
  if (pointerSize == 8)
    intType = Type::getInt64Ty(Ctx);

  Type *Int8PtrTy = Type::getInt8Ty(Ctx)->getPointerTo();
  Value *zero = ConstantInt::get(intType, 0);

  // 获取函数特定的栈使用选项
  bool useStack = EIBRUseStack;
  toObfuscateBoolOption(&F, "eibr_use_stack", &useStack);

  const BranchIndexCodec &indexCodec = funcIndexCodecs[&F];

  // 收集所有分支指令
  SmallVector<BranchInst *, 32> BIs;
  for (Instruction &Inst : instructions(F))
    if (BranchInst *BI = dyn_cast<BranchInst>(&Inst))
      BIs.emplace_back(BI);

  insertLazyGlobalBranchTableInitializer(F, GlobalTable, indexmap, BBKeys,
                                         intType);

  IRBuilder<NoFolder> IRBEntry(&F.getEntryBlock().front());

  for (BranchInst *BI : BIs) {
    if (useStack &&
        IRBEntry.GetInsertPoint() != F.getEntryBlock().begin())
      IRBEntry.SetInsertPoint(F.getEntryBlock().getTerminator());

    IRBuilder<NoFolder> IRBBI(BI);

    // 收集分支目标（跳过入口块）
    SmallVector<BasicBlock *, 2> BBs;
#if LLVM_VERSION_MAJOR <= 12
    if (BI->isConditional() && (BI->getSuccessor(1) != &F.getEntryBlock()))
      BBs.emplace_back(BI->getSuccessor(1));
    if (BI->getSuccessor(0) != &F.getEntryBlock())
      BBs.emplace_back(BI->getSuccessor(0));
#else
    if (BI->isConditional() && !BI->getSuccessor(1)->isEntryBlock())
      BBs.emplace_back(BI->getSuccessor(1));
    if (!BI->getSuccessor(0)->isEntryBlock())
      BBs.emplace_back(BI->getSuccessor(0));
#endif

    if (BBs.empty())
      continue;
    if (BI->isConditional() && BBs.size() != 2)
      continue;

    GlobalVariable *LoadFrom = nullptr;

    if (BI->isConditional() ||
        indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
      // === 条件分支 / 目标不在全局表 → 创建局部加密表 ===
      std::vector<Constant *> LocalElements;
      std::vector<BBEncInfo> LocalKeys;
      std::vector<unsigned> LocalSlots;
      for (unsigned i = 0; i < BBs.size(); ++i)
        LocalSlots.push_back(i);
      for (size_t i = LocalSlots.size(); i > 1; --i)
        std::swap(LocalSlots[i - 1], LocalSlots[cryptoutils->get_range(i)]);

      for (unsigned LogicalSlot = 0; LogicalSlot < BBs.size(); ++LogicalSlot) {
        BBEncInfo Info;
        Info.key1 = cryptoutils->get_uint64_t();
        Info.key2 = cryptoutils->get_uint64_t();
        Info.key3 = cryptoutils->get_uint64_t();
        Info.key4 = cryptoutils->get_uint64_t();
        Info.variant = cryptoutils->get_range(0, 3);
        LocalKeys.push_back(Info);

        Constant *Garbage = ConstantExpr::getIntToPtr(
            ConstantInt::get(intType, cryptoutils->get_uint64_t()), Int8PtrTy);
        LocalElements.push_back(Garbage);
      }

      ArrayType *LocalATy = ArrayType::get(Int8PtrTy, LocalElements.size());
      Constant *LocalCA =
          ConstantArray::get(LocalATy, ArrayRef<Constant *>(LocalElements));
      std::string LocalName = createObfuscatedName(*M);
      LoadFrom = new GlobalVariable(*M, LocalATy, false,
                                     GlobalValue::LinkageTypes::PrivateLinkage,
                                     LocalCA, LocalName);
      writeObfuscationMetadata(LoadFrom, "nipass.generated");
      appendToCompilerUsed(*M, {LoadFrom});

      for (unsigned LogicalSlot = 0; LogicalSlot < BBs.size(); ++LogicalSlot) {
        Value *Idx = ConstantInt::get(intType, LocalSlots[LogicalSlot]);
        Value *GEP =
            IRBBI.CreateGEP(LoadFrom->getValueType(), LoadFrom, {zero, Idx});
        Value *EncPtr = emitEncryptedBlockAddress(
            IRBBI, BBs[LogicalSlot], LocalKeys[LogicalSlot], intType, Ctx);
        IRBBI.CreateStore(EncPtr, GEP);
      }

      AllocaInst *LoadFromAI = nullptr;
      if (useStack) {
        LoadFromAI = IRBEntry.CreateAlloca(LoadFrom->getType());
        IRBEntry.CreateStore(LoadFrom, LoadFromAI);
      }

      auto CreateLocalDecodeBlock = [&](unsigned LogicalSlot) -> BasicBlock * {
        BasicBlock *DecodeBB = BasicBlock::Create(Ctx, "", &F);
        IRBuilder<NoFolder> DecodeIRB(DecodeBB);
        Value *TablePtr = LoadFrom;
        if (useStack)
          TablePtr = DecodeIRB.CreateLoad(LoadFrom->getType(), LoadFromAI);
        Value *Idx = ConstantInt::get(intType, LocalSlots[LogicalSlot]);
        Value *GEP = DecodeIRB.CreateGEP(LoadFrom->getValueType(), TablePtr,
                                         {zero, Idx});
        Value *EncPtr = DecodeIRB.CreateLoad(Int8PtrTy, GEP);
        Value *DecPtr =
            emitDecrypt4Key(DecodeIRB, EncPtr, LocalKeys[LogicalSlot],
                            intType, Ctx);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, 1, DecodeBB);
        indirBr->addDestination(BBs[LogicalSlot]);
        redirectPHIIncomingBlock(BBs[LogicalSlot], BI->getParent(), DecodeBB);
        return DecodeBB;
      };

      if (BI->isConditional()) {
        BasicBlock *FalseDecodeBB = CreateLocalDecodeBlock(0);
        BasicBlock *TrueDecodeBB = CreateLocalDecodeBlock(1);
        BranchInst *NewBr =
            BranchInst::Create(TrueDecodeBB, FalseDecodeBB,
                               BI->getCondition());
        ReplaceInstWithInst(BI, NewBr);
      } else {
        BasicBlock *DecodeBB = CreateLocalDecodeBlock(0);
        ReplaceInstWithInst(BI, BranchInst::Create(DecodeBB));
      }
    } else {
      // === 无条件分支 → 使用全局表 ===
      BasicBlock *Target = BI->getSuccessor(0);
      unsigned realIdx = indexmap[Target];
      uint64_t encodedIdx =
          encodeBranchIndex(realIdx, indexCodec, intType->getBitWidth());
      Value *RealIdxVal =
          emitDecodeBranchIndex(IRBBI, encodedIdx, indexCodec, intType);

      if (useStack) {
        AllocaInst *LoadFromAI = IRBEntry.CreateAlloca(GlobalTable->getType());
        IRBEntry.CreateStore(GlobalTable, LoadFromAI);
        AllocaInst *idxAI = IRBEntry.CreateAlloca(intType);
        IRBBI.CreateStore(RealIdxVal, idxAI);

        LoadInst *LILoadFrom =
            IRBBI.CreateLoad(GlobalTable->getType(), LoadFromAI);
        Value *idxLoad = IRBBI.CreateLoad(intType, idxAI);
        Value *GEP = IRBBI.CreateGEP(GlobalTable->getValueType(), LILoadFrom,
                                      {zero, idxLoad});
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        const BBEncInfo &Info = BBKeys[Target];
        Value *DecPtr = emitDecrypt4Key(IRBBI, EncPtr, Info, intType, Ctx);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      } else {
        Value *GEP = IRBBI.CreateGEP(GlobalTable->getValueType(), GlobalTable,
                                      {zero, RealIdxVal});
        Value *EncPtr = IRBBI.CreateLoad(Int8PtrTy, GEP);

        const BBEncInfo &Info = BBKeys[Target];
        Value *DecPtr = emitDecrypt4Key(IRBBI, EncPtr, Info, intType, Ctx);

        IndirectBrInst *indirBr = IndirectBrInst::Create(DecPtr, BBs.size());
        for (BasicBlock *BB : BBs)
          indirBr->addDestination(BB);
        ReplaceInstWithInst(BI, indirBr);
      }
    }
  }

  shuffleBasicBlocks(F);
  return PreservedAnalyses::none();
}

// 随机打乱函数中基本块的顺序
void EnhancedIndirectBranchPass::shuffleBasicBlocks(Function &F) {
  SmallVector<BasicBlock *, 32> blocks;
  for (BasicBlock &block : F) {
#if LLVM_VERSION_MAJOR <= 12
    if (&block != &F.getEntryBlock())
      blocks.emplace_back(&block);
#else
    if (!block.isEntryBlock())
      blocks.emplace_back(&block);
#endif
  }

  if (blocks.size() < 2)
    return;

  // Fisher-Yates 洗牌
  for (size_t i = blocks.size() - 1; i > 0; i--)
    std::swap(blocks[i], blocks[cryptoutils->get_range(i + 1)]);

  BasicBlock *prev = &F.getEntryBlock();
  for (BasicBlock *block : blocks) {
    block->moveAfter(prev);
    prev = block;
  }
}

} // namespace ni_pass

// EnhancedStringEncryption.cpp - 增强型字符串加密混淆Pass
// 基于 StringEncryption.cpp，增加以下安全增强：
// 1. GV/BB/指令名随机化  2. XOR密钥混淆(SubstituteImpl)
// 3. 多层异构加密  4. DecryptSpace生命周期管理  5. 独立副本(取消共享)
//===----------------------------------------------------------------------===//
#include "EncPass/EnhancedStringEncryption.h"
#include "EncPass/EncryptUtils.h"
#include "CryptoUtils.h"
#include "SubstituteImpl.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#define DEBUG_TYPE "enhancedstringencryption"
#include <unordered_set>

using namespace llvm;

// 命令行选项
static cl::opt<uint32_t>
    ElementEncryptProb("enstrcry_prob", cl::init(100), cl::NotHidden,
                       cl::desc("Probability [%] each element will be "
                                "obfuscated by the enhanced strenc pass"));
static uint32_t ElementEncryptProbTemp = 100;

static cl::opt<uint32_t>
    StrEncSubXorProb("enstrcry_subxor_prob", cl::init(50), cl::NotHidden,
                     cl::desc("Probability [%] each XOR in string decryption "
                              "will be substituted with complex expression"));
static uint32_t StrEncSubXorProbTemp = 50;

static cl::opt<bool>
    StrEncCleanup("enstrcry_cleanup", cl::init(true), cl::NotHidden,
                  cl::desc("Zero DecryptSpace on function return"));
static bool StrEncCleanupTemp = true;

namespace ni_pass {

static uint64_t nextRollingKey(uint64_t key, uint64_t mul, uint64_t inc,
                               unsigned bits) {
  uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
  key = (key * mul + inc) & mask;
  key ^= (key >> ((bits >= 16) ? 7 : 3));
  key &= mask;
  return key;
}

static Value *emitNextRollingKey(IRBuilder<> &IRB, Value *key,
                                 Value *mul, Value *inc,
                                 IntegerType *intType) {
  unsigned bits = intType->getBitWidth();
  Value *next = IRB.CreateAdd(IRB.CreateMul(key, mul), inc);
  next = IRB.CreateXor(next, IRB.CreateLShr(
                                 next, ConstantInt::get(intType,
                                                        bits >= 16 ? 7 : 3)));
  return next;
}

//===----------------------------------------------------------------------===//
// handleableGV / processConstantAggregate / HandleUser — 与原版相同
//===----------------------------------------------------------------------===//

bool EnhancedStringEncryptionPass::handleableGV(GlobalVariable *GV) {
#if LLVM_VERSION_MAJOR >= 18
  if (GV->hasInitializer() && !GV->getSection().starts_with("llvm.") &&
#else
  if (GV->hasInitializer() && !GV->getSection().startswith("llvm.") &&
#endif
      !(GV->getSection().find("__objc") != std::string::npos &&
        GV->getSection().find("array") == std::string::npos) &&
      GV->getName().find("OBJC") == std::string::npos &&
      std::find(genedgv.begin(), genedgv.end(), GV) == genedgv.end() &&
      ((GV->getLinkage() == GlobalValue::LinkageTypes::PrivateLinkage ||
        GV->getLinkage() == GlobalValue::LinkageTypes::InternalLinkage) &&
       (flag || AreUsersInOneFunction(GV))))
    return true;
  return false;
}

void EnhancedStringEncryptionPass::processConstantAggregate(
    GlobalVariable *strGV, ConstantAggregate *CA,
    std::unordered_set<GlobalVariable *> *rawStrings,
    SmallVector<GlobalVariable *, 32> *unhandleablegvs,
    SmallVector<GlobalVariable *, 32> *Globals,
    std::unordered_set<User *> *Users, bool *breakFor) {
  for (unsigned i = 0; i < CA->getNumOperands(); i++) {
    Constant *Op = CA->getOperand(i);
    if (GlobalVariable *GV =
            dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
      if (!handleableGV(GV)) {
        unhandleablegvs->emplace_back(GV);
        continue;
      }
      Users->insert(opaquepointers ? CA : Op);
      if (std::find(Globals->begin(), Globals->end(), GV) == Globals->end()) {
        Globals->emplace_back(GV);
        *breakFor = true;
      }
    } else if (ConstantAggregate *NestedCA =
                   dyn_cast<ConstantAggregate>(Op)) {
      processConstantAggregate(strGV, NestedCA, rawStrings, unhandleablegvs,
                               Globals, Users, breakFor);
    } else if (isa<ConstantDataSequential>(Op)) {
      if (CA->getNumOperands() != 1)
        continue;
      Users->insert(CA);
      rawStrings->insert(strGV);
    }
  }
}

void EnhancedStringEncryptionPass::HandleUser(
    User *U, SmallVector<GlobalVariable *, 32> &Globals,
    std::unordered_set<User *> &Users,
    std::unordered_set<User *> &VisitedUsers) {
  VisitedUsers.emplace(U);
  for (Value *Op : U->operands()) {
    if (GlobalVariable *G =
            dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
      if (User *U2 = dyn_cast<User>(Op))
        Users.insert(U2);
      Users.insert(U);
      Globals.emplace_back(G);
    } else if (User *InnerU = dyn_cast<User>(Op)) {
      if (!VisitedUsers.count(InnerU))
        HandleUser(InnerU, Globals, Users, VisitedUsers);
    }
  }
}

//===----------------------------------------------------------------------===//
// HandleFunction — 改动三(多层加密) + 改动四a(独立副本)
//===----------------------------------------------------------------------===//

// 辅助宏：为每种整数宽度生成加密循环
#define ENCRYPT_LOOP(T, get_key_fn)                                            \
  {                                                                            \
    std::vector<T> keys, encry, dummy, keys2, keys3;                           \
    if (useRollingKey) {                                                       \
      uint64_t key = rollingSeed;                                              \
      for (unsigned i = 0; i < CDS->getNumElements(); i++) {                   \
        key = nextRollingKey(key, rollingMul, rollingInc,                      \
                             intType->getBitWidth());                          \
        const T K1 = static_cast<T>(key);                                      \
        const uint64_t V = CDS->getElementAsInteger(i);                       \
        dummy.emplace_back(static_cast<T>(cryptoutils->get_key_fn()));         \
        encry.emplace_back(static_cast<T>(V ^ K1));                            \
      }                                                                        \
    } else for (unsigned i = 0; i < CDS->getNumElements(); i++) {              \
      if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {             \
        unencryptedindex[GV].emplace_back(i);                                  \
        keys.emplace_back(1);                                                  \
        dummy.emplace_back(static_cast<T>(CDS->getElementAsInteger(i)));       \
        if (pattern == StrEncPattern::XOR_SUB ||                               \
            pattern == StrEncPattern::XOR_ADD)                                  \
          keys2.emplace_back(0);                                               \
        if (pattern == StrEncPattern::XOR_ADD_XOR) {                           \
          keys2.emplace_back(0);                                               \
          keys3.emplace_back(0);                                               \
        }                                                                      \
        continue;                                                              \
      }                                                                        \
      const T K1 = static_cast<T>(cryptoutils->get_key_fn());                 \
      const uint64_t V = CDS->getElementAsInteger(i);                         \
      keys.emplace_back(K1);                                                   \
      dummy.emplace_back(static_cast<T>(cryptoutils->get_key_fn()));           \
      switch (pattern) {                                                       \
      case StrEncPattern::XOR_ONLY:                                            \
        encry.emplace_back(static_cast<T>(V ^ K1));                            \
        break;                                                                 \
      case StrEncPattern::XOR_SUB: {                                           \
        T K2 = static_cast<T>(cryptoutils->get_key_fn());                     \
        keys2.emplace_back(K2);                                                \
        encry.emplace_back(static_cast<T>((V ^ K1) - K2));                    \
        break;                                                                 \
      }                                                                        \
      case StrEncPattern::XOR_ADD: {                                           \
        T K2 = static_cast<T>(cryptoutils->get_key_fn());                     \
        keys2.emplace_back(K2);                                                \
        encry.emplace_back(static_cast<T>((V ^ K1) + K2));                    \
        break;                                                                 \
      }                                                                        \
      case StrEncPattern::XOR_ADD_XOR: {                                       \
        T K2 = static_cast<T>(cryptoutils->get_key_fn());                     \
        T K3 = static_cast<T>(cryptoutils->get_key_fn());                     \
        keys2.emplace_back(K2);                                                \
        keys3.emplace_back(K3);                                                \
        encry.emplace_back(static_cast<T>(((V ^ K1) + K2) ^ K3));             \
        break;                                                                 \
      }                                                                        \
      default:                                                                 \
        encry.emplace_back(static_cast<T>(V ^ K1));                            \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
    if (!useRollingKey)                                                        \
      KeyConst =                                                               \
          ConstantDataArray::get(M->getContext(), ArrayRef<T>(keys));           \
    EncryptedConst =                                                           \
        ConstantDataArray::get(M->getContext(), ArrayRef<T>(encry));            \
    DummyConst =                                                               \
        ConstantDataArray::get(M->getContext(), ArrayRef<T>(dummy));            \
    if (!keys2.empty())                                                        \
      Key2Const =                                                              \
          ConstantDataArray::get(M->getContext(), ArrayRef<T>(keys2));          \
    if (!keys3.empty())                                                        \
      Key3Const =                                                              \
          ConstantDataArray::get(M->getContext(), ArrayRef<T>(keys3));          \
  }

void EnhancedStringEncryptionPass::HandleFunction(Function *Func) {
  FixFunctionConstantExpr(Func);

  SmallVector<GlobalVariable *, 32> Globals;
  std::unordered_set<User *> Users;
  {
    std::unordered_set<User *> VisitedUsers;
    for (Instruction &I : instructions(Func))
      HandleUser(&I, Globals, Users, VisitedUsers);
  }

  std::unordered_set<GlobalVariable *> rawStrings;
  std::unordered_set<GlobalVariable *> objCStrings;
  std::unordered_map<GlobalVariable *, StrEncInfo> GV2Info;
  std::unordered_map<GlobalVariable *,
                     std::pair<GlobalVariable *, GlobalVariable *>>
      old2new;

  auto endIt = Globals.end();
  for (auto it = Globals.begin(); it != endIt; ++it)
    endIt = std::remove(it + 1, endIt, *it);
  Globals.erase(endIt, Globals.end());

  Module *M = Func->getParent();
  SmallVector<GlobalVariable *, 32> transedGlobals, unhandleablegvs;

  do {
    for (GlobalVariable *GV : Globals) {
      if (std::find(transedGlobals.begin(), transedGlobals.end(), GV) ==
          transedGlobals.end()) {
        bool breakThisFor = false;
        if (handleableGV(GV)) {
          if (GlobalVariable *CastedGV = dyn_cast<GlobalVariable>(
                  GV->getInitializer()->stripPointerCasts())) {
            if (std::find(Globals.begin(), Globals.end(), CastedGV) ==
                Globals.end()) {
              Globals.emplace_back(CastedGV);
              ConstantExpr *CE = dyn_cast<ConstantExpr>(GV->getInitializer());
              Users.insert(CE ? CE : GV->getInitializer());
              breakThisFor = true;
            }
          }
          if (GV->getInitializer()->getType() ==
              StructType::getTypeByName(M->getContext(),
                                        "struct.__NSConstantString_tag")) {
            objCStrings.insert(GV);
            rawStrings.insert(cast<GlobalVariable>(
                cast<ConstantStruct>(GV->getInitializer())
                    ->getOperand(2)
                    ->stripPointerCasts()));
          } else if (isa<ConstantDataSequential>(GV->getInitializer())) {
            rawStrings.insert(GV);
          } else if (ConstantAggregate *CA =
                         dyn_cast<ConstantAggregate>(GV->getInitializer())) {
            processConstantAggregate(GV, CA, &rawStrings, &unhandleablegvs,
                                     &Globals, &Users, &breakThisFor);
          }
        } else {
          unhandleablegvs.emplace_back(GV);
        }
        transedGlobals.emplace_back(GV);
        if (breakThisFor)
          break;
      }
    }
  } while (transedGlobals.size() != Globals.size());

  for (GlobalVariable *ugv : unhandleablegvs)
    if (std::find(genedgv.begin(), genedgv.end(), ugv) != genedgv.end()) {
      if (ugv->getInitializer()->getType() ==
          StructType::getTypeByName(M->getContext(),
                                    "struct.__NSConstantString_tag")) {
        GlobalVariable *rawgv =
            cast<GlobalVariable>(cast<ConstantStruct>(ugv->getInitializer())
                                     ->getOperand(2)
                                     ->stripPointerCasts());
        auto it = mgv2info.find(rawgv);
        if (it != mgv2info.end())
          GV2Info[rawgv] = it->second;
      } else {
        auto it = mgv2info.find(ugv);
        if (it != mgv2info.end())
          GV2Info[ugv] = it->second;
      }
    }

  // 改动四a：取消跨函数共享，每个函数独立创建加密副本
  for (GlobalVariable *GV : rawStrings) {
    if (GV->getInitializer()->isZeroValue() ||
        GV->getInitializer()->isNullValue())
      continue;

    ConstantDataSequential *CDS =
        dyn_cast<ConstantDataSequential>(GV->getInitializer());
    bool rust_string = !CDS;
    if (rust_string)
      CDS = cast<ConstantDataSequential>(
          cast<ConstantAggregate>(GV->getInitializer())->getOperand(0));

    Type *ElementTy = CDS->getElementType();
    if (!ElementTy->isIntegerTy())
      continue;

    IntegerType *intType = cast<IntegerType>(ElementTy);
    Constant *KeyConst = nullptr, *EncryptedConst = nullptr,
             *DummyConst = nullptr;
    Constant *Key2Const = nullptr, *Key3Const = nullptr;
    unencryptedindex[GV] = {};

    StrEncPattern pattern = static_cast<StrEncPattern>(
        cryptoutils->get_range(static_cast<uint32_t>(StrEncPattern::COUNT)));
    bool useRollingKey = ElementEncryptProbTemp == 100 &&
                         cryptoutils->get_range(100) < 50;
    uint64_t rollingSeed = 0, rollingMul = 0, rollingInc = 0;
    if (useRollingKey) {
      pattern = StrEncPattern::XOR_ONLY;
      rollingSeed = cryptoutils->get_uint64_t();
      rollingMul = cryptoutils->get_uint64_t() | 1;
      rollingInc = cryptoutils->get_uint64_t() | 1;
    }

    if (intType == Type::getInt8Ty(M->getContext())) {
      ENCRYPT_LOOP(uint8_t, get_uint8_t)
    } else if (intType == Type::getInt16Ty(M->getContext())) {
      ENCRYPT_LOOP(uint16_t, get_uint16_t)
    } else if (intType == Type::getInt32Ty(M->getContext())) {
      ENCRYPT_LOOP(uint32_t, get_uint32_t)
    } else if (intType == Type::getInt64Ty(M->getContext())) {
      ENCRYPT_LOOP(uint64_t, get_uint64_t)
    } else {
      llvm_unreachable("Unsupported CDS Type");
    }

    std::string EncryptedName = createObfuscatedName(*M);
    GlobalVariable *EncryptedRawGV = new GlobalVariable(
        *M, EncryptedConst->getType(), false, GV->getLinkage(),
        EncryptedConst, EncryptedName, nullptr, GV->getThreadLocalMode(),
        GV->getType()->getAddressSpace());
    genedgv.emplace_back(EncryptedRawGV);

    GlobalVariable *DecryptSpaceGV;
    std::string DecryptName = createObfuscatedName(*M);
    if (rust_string) {
      ConstantAggregate *CA = cast<ConstantAggregate>(GV->getInitializer());
      CA->setOperand(0, DummyConst);
      DecryptSpaceGV = new GlobalVariable(
          *M, GV->getValueType(), false, GV->getLinkage(), CA,
          DecryptName, nullptr, GV->getThreadLocalMode(),
          GV->getType()->getAddressSpace());
    } else {
      DecryptSpaceGV = new GlobalVariable(
          *M, DummyConst->getType(), false, GV->getLinkage(), DummyConst,
          DecryptName, nullptr, GV->getThreadLocalMode(),
          GV->getType()->getAddressSpace());
    }
    genedgv.emplace_back(DecryptSpaceGV);

    old2new[GV] = std::make_pair(EncryptedRawGV, DecryptSpaceGV);
    StrEncInfo Info;
    Info.KeyConst = KeyConst;
    Info.EncryptedGV = EncryptedRawGV;
    Info.Key2Const = Key2Const;
    Info.Key3Const = Key3Const;
    Info.Pattern = pattern;
    Info.RollingKey = useRollingKey;
    Info.RollingSeed = rollingSeed;
    Info.RollingMul = rollingMul;
    Info.RollingInc = rollingInc;
    GV2Info[DecryptSpaceGV] = Info;
    mgv2keys[DecryptSpaceGV] = std::make_pair(KeyConst, EncryptedRawGV);
    mgv2info[DecryptSpaceGV] = Info;
    if (KeyConst)
      unencryptedindex[KeyConst] = unencryptedindex[GV];
    globalProcessedGVs.insert(GV);
  }

  // ObjC字符串
  for (GlobalVariable *GV : objCStrings) {
    ConstantStruct *CS = cast<ConstantStruct>(GV->getInitializer());
    GlobalVariable *oldrawString =
        cast<GlobalVariable>(CS->getOperand(2)->stripPointerCasts());
    if (old2new.find(oldrawString) == old2new.end())
      continue;
    GlobalVariable *EncryptedOCGV = ObjectiveCString(
        GV, "", old2new[oldrawString].first, CS);
    genedgv.emplace_back(EncryptedOCGV);
    GlobalVariable *DecryptSpaceOCGV = ObjectiveCString(
        GV, "", old2new[oldrawString].second, CS);
    genedgv.emplace_back(DecryptSpaceOCGV);
    old2new[GV] = std::make_pair(EncryptedOCGV, DecryptSpaceOCGV);
  }

  if (GV2Info.empty())
    return;

  // 替换所有使用
  for (User *U : Users) {
    for (auto iter = old2new.begin(); iter != old2new.end(); ++iter) {
      if (isa<Constant>(U) && !isa<GlobalValue>(U)) {
        Constant *CC = cast<Constant>(U);
        for (Value *Op : CC->operands())
          if (Op == iter->first) {
            CC->handleOperandChange(iter->first, iter->second.second);
            break;
          }
      } else
        U->replaceUsesOfWith(iter->first, iter->second.second);
      iter->first->removeDeadConstantUsers();
    }
  }

  // 清理旧ObjC全局变量
  for (GlobalVariable *GV : objCStrings) {
    GlobalVariable *PtrauthGV = nullptr;
    if (appleptrauth) {
      Constant *CC = dyn_cast_or_null<Constant>(
          opaquepointers
              ? GV->getInitializer()
              : cast<ConstantExpr>(GV->getInitializer()->getOperand(0)));
      if (CC) {
        PtrauthGV = dyn_cast<GlobalVariable>(CC->getOperand(0));
        if (PtrauthGV->getSection() == "llvm.ptrauth") {
          if (ConstantExpr *CE = dyn_cast<ConstantExpr>(
                  PtrauthGV->getInitializer()->getOperand(2))) {
            if (GlobalVariable *GV2 =
                    dyn_cast<GlobalVariable>(CE->getOperand(0))) {
              if (GV->getNumUses() <= 1 &&
#if LLVM_VERSION_MAJOR >= 21
                  GV2 == GV)
#else
                  GV2->getGlobalIdentifier() == GV->getGlobalIdentifier())
#endif
                PtrauthGV->getInitializer()->setOperand(
                    2, ConstantExpr::getPtrToInt(
                           M->getGlobalVariable(
                               "__CFConstantStringClassReference"),
                           Type::getInt64Ty(M->getContext())));
            }
          } else if (GlobalVariable *GV2 = dyn_cast<GlobalVariable>(
                         PtrauthGV->getInitializer()->getOperand(2)))
            if (GV->getNumUses() <= 1 &&
#if LLVM_VERSION_MAJOR >= 21
                GV2 == GV)
#else
                GV2->getGlobalIdentifier() == GV->getGlobalIdentifier())
#endif
              PtrauthGV->getInitializer()->setOperand(
                  2, ConstantExpr::getPtrToInt(
                         M->getGlobalVariable(
                             "__CFConstantStringClassReference"),
                         Type::getInt64Ty(M->getContext())));
        }
      }
    }
    GV->removeDeadConstantUsers();
    if (GV->getNumUses() == 0) {
      GV->dropAllReferences();
      old2new.erase(GV);
      GV->eraseFromParent();
    }
    if (PtrauthGV) {
      PtrauthGV->removeDeadConstantUsers();
      if (PtrauthGV->getNumUses() == 0) {
        PtrauthGV->dropAllReferences();
        PtrauthGV->eraseFromParent();
      }
    }
  }

  // ---- 构建解密入口 ----
  GlobalVariable *StatusGV = encstatus[Func];
  BasicBlock *A = &(Func->getEntryBlock());
  BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
  C->setName("");
  BasicBlock *B = BasicBlock::Create(Func->getContext(), "", Func, C);
  BranchInst *newBr = BranchInst::Create(B);
  ReplaceInstWithInst(A->getTerminator(), newBr);

  HandleDecryptionBlock(B, C, GV2Info);

  // 改动四b：EncStatus 改为引用计数（atomicrmw add）
#if LLVM_VERSION_MAJOR < 20
  IRBuilder<> IRB(A->getFirstNonPHIOrDbgOrLifetime());
#else
  Instruction *InsertPt = &*A->getFirstNonPHIOrDbgOrLifetime();
  IRBuilder<> IRB(InsertPt);
#endif

  Value *OldCount = IRB.CreateAtomicRMW(
      AtomicRMWInst::Add, StatusGV,
      ConstantInt::get(Type::getInt32Ty(Func->getContext()), 1),
      Align(4), AtomicOrdering::Acquire);
  Value *condition = IRB.CreateICmpEQ(
      OldCount, ConstantInt::get(Type::getInt32Ty(Func->getContext()), 0));
  A->getTerminator()->eraseFromParent();
  BranchInst::Create(B, C, condition, A);

  // 改动四c/d：在函数出口插入清零逻辑
  if (StrEncCleanupTemp)
    InsertCleanupAtReturns(Func, StatusGV, GV2Info);
}

#undef ENCRYPT_LOOP

//===----------------------------------------------------------------------===//
// ObjectiveCString — 与原版相同，名字参数由调用方传入""
//===----------------------------------------------------------------------===//

GlobalVariable *EnhancedStringEncryptionPass::ObjectiveCString(
    GlobalVariable *GV, std::string name, GlobalVariable *newString,
    ConstantStruct *CS) {
  Value *zero = ConstantInt::get(Type::getInt32Ty(GV->getContext()), 0);
  SmallVector<Constant *, 4> vals;
  vals.emplace_back(CS->getOperand(0));
  vals.emplace_back(CS->getOperand(1));

  Constant *GEPed = ConstantExpr::getInBoundsGetElementPtr(
      newString->getValueType(), newString, {zero, zero});
  if (GEPed->getType() == CS->getOperand(2)->getType()) {
    vals.emplace_back(GEPed);
  } else {
    Constant *BitCasted =
        ConstantExpr::getBitCast(newString, CS->getOperand(2)->getType());
    vals.emplace_back(BitCasted);
  }
  vals.emplace_back(CS->getOperand(3));

  Constant *newCS =
      ConstantStruct::get(CS->getType(), ArrayRef<Constant *>(vals));
  GlobalVariable *ObjcGV = new GlobalVariable(
      *(GV->getParent()), newCS->getType(), false, GV->getLinkage(), newCS,
      name, nullptr, GV->getThreadLocalMode(),
      GV->getType()->getAddressSpace());

  if (appleptrauth) {
    Constant *C = dyn_cast_or_null<Constant>(
        opaquepointers ? newCS : cast<ConstantExpr>(newCS->getOperand(0)));
    GlobalVariable *PtrauthGV = dyn_cast<GlobalVariable>(C->getOperand(0));
    if (PtrauthGV && PtrauthGV->getSection() == "llvm.ptrauth") {
      GlobalVariable *NewPtrauthGV = new GlobalVariable(
          *PtrauthGV->getParent(), PtrauthGV->getValueType(), true,
          PtrauthGV->getLinkage(),
          ConstantStruct::getAnon(
              {(Constant *)PtrauthGV->getInitializer()->getOperand(0),
               (ConstantInt *)PtrauthGV->getInitializer()->getOperand(1),
               ConstantExpr::getPtrToInt(
                   ObjcGV, Type::getInt64Ty(ObjcGV->getContext())),
               (ConstantInt *)PtrauthGV->getInitializer()->getOperand(3)},
              false),
          PtrauthGV->getName(), nullptr, PtrauthGV->getThreadLocalMode());
      NewPtrauthGV->setSection("llvm.ptrauth");
      NewPtrauthGV->setAlignment(Align(8));
      ObjcGV->getInitializer()->setOperand(
          0,
          ConstantExpr::getBitCast(
              NewPtrauthGV,
              Type::getInt32Ty(NewPtrauthGV->getContext())->getPointerTo()));
    }
  }
  return ObjcGV;
}

//===----------------------------------------------------------------------===//
// HandleDecryptionBlock — 改动二(SubstituteXor) + 改动三(多层解密)
//===----------------------------------------------------------------------===//

void EnhancedStringEncryptionPass::HandleDecryptionBlock(
    BasicBlock *B, BasicBlock *C,
    std::unordered_map<GlobalVariable *, StrEncInfo> &GV2Info) {
  IRBuilder<> IRB(B);
  Value *zero = ConstantInt::get(Type::getInt32Ty(B->getContext()), 0);

  for (auto &iter : GV2Info) {
    GlobalVariable *DecryptGV = iter.first;
    StrEncInfo &info = iter.second;

    bool rust_string =
        !isa<ConstantDataSequential>(DecryptGV->getInitializer());
    ConstantAggregate *CA =
        rust_string ? cast<ConstantAggregate>(DecryptGV->getInitializer())
                    : nullptr;

    ConstantDataArray *CastedCDA =
        info.KeyConst ? cast<ConstantDataArray>(info.KeyConst) : nullptr;
    ConstantDataArray *CastedCDA2 =
        info.Key2Const ? cast<ConstantDataArray>(info.Key2Const) : nullptr;
    ConstantDataArray *CastedCDA3 =
        info.Key3Const ? cast<ConstantDataArray>(info.Key3Const) : nullptr;

    appendToCompilerUsed(*info.EncryptedGV->getParent(), {info.EncryptedGV});

    uint64_t realkeyoff = 0;
    uint64_t numElements =
        info.RollingKey
            ? cast<ArrayType>(info.EncryptedGV->getValueType())->getNumElements()
            : CastedCDA->getType()->getNumElements();
    Value *RollingKey = nullptr;
    IntegerType *ElemTy = nullptr;
    if (info.RollingKey) {
      ElemTy = cast<IntegerType>(
          cast<ArrayType>(info.EncryptedGV->getValueType())->getElementType());
      RollingKey = emitSplitKey(IRB, info.RollingSeed, ElemTy);
    }
    Value *RollingMul = nullptr;
    Value *RollingInc = nullptr;
    if (info.RollingKey) {
      RollingMul = emitSplitKey(IRB, info.RollingMul, ElemTy);
      RollingInc = emitSplitKey(IRB, info.RollingInc, ElemTy);
    }

    for (uint64_t i = 0; i < numElements; i++) {
      if (!info.RollingKey && unencryptedindex[info.KeyConst].size() &&
          std::find(unencryptedindex[info.KeyConst].begin(),
                    unencryptedindex[info.KeyConst].end(),
                    i) != unencryptedindex[info.KeyConst].end())
        continue;

      Value *offset =
          ConstantInt::get(Type::getInt64Ty(B->getContext()), realkeyoff);
      Value *offset2 =
          ConstantInt::get(Type::getInt64Ty(B->getContext()), i);

      Value *EncryptedGEP =
          IRB.CreateGEP(info.EncryptedGV->getValueType(),
                        info.EncryptedGV, {zero, offset});

      Value *DecryptedGEP =
          rust_string
              ? IRB.CreateGEP(
                    CA->getOperand(0)->getType(),
                    IRB.CreateGEP(
                        CA->getType(), DecryptGV,
                        {zero, ConstantInt::getNullValue(
                                   Type::getInt64Ty(B->getContext()))}),
                    {zero, offset2})
              : IRB.CreateGEP(DecryptGV->getValueType(), DecryptGV,
                              {zero, offset2});

	      // 改动一：指令名随机化
      Type *LoadTy = info.RollingKey ? ElemTy : CastedCDA->getElementType();
      LoadInst *LI = IRB.CreateLoad(LoadTy, EncryptedGEP,
	                                    ""); // 原为 "EncryptedChar"

	      // 改动三：按模式生成逆运算
      Value *Result = LI;
      if (info.RollingKey)
        RollingKey = emitNextRollingKey(IRB, RollingKey, RollingMul,
                                        RollingInc, ElemTy);
      switch (info.Pattern) {
      case StrEncPattern::XOR_ONLY: {
        // load → xor(K1) → store
        BinaryOperator *XORInst = BinaryOperator::Create(
            Instruction::Xor, Result,
            info.RollingKey ? RollingKey : CastedCDA->getElementAsConstant(i));
        IRB.Insert(XORInst);
        // 改动二：SubstituteXor
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteXor(XORInst);
        Result = XORInst;
        break;
      }
      case StrEncPattern::XOR_SUB: {
        // load → add(K2) → xor(K1) → store
        BinaryOperator *AddInst = BinaryOperator::Create(
            Instruction::Add, Result,
            CastedCDA2->getElementAsConstant(i));
        IRB.Insert(AddInst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteAdd(AddInst);
        BinaryOperator *XORInst = BinaryOperator::Create(
            Instruction::Xor, AddInst, CastedCDA->getElementAsConstant(i));
        IRB.Insert(XORInst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteXor(XORInst);
        Result = XORInst;
        break;
      }
      case StrEncPattern::XOR_ADD: {
        // load → sub(K2) → xor(K1) → store
        BinaryOperator *SubInst = BinaryOperator::Create(
            Instruction::Sub, Result,
            CastedCDA2->getElementAsConstant(i));
        IRB.Insert(SubInst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteSub(SubInst);
        BinaryOperator *XORInst = BinaryOperator::Create(
            Instruction::Xor, SubInst, CastedCDA->getElementAsConstant(i));
        IRB.Insert(XORInst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteXor(XORInst);
        Result = XORInst;
        break;
      }
      case StrEncPattern::XOR_ADD_XOR: {
        // load → xor(K3) → sub(K2) → xor(K1) → store
        BinaryOperator *XOR3Inst = BinaryOperator::Create(
            Instruction::Xor, Result,
            CastedCDA3->getElementAsConstant(i));
        IRB.Insert(XOR3Inst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteXor(XOR3Inst);
        BinaryOperator *SubInst = BinaryOperator::Create(
            Instruction::Sub, XOR3Inst,
            CastedCDA2->getElementAsConstant(i));
        IRB.Insert(SubInst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteSub(SubInst);
        BinaryOperator *XOR1Inst = BinaryOperator::Create(
            Instruction::Xor, SubInst, CastedCDA->getElementAsConstant(i));
        IRB.Insert(XOR1Inst);
        if (cryptoutils->get_range(100) < StrEncSubXorProbTemp)
          SubstituteImpl::substituteXor(XOR1Inst);
        Result = XOR1Inst;
        break;
      }
      default:
        break;
      }

      IRB.CreateStore(Result, DecryptedGEP);
      realkeyoff++;
    }
  }
  IRB.CreateBr(C);
}

//===----------------------------------------------------------------------===//
// InsertCleanupAtReturns — 改动四c：函数出口清零
//===----------------------------------------------------------------------===//

// 辅助：沿 def-use 链向上追溯，判断 V 是否源自 GV2Info 中的某个 DecryptSpaceGV
// 返回追溯到的 GV 集合
static SmallPtrSet<GlobalVariable *, 4> traceToDecryptGVs(
    Value *V,
    const std::unordered_map<GlobalVariable *, StrEncInfo> &GV2Info) {
  SmallPtrSet<GlobalVariable *, 4> Result;
  SmallVector<Value *, 8> Worklist;
  SmallPtrSet<Value *, 16> Visited;
  Worklist.push_back(V);
  while (!Worklist.empty()) {
    Value *Cur = Worklist.pop_back_val();
    if (!Visited.insert(Cur).second)
      continue;
    // 剥离 bitcast / addrspacecast / GEP 常量表达式
    Cur = Cur->stripPointerCasts();
    if (auto *GV = dyn_cast<GlobalVariable>(Cur)) {
      if (GV2Info.count(GV)) {
        Result.insert(GV);
      } else if (GV->hasInitializer()) {
        Worklist.push_back(GV->getInitializer());
      }
      continue;
    }
    if (auto *GEP = dyn_cast<GetElementPtrInst>(Cur)) {
      Worklist.push_back(GEP->getPointerOperand());
    } else if (auto *BC = dyn_cast<BitCastInst>(Cur)) {
      Worklist.push_back(BC->getOperand(0));
    } else if (auto *PHI = dyn_cast<PHINode>(Cur)) {
      for (Value *Inc : PHI->incoming_values())
        Worklist.push_back(Inc);
    } else if (auto *SI = dyn_cast<SelectInst>(Cur)) {
      Worklist.push_back(SI->getTrueValue());
      Worklist.push_back(SI->getFalseValue());
    } else if (auto *LI = dyn_cast<LoadInst>(Cur)) {
      // load from alloca — 追溯所有 store 到该 alloca 的值
      // load from global — 追溯所有 store 到该全局变量的值 + 初始化器
      Value *Ptr = LI->getPointerOperand()->stripPointerCasts();
      Worklist.push_back(Ptr);
      if (isa<AllocaInst>(Ptr) || isa<GlobalVariable>(Ptr)) {
        for (User *U : Ptr->users()) {
          if (auto *Store = dyn_cast<StoreInst>(U)) {
            if (Store->getPointerOperand()->stripPointerCasts() == Ptr)
              Worklist.push_back(Store->getValueOperand());
          }
        }
        // 全局变量的初始化器也可能指向 DecryptSpaceGV
        if (auto *GVPtr = dyn_cast<GlobalVariable>(Ptr)) {
          if (GVPtr->hasInitializer())
            Worklist.push_back(GVPtr->getInitializer());
        }
      }
    } else if (auto *CE = dyn_cast<ConstantExpr>(Cur)) {
      for (unsigned i = 0; i < CE->getNumOperands(); ++i)
        Worklist.push_back(CE->getOperand(i));
    } else if (auto *CA = dyn_cast<ConstantAggregate>(Cur)) {
      for (unsigned i = 0; i < CA->getNumOperands(); ++i)
        Worklist.push_back(CA->getOperand(i));
    }
  }
  return Result;
}

void EnhancedStringEncryptionPass::InsertCleanupAtReturns(
    Function *Func, GlobalVariable *StatusGV,
    std::unordered_map<GlobalVariable *, StrEncInfo> &GV2Info) {
  // 收集所有 ReturnInst
  SmallVector<ReturnInst *, 4> Returns;
  for (BasicBlock &BB : *Func)
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
      Returns.push_back(RI);

  // 如果函数返回指针类型，收集所有可能被返回的 DecryptSpaceGV
  // 这些 GV 不能在函数返回时清零，否则调用者拿到的指针指向空数据
  SmallPtrSet<GlobalVariable *, 4> ReturnedGVs;
  if (Func->getReturnType()->isPointerTy()) {
    for (ReturnInst *RI : Returns) {
      if (Value *RV = RI->getReturnValue()) {
        auto Traced = traceToDecryptGVs(RV, GV2Info);
        ReturnedGVs.insert(Traced.begin(), Traced.end());
      }
    }
  }

  // 如果所有 DecryptSpaceGV 都可能被返回，则完全跳过 cleanup
  if (ReturnedGVs.size() == GV2Info.size())
    return;

  for (ReturnInst *RI : Returns) {
    BasicBlock *RetBB = RI->getParent();

    // 在 ReturnInst 前拆分
    BasicBlock *TailBB = RetBB->splitBasicBlock(RI, "");
    // RetBB 现在以 br TailBB 结尾，删掉它
    RetBB->getTerminator()->eraseFromParent();

    // 创建清零 BB
    BasicBlock *ZeroBB =
        BasicBlock::Create(Func->getContext(), "", Func, TailBB);

    // 在 RetBB 末尾插入 atomicrmw sub + 条件分支
    IRBuilder<> IRB(RetBB);
    Value *OldCount = IRB.CreateAtomicRMW(
        AtomicRMWInst::Sub, StatusGV,
        ConstantInt::get(Type::getInt32Ty(Func->getContext()), 1),
        Align(4), AtomicOrdering::Release);
    Value *IsLast = IRB.CreateICmpEQ(
        OldCount, ConstantInt::get(Type::getInt32Ty(Func->getContext()), 1));
    IRB.CreateCondBr(IsLast, ZeroBB, TailBB);

    // 在 ZeroBB 中 memset 所有 DecryptSpace（跳过可能被返回的 GV）
    IRBuilder<> ZeroIRB(ZeroBB);
    for (auto &kv : GV2Info) {
      GlobalVariable *DecryptGV = kv.first;
      if (ReturnedGVs.count(DecryptGV))
        continue; // 该 GV 可能被返回，不清零
      uint64_t size = Func->getParent()->getDataLayout().getTypeAllocSize(
          DecryptGV->getValueType());
      ZeroIRB.CreateMemSet(DecryptGV, ZeroIRB.getInt8(0), size, Align(1));
    }
    // 重置 StatusGV 为 0
    StoreInst *ResetSI = ZeroIRB.CreateStore(
        ConstantInt::get(Type::getInt32Ty(Func->getContext()), 0), StatusGV);
    ResetSI->setAlignment(Align(4));
    ResetSI->setAtomic(AtomicOrdering::Release);
    ZeroIRB.CreateBr(TailBB);
  }
}

//===----------------------------------------------------------------------===//
// run — Pass主入口
//===----------------------------------------------------------------------===//

PreservedAnalyses
EnhancedStringEncryptionPass::run(Module &M, ModuleAnalysisManager &MAM) {
  this->appleptrauth = hasApplePtrauth(&M);

#if LLVM_VERSION_MAJOR >= 17
  this->opaquepointers = true;
#elif LLVM_VERSION_MAJOR > 12 && LLVM_VERSION_MAJOR < 17
  this->opaquepointers = !M.getContext().supportsTypedPointers();
#else
  this->opaquepointers = false;
#endif

  bool changed = false;
  for (Function &F : M)
    if (toObfuscate(flag, &F, "enstrenc")) {
      LLVM_DEBUG(dbgs() << "Running EnhancedStringEncryption On " << F.getName() << "\n");
      changed = true;

      if (!toObfuscateUint32Option(&F, "enstrcry_prob",
                                   &ElementEncryptProbTemp))
        ElementEncryptProbTemp = ElementEncryptProb;

      if (!toObfuscateUint32Option(&F, "enstrcry_subxor_prob",
                                   &StrEncSubXorProbTemp))
        StrEncSubXorProbTemp = StrEncSubXorProb;

      StrEncCleanupTemp = StrEncCleanup;
      toObfuscateBoolOption(&F, "enstrcry_cleanup", &StrEncCleanupTemp);

      if (!((ElementEncryptProbTemp > 0) && (ElementEncryptProbTemp <= 100))) {
        errs() << "EnhancedStringEncryption element percentage "
                  "-enstrcry_prob=x must be 0 < x <= 100";
        return PreservedAnalyses::all();
      }

      Constant *S =
          ConstantInt::getNullValue(Type::getInt32Ty(M.getContext()));
      std::string StatusName = createObfuscatedName(M);
      GlobalVariable *GV = new GlobalVariable(
          M, S->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage,
          S, StatusName);
      encstatus[&F] = GV;

      HandleFunction(&F);
    }

  for (GlobalVariable *GV : globalProcessedGVs) {
    GV->removeDeadConstantUsers();
    if (GV->getNumUses() == 0) {
      GV->dropAllReferences();
      GV->eraseFromParent();
    }
  }

  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

std::unique_ptr<EnhancedStringEncryptionPass>
createEnhancedStringEncryptionPass(bool flag) {
  return std::make_unique<EnhancedStringEncryptionPass>(flag);
}

} // namespace ni_pass

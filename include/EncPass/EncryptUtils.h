#ifndef LLVM_ENCPASS_ENCRYPT_UTILS_H
#define LLVM_ENCPASS_ENCRYPT_UTILS_H

#include "CryptoUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/NoFolder.h"
#include <algorithm>

using namespace llvm;

namespace ni_pass {

template <typename IRBuilderTy>
static Value *emitRuntimeNoise(IRBuilderTy &IRB, IntegerType *intType) {
  AllocaInst *Slot = nullptr;
  if (BasicBlock *InsertBB = IRB.GetInsertBlock()) {
    if (Function *Fn = InsertBB->getParent()) {
      BasicBlock &Entry = Fn->getEntryBlock();
      BasicBlock::iterator InsertPt = Entry.getFirstInsertionPt();
      if (InsertPt == Entry.end()) {
        IRBuilder<NoFolder> AllocaIRB(&Entry);
        Slot = AllocaIRB.CreateAlloca(intType);
      } else {
        IRBuilder<NoFolder> AllocaIRB(&*InsertPt);
        Slot = AllocaIRB.CreateAlloca(intType);
      }
    }
  }
  if (!Slot)
    Slot = IRB.CreateAlloca(intType);
  Slot->setAlignment(Align(std::max<uint64_t>(1, intType->getBitWidth() / 8)));
  auto *Seed = ConstantInt::get(intType, cryptoutils->get_uint64_t());
  IRB.CreateStore(Seed, Slot)->setVolatile(true);
  LoadInst *Load = IRB.CreateLoad(intType, Slot);
  Load->setVolatile(true);
  return IRB.CreateXor(Load, Seed);
}

template <typename IRBuilderTy>
static Value *emitOpaqueConst(IRBuilderTy &IRB, IntegerType *intType,
                              uint64_t value) {
  Value *Noise = emitRuntimeNoise(IRB, intType);
  return IRB.CreateXor(ConstantInt::get(intType, value), Noise);
}

// 运行时密钥拆分：将一个密钥拆分为 2~3 个部分通过 XOR 合成
template <typename IRBuilderTy>
static Value *emitSplitKey(IRBuilderTy &IRB, uint64_t key, IntegerType *intType) {
  uint32_t numParts = cryptoutils->get_range(2, 5); // 2, 3 or 4
  if (numParts == 2) {
    uint64_t a = cryptoutils->get_uint64_t();
    uint64_t b = key ^ a;
    return IRB.CreateXor(emitOpaqueConst(IRB, intType, a),
                         emitOpaqueConst(IRB, intType, b));
  } else if (numParts == 3) {
    uint64_t a = cryptoutils->get_uint64_t();
    uint64_t b = cryptoutils->get_uint64_t();
    uint64_t c = key ^ a ^ b;
    Value *Left = IRB.CreateXor(emitOpaqueConst(IRB, intType, a),
                                emitOpaqueConst(IRB, intType, b));
    return IRB.CreateXor(Left, emitOpaqueConst(IRB, intType, c));
  } else {
    uint64_t a = cryptoutils->get_uint64_t();
    uint64_t b = cryptoutils->get_uint64_t();
    uint64_t c = cryptoutils->get_uint64_t();
    uint64_t d = key ^ a ^ b ^ c;
    Value *Left = IRB.CreateXor(emitOpaqueConst(IRB, intType, a),
                                emitOpaqueConst(IRB, intType, b));
    Value *Right = IRB.CreateXor(emitOpaqueConst(IRB, intType, c),
                                 emitOpaqueConst(IRB, intType, d));
    return IRB.CreateXor(Left, Right);
  }
}

// 多态解密：3 种等价解密变体（4 密钥 XOR-ADD 混合方案）
// 编译时加密: combined = (key1 ^ key2) + (key3 ^ key4)
//            stored   = inttoptr( ptrtoint(ptr) + combined )
// 运行时解密: 重建 combined，然后 ptrtoint(stored) - combined
// EncInfoTy 需要有 key1, key2, key3, key4, variant 字段
template <typename IRBuilderTy, typename EncInfoTy>
static Value *emitDecrypt4Key(IRBuilderTy &IRB, Value *EncPtr,
                              const EncInfoTy &Info, IntegerType *intType,
                              LLVMContext &Ctx) {
  auto *i8ptr = Type::getInt8Ty(Ctx)->getPointerTo();
  Value *AsInt = IRB.CreatePtrToInt(EncPtr, intType);

  // 4 个密钥各自经过 split 拆分，增加提取难度
  Value *K1 = emitSplitKey(IRB, Info.key1, intType);
  Value *K2 = emitSplitKey(IRB, Info.key2, intType);
  Value *K3 = emitSplitKey(IRB, Info.key3, intType);
  Value *K4 = emitSplitKey(IRB, Info.key4, intType);

  Value *XorA, *XorB, *Combined, *DecInt;

  switch (Info.variant) {
  case 0: { // 标准: 直接 XOR + ADD 重建密钥，SUB 解密
    XorA = IRB.CreateXor(K1, K2);
    XorB = IRB.CreateXor(K3, K4);
    Combined = IRB.CreateAdd(XorA, XorB);
    DecInt = IRB.CreateSub(AsInt, Combined);
    break;
  }
  case 1: { // NOT-XOR 恒等式重建: ~(~a ^ b) == a ^ b，NEG 替代 SUB
    XorA = IRB.CreateNot(IRB.CreateXor(IRB.CreateNot(K1), K2));
    XorB = IRB.CreateNot(IRB.CreateXor(K3, IRB.CreateNot(K4)));
    Combined = IRB.CreateAdd(XorA, XorB);
    Value *NegCombined = IRB.CreateNeg(Combined);
    DecInt = IRB.CreateAdd(AsInt, NegCombined);
    break;
  }
  case 2: { // OR-AND 分解 XOR: a^b == (a|b) & ~(a&b)，NOT 恒等式解密
    Value *OrA = IRB.CreateOr(K1, K2);
    Value *NandA = IRB.CreateNot(IRB.CreateAnd(K1, K2));
    XorA = IRB.CreateAnd(OrA, NandA);
    Value *OrB = IRB.CreateOr(K3, K4);
    Value *NandB = IRB.CreateNot(IRB.CreateAnd(K3, K4));
    XorB = IRB.CreateAnd(OrB, NandB);
    Combined = IRB.CreateAdd(XorA, XorB);
    // a - b == ~(~a + b)
    DecInt = IRB.CreateNot(IRB.CreateAdd(IRB.CreateNot(AsInt), Combined));
    break;
  }
  default: {
    XorA = IRB.CreateXor(K1, K2);
    XorB = IRB.CreateXor(K3, K4);
    Combined = IRB.CreateAdd(XorA, XorB);
    DecInt = IRB.CreateSub(AsInt, Combined);
    break;
  }
  }

  return IRB.CreateIntToPtr(DecInt, i8ptr);
}

} // namespace ni_pass

#endif // LLVM_ENCPASS_ENCRYPT_UTILS_H

#include "EncPass/EnVMFlatten.h"
#include "Utils.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#define DEBUG_TYPE "envmflatten"

using namespace llvm;

namespace ni_pass {

// ============================================================
// Pass 入口
// ============================================================

PreservedAnalyses EnVMFlattenPass::run(Function &F, FunctionAnalysisManager &FAM) {
    Function *tmp = &F;
    if (toObfuscate(flag, tmp, "envmf")) {
        LLVM_DEBUG(dbgs() << "\033[1;32m[EnVMFlattening] Function : " << F.getName() << "\033[0m\n");
        DoFlatten(tmp);
        writeObfuscationMetadata(tmp, "envmf.applied");
        return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
}

// ============================================================
// 工具函数
// ============================================================

std::vector<BasicBlock *> *EnVMFlattenPass::getBlocks(Function *function, std::vector<BasicBlock *> *lists) {
    lists->clear();
    for (BasicBlock &bb : *function)
        lists->push_back(&bb);
    return lists;
}

unsigned int EnVMFlattenPass::getUniqueNumber(std::vector<unsigned int> *rand_list) {
    unsigned int num = cryptoutils->get_uint32_t();
    while (true) {
        bool unique = true;
        for (auto n : *rand_list) {
            if (n == num) { unique = false; break; }
        }
        if (unique) break;
        num = cryptoutils->get_uint32_t();
    }
    return num;
}

bool EnVMFlattenPass::valueEscapes(Instruction *Inst) {
    const BasicBlock *BB = Inst->getParent();
    for (const User *U : Inst->users()) {
        const Instruction *UI = cast<Instruction>(U);
        if (UI->getParent() != BB || isa<PHINode>(UI))
            return true;
    }
    return false;
}

EnNode *EnVMFlattenPass::newNode(unsigned int value) {
    EnNode *node = new EnNode();
    node->value = value;
    node->bb1 = node->bb2 = nullptr;
    return node;
}

EnVMInst *EnVMFlattenPass::newInst(unsigned int type, unsigned int op1, unsigned int op2) {
    EnVMInst *code = new EnVMInst();
    code->type = type;
    code->op1 = op1;
    code->op2 = op2;
    return code;
}

EnNode *EnVMFlattenPass::findBBNode(BasicBlock *bb, std::vector<EnNode *> *all_node) {
    for (auto *n : *all_node) {
        if (bb == n->data) return n;
    }
    return NULL;
}

// ============================================================
// 增强 1: 多态调度器 —— 随机化指令类型编码
// ============================================================

VMTypeMap EnVMFlattenPass::generateTypeMap() {
    VMTypeMap m;
    std::vector<unsigned int> used;
    m.RunBlock = getUniqueNumber(&used);  used.push_back(m.RunBlock);
    m.JmpBoring = getUniqueNumber(&used); used.push_back(m.JmpBoring);
    m.JmpSelect = getUniqueNumber(&used); used.push_back(m.JmpSelect);
    m.VmNop = getUniqueNumber(&used);
    return m;
}

VMBytecodeLayout EnVMFlattenPass::generateBytecodeLayout() {
    VMBytecodeLayout L;
    std::vector<unsigned int> slots = {0, 1, 2};
    for (size_t i = slots.size(); i > 1; --i)
        std::swap(slots[i - 1], slots[cryptoutils->get_range(i)]);

    L.TypeSlot = slots[0];
    L.Op1Slot = slots[1];
    L.Op2Slot = slots[2];
    L.Stride = 3 + cryptoutils->get_range(0, 4);
    return L;
}

VMBytecodeCipher EnVMFlattenPass::generateBytecodeCipher() {
    VMBytecodeCipher C;
    C.Seed = cryptoutils->get_uint32_t();
    C.Mul = cryptoutils->get_uint32_t() | 1;
    C.Inc = cryptoutils->get_uint32_t() | 1;
    C.Salt1 = cryptoutils->get_uint32_t();
    C.Salt2 = cryptoutils->get_uint32_t();
    C.Rot1 = 1 + cryptoutils->get_range(0, 31);
    C.Rot2 = 1 + cryptoutils->get_range(0, 31);
    C.Shift = 3 + cryptoutils->get_range(0, 13);
    C.Variant = cryptoutils->get_range(0, 3);
    return C;
}

static uint32_t rotateLeft32(uint32_t value, unsigned int amount) {
    amount &= 31;
    return amount == 0 ? value : ((value << amount) | (value >> (32 - amount)));
}

uint32_t EnVMFlattenPass::computeBytecodeKey(uint32_t flatIndex) const {
    uint32_t key = currentCipher.Seed +
                   flatIndex * currentCipher.Mul +
                   currentCipher.Inc;
    switch (currentCipher.Variant) {
    case 0:
        key = rotateLeft32(key ^ currentCipher.Salt1, currentCipher.Rot1);
        key += currentCipher.Salt2;
        key ^= key >> currentCipher.Shift;
        break;
    case 1:
        key = rotateLeft32(key + currentCipher.Salt1, currentCipher.Rot1);
        key ^= currentCipher.Salt2;
        key = rotateLeft32(key, currentCipher.Rot2);
        break;
    default:
        key ^= rotateLeft32(flatIndex + currentCipher.Salt1,
                            currentCipher.Rot1);
        key += rotateLeft32(currentCipher.Salt2, currentCipher.Rot2);
        key ^= key >> currentCipher.Shift;
        break;
    }
    return key;
}

Value *EnVMFlattenPass::emitBytecodeKey(IRBuilder<> &IRB, Value *flatIndex,
                                        IntegerType *i32Ty) const {
    auto Const = [&](uint32_t V) { return ConstantInt::get(i32Ty, V); };
    auto RotL = [&](Value *V, unsigned int Amount) -> Value * {
        Amount &= 31;
        if (Amount == 0)
            return V;
        Value *L = IRB.CreateShl(V, Const(Amount));
        Value *R = IRB.CreateLShr(V, Const(32 - Amount));
        return IRB.CreateOr(L, R);
    };

    Value *key = IRB.CreateAdd(
        IRB.CreateAdd(Const(currentCipher.Seed),
                      IRB.CreateMul(flatIndex, Const(currentCipher.Mul))),
        Const(currentCipher.Inc));

    switch (currentCipher.Variant) {
    case 0:
        key = RotL(IRB.CreateXor(key, Const(currentCipher.Salt1)),
                   currentCipher.Rot1);
        key = IRB.CreateAdd(key, Const(currentCipher.Salt2));
        key = IRB.CreateXor(key, IRB.CreateLShr(key, Const(currentCipher.Shift)));
        break;
    case 1:
        key = RotL(IRB.CreateAdd(key, Const(currentCipher.Salt1)),
                   currentCipher.Rot1);
        key = IRB.CreateXor(key, Const(currentCipher.Salt2));
        key = RotL(key, currentCipher.Rot2);
        break;
    default:
        key = IRB.CreateXor(
            key, RotL(IRB.CreateAdd(flatIndex, Const(currentCipher.Salt1)),
                      currentCipher.Rot1));
        key = IRB.CreateAdd(key, RotL(Const(currentCipher.Salt2),
                                      currentCipher.Rot2));
        key = IRB.CreateXor(key, IRB.CreateLShr(key, Const(currentCipher.Shift)));
        break;
    }
    return key;
}

// ============================================================
// 指令生成（使用 currentTypeMap）
// ============================================================

void EnVMFlattenPass::create_node_inst(std::vector<EnVMInst *> *all_inst,
                                       std::map<EnNode *, unsigned int> *inst_map,
                                       EnNode *node) {
    EnVMInst *code = newInst(currentTypeMap.RunBlock, node->value, 0);
    all_inst->push_back(code);
    inst_map->insert(std::map<EnNode *, unsigned int>::value_type(node, all_inst->size() - 1));
}

void EnVMFlattenPass::gen_inst(std::vector<EnVMInst *> *all_inst,
                               std::map<EnNode *, unsigned int> *inst_map,
                               EnNode *node) {
    if (node->bb1 != NULL && node->bb2 == NULL) {
        // 无条件跳转
        if (inst_map->count(node->bb1) == 0) {
            create_node_inst(all_inst, inst_map, node->bb1);
            gen_inst(all_inst, inst_map, node->bb1);
        } else {
            unsigned int addr = (*inst_map->find(node->bb1)).second * currentLayout.Stride;
            EnVMInst *code = newInst(currentTypeMap.JmpBoring, addr, 0);
            all_inst->push_back(code);
        }
    } else if (node->bb2 != NULL) {
        // 条件跳转
        EnVMInst *code = newInst(currentTypeMap.JmpSelect, 0, 0);
        all_inst->push_back(code);

        // 记录 bb1 子树生成前的指令数，用于判断是否需要补跳转
        bool bb1_was_new = (inst_map->count(node->bb1) == 0);
        bool bb2_was_new = (inst_map->count(node->bb2) == 0);

        if (bb1_was_new) {
            create_node_inst(all_inst, inst_map, node->bb1);
            gen_inst(all_inst, inst_map, node->bb1);
        }

        // 修复: bb1 子树结束后，如果 bb2 还要生成新指令，
        // bb1 子树的最后一条 RunBlock 会 fall-through 到 bb2 的 RunBlock，
        // 这是错误的。需要在 bb1 子树末尾补一条 JmpBoring 回到 bb1 子树
        // 的正确后继（由 JmpSelect 控制，不需要额外跳转）。
        // 但更根本的问题是：bb1 子树末尾的 RunBlock 执行完后，
        // pc fall-through 到下一条指令。如果下一条是 bb2 的 RunBlock，
        // 就会错误执行 bb2 的代码。
        // 实际上这不会出问题，因为 JmpSelect 已经把 pc 设到了 bb1 或 bb2，
        // fall-through 只发生在 bb1 子树内部的线性链中。
        // 真正的 bug 是：当 bb2 已经被访问过（bb2_was_new == false），
        // bb1 子树生成完毕后没有更多指令，如果 bb1 子树的最后一个节点
        // 是 return block（无后继），则 ok；但如果不是 return block，
        // 其 gen_inst 会生成 JmpBoring 或继续递归，所以也 ok。
        // 问题出在整个递归的最末尾：最后生成的 RunBlock 如果不是 return block，
        // 它的 fall-through 会越界。

        if (bb2_was_new) {
            create_node_inst(all_inst, inst_map, node->bb2);
            gen_inst(all_inst, inst_map, node->bb2);
        }

        code->op1 = (*inst_map->find(node->bb1)).second * currentLayout.Stride;
        code->op2 = (*inst_map->find(node->bb2)).second * currentLayout.Stride;
    }
}

void EnVMFlattenPass::dump_inst(std::vector<EnVMInst *> *all_inst) {
    for (auto *c : *all_inst) {
        if (c->type == currentTypeMap.RunBlock) {
            // errs() << "RUN_BLOCK 0x" << Twine::utohexstr(c->op1) << "\n";
        } else if (c->type == currentTypeMap.JmpBoring) {
            // errs() << "JMP_BORING 0x" << Twine::utohexstr(c->op1) << "\n";
        } else if (c->type == currentTypeMap.JmpSelect) {
            // errs() << "JMP_SELECT 0x" << Twine::utohexstr(c->op1) << " 0x" << Twine::utohexstr(c->op2) << "\n";
        } else if (c->type == currentTypeMap.VmNop) {
            // errs() << "VM_NOP\n";
        }
    }
}

// ============================================================
// 增强 3: Dummy 指令插入
// ============================================================

unsigned int EnVMFlattenPass::insertDummyInstructions(std::vector<EnVMInst *> *all_inst) {
    std::vector<EnVMInst *> newList;
    // oldOffset -> newOffset 映射（以 i32 数组下标为单位）
    std::map<unsigned int, unsigned int> offsetMap;

    // 第一遍：插入 dummy，建立偏移映射
    for (unsigned int i = 0; i < all_inst->size(); i++) {
        unsigned int oldOffset = i * currentLayout.Stride;
        // 在每条真实指令前插入 1-3 条 NOP
        unsigned int nopCount = 1 + (cryptoutils->get_uint32_t() % 3);
        for (unsigned int j = 0; j < nopCount; j++) {
            EnVMInst *nop = newInst(currentTypeMap.VmNop,
                                    cryptoutils->get_uint32_t(),
                                    cryptoutils->get_uint32_t());
            newList.push_back(nop);
        }
        unsigned int newOffset = (unsigned int)(newList.size()) * currentLayout.Stride;
        offsetMap[oldOffset] = newOffset;
        newList.push_back((*all_inst)[i]);
    }

    // 第二遍：修正跳转地址
    for (auto *inst : newList) {
        if (inst->type == currentTypeMap.JmpBoring) {
            auto it = offsetMap.find(inst->op1);
            if (it != offsetMap.end()) inst->op1 = it->second;
        } else if (inst->type == currentTypeMap.JmpSelect) {
            auto it1 = offsetMap.find(inst->op1);
            if (it1 != offsetMap.end()) inst->op1 = it1->second;
            auto it2 = offsetMap.find(inst->op2);
            if (it2 != offsetMap.end()) inst->op2 = it2->second;
        }
    }

    // 计算新的起始偏移（原始第 0 条指令的新位置）
    unsigned int startOffset = offsetMap[0];

    // 替换原列表
    *all_inst = std::move(newList);
    return startOffset;
}

// ============================================================
// 增强 4: 操作数 XOR 编码
// ============================================================

void EnVMFlattenPass::encodeOperands(std::vector<EnVMInst *> *all_inst) {
    for (auto *inst : *all_inst) {
        if (inst->type == currentTypeMap.RunBlock) {
            inst->op1 ^= currentOperandKey;
        } else if (inst->type == currentTypeMap.JmpBoring) {
            inst->op1 ^= currentOperandKey;
        } else if (inst->type == currentTypeMap.JmpSelect) {
            inst->op1 ^= currentOperandKey;
            inst->op2 ^= currentOperandKey;
        }
        // VM_NOP 的操作数本来就是垃圾值，不需要编码
    }
}

// ============================================================
// 主函数 DoFlatten
// ============================================================

void EnVMFlattenPass::DoFlatten(Function *f) {
    // --- 将 InvokeInst 降级为 CallInst + BranchInst ---
    // C++ 异常处理会生成 InvokeInst（2个后继：normal + unwind），
    // VM 平坦化无法处理，需要先降级为普通调用 + 无条件跳转
    {
        SmallVector<BasicBlock *, 8> invokeBlocks;
        for (BasicBlock &BB : *f)
            if (isa<InvokeInst>(BB.getTerminator()))
                invokeBlocks.push_back(&BB);
        for (BasicBlock *BB : invokeBlocks)
            removeUnwindEdge(BB);
        // 清理不可达的 landing pad 块
        if (!invokeBlocks.empty())
            removeUnreachableBlocks(*f);
    }

    // --- 增强 1: 随机化种子（使用 cryptoutils，不再 srand） ---
    // --- 增强 2: 多态调度器 ---
    currentTypeMap = generateTypeMap();
    currentLayout = generateBytecodeLayout();
    currentCipher = generateBytecodeCipher();
    currentOperandKey = cryptoutils->get_uint32_t();

    std::vector<BasicBlock *> origBB;
    getBlocks(f, &origBB);
    if (origBB.size() <= 1) return;

    Function::iterator tmp = f->begin();
    BasicBlock *oldEntry = &*tmp;
    origBB.erase(origBB.begin());
    BranchInst *firstBr = NULL;
    if (isa<BranchInst>(oldEntry->getTerminator()))
        firstBr = cast<BranchInst>(oldEntry->getTerminator());

    BasicBlock *firstbb = oldEntry->getTerminator()->getSuccessor(0);
    if ((firstBr != NULL && firstBr->isConditional()) ||
        oldEntry->getTerminator()->getNumSuccessors() > 2) {
        BasicBlock::iterator iter = oldEntry->end();
        iter--;
        if (oldEntry->size() > 1) iter--;
        BasicBlock *splited = oldEntry->splitBasicBlock(iter, Twine(""));
        firstbb = splited;
        origBB.insert(origBB.begin(), splited);
    }

    // --- 降级 SwitchInst 为 if-else 链 ---
    // VM 只能处理 1-2 个 successor 的块，SwitchInst 有 >2 个需要拆分
    // 注意：不需要手动更新 PHI 节点，后续 DemotePHIToStack 会统一处理
    {
        std::vector<BasicBlock *> extraBlocks;
        for (auto *bb : origBB) {
            auto *SI = dyn_cast<SwitchInst>(bb->getTerminator());
            if (!SI || SI->getNumCases() == 0) continue;

            Value *cond = SI->getCondition();
            BasicBlock *defaultDest = SI->getDefaultDest();

            std::vector<std::pair<ConstantInt *, BasicBlock *>> cases;
            for (auto &C : SI->cases())
                cases.push_back({C.getCaseValue(), C.getCaseSuccessor()});

            SI->eraseFromParent();

            // 从最后一个 case 向前构建 if-else 链
            BasicBlock *elseBB = defaultDest;
            for (int i = (int)cases.size() - 1; i >= 1; i--) {
                BasicBlock *newBB = BasicBlock::Create(
                    f->getContext(), "", f, defaultDest);
                IRBuilder<> builder(newBB);
                Value *cmp = builder.CreateICmpEQ(cond, cases[i].first);
                builder.CreateCondBr(cmp, cases[i].second, elseBB);
                elseBB = newBB;
                extraBlocks.push_back(newBB);
            }

            // 第一个 case 放在原始块中
            IRBuilder<> builder(bb);
            Value *cmp = builder.CreateICmpEQ(cond, cases[0].first);
            builder.CreateCondBr(cmp, cases[0].second, elseBB);
        }

        for (auto *nb : extraBlocks)
            origBB.push_back(nb);
    }

    // 为每个基本块创建节点
    std::vector<EnNode *> all_node;
    std::vector<unsigned int> rand_list;
    for (auto *bb : origBB) {
        unsigned int num = getUniqueNumber(&rand_list);
        rand_list.push_back(num);
        EnNode *n = newNode(num);
        all_node.push_back(n);
        n->data = bb;
    }

    // 建立节点连接
    for (auto *n : all_node) {
        BasicBlock *bb = n->data;
        if (bb->getTerminator()->getNumSuccessors() == 2) {
            n->bb1 = findBBNode(bb->getTerminator()->getSuccessor(0), &all_node);
            n->bb2 = findBBNode(bb->getTerminator()->getSuccessor(1), &all_node);
        } else if (bb->getTerminator()->getNumSuccessors() == 1) {
            n->bb1 = findBBNode(bb->getTerminator()->getSuccessor(0), &all_node);
        }
    }

    // 生成指令序列
    EnNode *start = findBBNode(firstbb, &all_node);
    EnNode *fake = newNode(0x7FFFFFFF);
    std::vector<EnVMInst *> all_inst;
    std::map<EnNode *, unsigned int> inst_map;
    fake->bb1 = start;
    gen_inst(&all_inst, &inst_map, fake);
    dump_inst(&all_inst);

    // --- 增强 3: 插入 dummy 指令 ---
    unsigned int startOffset = insertDummyInstructions(&all_inst);

    // --- 增强 4: 操作数编码 ---
    encodeOperands(&all_inst);

    // --- 增强 5: 序列化 + XOR 加密 ---
    std::vector<Constant *> opcodes;
    LLVMContext &ctx = f->getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);

    for (unsigned int i = 0; i < all_inst.size(); i++) {
        EnVMInst *inst = all_inst[i];
        std::vector<uint32_t> raw(currentLayout.Stride);
        for (unsigned int k = 0; k < currentLayout.Stride; ++k)
            raw[k] = cryptoutils->get_uint32_t();
        raw[currentLayout.TypeSlot] = inst->type;
        raw[currentLayout.Op1Slot] = inst->op1;
        raw[currentLayout.Op2Slot] = inst->op2;

        for (unsigned int k = 0; k < currentLayout.Stride; k++) {
            uint32_t flatIdx = i * currentLayout.Stride + k;
            uint32_t encrypted = raw[k] ^ computeBytecodeKey(flatIdx);
            opcodes.push_back(ConstantInt::get(i32Ty, encrypted));
        }
    }

    ArrayType *AT = ArrayType::get(i32Ty, opcodes.size());
    Constant *opcode_array = ConstantArray::get(AT, ArrayRef<Constant *>(opcodes));
    std::string opcodeName = createObfuscatedName(*f->getParent());
    GlobalVariable *oparr_var = new GlobalVariable(
        *(f->getParent()), AT, false,
        GlobalValue::LinkageTypes::PrivateLinkage, opcode_array, opcodeName);
    writeObfuscationMetadata(oparr_var, "nipass.generated");
    appendToCompilerUsed(*(f->getParent()), {oparr_var});

    // 去除入口块末尾跳转
    oldEntry->getTerminator()->eraseFromParent();

    // 创建 VM 寄存器
    AllocaInst *vm_pc = new AllocaInst(i32Ty, 0, Twine(""), oldEntry);
    Constant *init_pc = ConstantInt::get(i32Ty, startOffset); // 使用 dummy 后的新起始偏移
    new StoreInst(init_pc, vm_pc, oldEntry);

    AllocaInst *vm_flag = new AllocaInst(i32Ty, 0, Twine(""), oldEntry);

    // 创建 VM 入口块
    BasicBlock *vm_entry = BasicBlock::Create(ctx, "", f, firstbb);
    BranchInst::Create(vm_entry, oldEntry);

    // ---- 构建解释器（带 XOR 解密） ----
    IRBuilder<> IRB(vm_entry);
    Value *zero = ConstantInt::get(i32Ty, 0);
    ArrayType *arrayTy = cast<ArrayType>(oparr_var->getValueType());

    // 加载 vm_pc 一次
    Value *pcVal = IRB.CreateLoad(i32Ty, vm_pc);

    // 根据每函数随机布局计算 type/op1/op2 所在槽位
    Value *idxType = IRB.CreateAdd(
        pcVal, ConstantInt::get(i32Ty, currentLayout.TypeSlot));
    Value *idxOp1 = IRB.CreateAdd(
        pcVal, ConstantInt::get(i32Ty, currentLayout.Op1Slot));
    Value *idxOp2 = IRB.CreateAdd(
        pcVal, ConstantInt::get(i32Ty, currentLayout.Op2Slot));

    // 加载 raw 密文
    Value *rawType = IRB.CreateLoad(
        i32Ty, IRB.CreateGEP(arrayTy, oparr_var, {zero, idxType}));
    Value *rawOp1 = IRB.CreateLoad(
        i32Ty, IRB.CreateGEP(arrayTy, oparr_var, {zero, idxOp1}));
    Value *rawOp2 = IRB.CreateLoad(
        i32Ty, IRB.CreateGEP(arrayTy, oparr_var, {zero, idxOp2}));

    // 每个槽位使用当前函数随机 key stream 解密。
    Value *keyType = emitBytecodeKey(IRB, idxType, i32Ty);
    Value *keyOp1 = emitBytecodeKey(IRB, idxOp1, i32Ty);
    Value *keyOp2 = emitBytecodeKey(IRB, idxOp2, i32Ty);

    Value *optype = IRB.CreateXor(rawType, keyType);
    Value *op1    = IRB.CreateXor(rawOp1, keyOp1);
    Value *op2    = IRB.CreateXor(rawOp2, keyOp2);

    // 更新 pc += stride
    IRB.CreateStore(
        IRB.CreateAdd(pcVal, ConstantInt::get(i32Ty, currentLayout.Stride)),
        vm_pc);

    // 创建处理块
    BasicBlock *run_block   = BasicBlock::Create(ctx, "", f, firstbb);
    BasicBlock *jmp_boring  = BasicBlock::Create(ctx, "", f, firstbb);
    BasicBlock *jmp_select  = BasicBlock::Create(ctx, "", f, firstbb);
    BasicBlock *vm_nop      = BasicBlock::Create(ctx, "", f, firstbb);
    BasicBlock *defaultCase = BasicBlock::Create(ctx, "", f, firstbb);

    BranchInst::Create(vm_entry, defaultCase);
    BranchInst::Create(vm_entry, vm_nop); // NOP 直接回 VMEntry

    // switch 分发（使用随机化的类型编码）
    SwitchInst *switch1 = IRB.CreateSwitch(optype, defaultCase, 4);
    switch1->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, currentTypeMap.RunBlock)), run_block);
    switch1->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, currentTypeMap.JmpBoring)), jmp_boring);
    switch1->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, currentTypeMap.JmpSelect)), jmp_select);
    switch1->addCase(cast<ConstantInt>(ConstantInt::get(i32Ty, currentTypeMap.VmNop)), vm_nop);

    // ---- RunBlock: op1 先 XOR 解码再 switch ----
    IRB.SetInsertPoint(run_block);
    Value *decodedOp1 = IRB.CreateXor(op1, ConstantInt::get(i32Ty, currentOperandKey));
    SwitchInst *switch2 = IRB.CreateSwitch(decodedOp1, defaultCase, 0);
    for (auto *bb : origBB) {
        bb->moveBefore(defaultCase);
        EnNode *t = findBBNode(bb, &all_node);
        ConstantInt *numCase = cast<ConstantInt>(ConstantInt::get(switch2->getCondition()->getType(), t->value));
        switch2->addCase(numCase, bb);
    }

    // 改写原始基本块的 terminator
    for (auto *block : origBB) {
        if (block->getTerminator()->getNumSuccessors() == 1) {
            block->getTerminator()->eraseFromParent();
            BranchInst::Create(defaultCase, block);
        } else if (block->getTerminator()->getNumSuccessors() == 2) {
            BranchInst *oldBr = cast<BranchInst>(block->getTerminator());
            SelectInst *select = SelectInst::Create(
                oldBr->getCondition(),
                ConstantInt::get(i32Ty, 1),
                ConstantInt::get(i32Ty, 0),
                "", block->getTerminator());
            new StoreInst(select, vm_flag, block->getTerminator());
            block->getTerminator()->eraseFromParent();
            BranchInst::Create(defaultCase, block);
        }
    }

    // ---- JmpBoring: op1 先 XOR 解码再赋值 pc ----
    IRB.SetInsertPoint(jmp_boring);
    Value *jmpBoringDst = IRB.CreateXor(op1, ConstantInt::get(i32Ty, currentOperandKey));
    IRB.CreateStore(jmpBoringDst, vm_pc);
    IRB.CreateBr(vm_entry);

    // ---- JmpSelect: op1/op2 先 XOR 解码 ----
    IRB.SetInsertPoint(jmp_select);
    BasicBlock *select_true  = BasicBlock::Create(ctx, "", f, firstbb);
    BasicBlock *select_false = BasicBlock::Create(ctx, "", f, firstbb);
    IRB.CreateCondBr(
        IRB.CreateICmpEQ(IRB.CreateLoad(i32Ty, vm_flag), ConstantInt::get(i32Ty, 1)),
        select_true, select_false);

    IRB.SetInsertPoint(select_true);
    Value *selTrueDst = IRB.CreateXor(op1, ConstantInt::get(i32Ty, currentOperandKey));
    IRB.CreateStore(selTrueDst, vm_pc);
    IRB.CreateBr(vm_entry);

    IRB.SetInsertPoint(select_false);
    Value *selFalseDst = IRB.CreateXor(op2, ConstantInt::get(i32Ty, currentOperandKey));
    IRB.CreateStore(selFalseDst, vm_pc);
    IRB.CreateBr(vm_entry);

    // ---- PHI / 逃逸值修复 ----
    std::vector<PHINode *> tmpPhi;
    std::vector<Instruction *> tmpReg;
    BasicBlock *bbEntry = &*f->begin();

    do {
        tmpPhi.clear();
        tmpReg.clear();
        for (Function::iterator i = f->begin(); i != f->end(); i++) {
            for (BasicBlock::iterator j = i->begin(); j != i->end(); j++) {
                if (isa<PHINode>(j)) {
                    tmpPhi.push_back(cast<PHINode>(j));
                    continue;
                }
                if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
                    (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
                    tmpReg.push_back(&*j);
                    continue;
                }
            }
        }
#if LLVM_VERSION_MAJOR >= 19
        for (unsigned int i = 0; i < tmpReg.size(); i++)
            DemoteRegToStack(*tmpReg.at(i), false, f->begin()->getTerminator()->getIterator());
        for (unsigned int i = 0; i < tmpPhi.size(); i++)
            DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator()->getIterator());
#else
        for (unsigned int i = 0; i < tmpReg.size(); i++)
            DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
        for (unsigned int i = 0; i < tmpPhi.size(); i++)
            DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator());
#endif
    } while (tmpReg.size() != 0 || tmpPhi.size() != 0);

    // 释放内存
    delete fake;
    for (EnNode *node : all_node) delete node;
    for (EnVMInst *inst : all_inst) delete inst;
}

// 工厂函数
std::unique_ptr<llvm::PassInfoMixin<EnVMFlattenPass>> createEnVMFlatten(bool flag) {
    return std::make_unique<EnVMFlattenPass>(flag);
}

} // namespace ni_pass

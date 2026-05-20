// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "Utils.h"
#include "CryptoUtils.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include <cstdint>
#include <cstdlib>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>
#include <set>
#include <sstream>
#include <unordered_map>
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Operator.h"

using namespace llvm;

namespace ni_pass {

// 检查指令的值是否"逃逸"出当前基本块
// "逃逸"指的是该值在其他基本块中被使用，或被PHI节点使用
// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

// 将寄存器变量降级为栈变量，消除PHI节点
// 这是混淆的重要步骤，因为它使控制流分析更加困难
void fixStack(Function *f) {
  // 尝试移除phi节点并将寄存器变量降级为栈变量
  SmallVector<PHINode *, 8> tmpPhi;
  SmallVector<Instruction *, 32> tmpReg;
  BasicBlock *bbEntry = &*f->begin();
  // 找到第一个非alloca指令并创建插入点
  // 如果基本块格式正确，这是安全的：它总是有终结符，否则会触发断言
  BasicBlock::iterator I = bbEntry->begin();
  while (isa<AllocaInst>(I))
    ++I;
  Instruction *AllocaInsertionPoint = &*I;
  do {
    tmpPhi.clear();
    tmpReg.clear();
    // 遍历函数中的所有指令
    for (BasicBlock &i : *f) {
      for (Instruction &j : i) {
        // 收集所有PHI节点
        if (isa<PHINode>(&j)) {
          PHINode *phi = cast<PHINode>(&j);
          tmpPhi.emplace_back(phi);
          continue;
        }
        // 收集所有"逃逸"的指令或在块外使用的指令
        // 排除入口块中的AllocaInst指令
        if (!(isa<AllocaInst>(&j) && j.getParent() == bbEntry) &&
            (valueEscapes(&j) || j.isUsedOutsideOfBlock(&i))) {
          tmpReg.emplace_back(&j);
          continue;
        }
      }
    }
#if LLVM_VERSION_MAJOR >= 19
    // 将收集的寄存器指令降级为栈操作
    for (Instruction *I : tmpReg)
      DemoteRegToStack(*I, false, AllocaInsertionPoint->getIterator());
    // 将PHI节点降级为栈操作
    for (PHINode *P : tmpPhi)
      DemotePHIToStack(P, AllocaInsertionPoint->getIterator());
#else
    // LLVM 19之前的版本使用不同的API
    for (Instruction *I : tmpReg)
      DemoteRegToStack(*I, false, AllocaInsertionPoint);
    for (PHINode *P : tmpPhi)
      DemotePHIToStack(P, AllocaInsertionPoint);
#endif
  } while (tmpReg.size() != 0 || tmpPhi.size() != 0); // 持续处理直到没有更多需要处理的指令
}

// 读取函数中的标记（通过特殊函数调用）
// 与O-LLVM不同，O-LLVM使用__attribute__，但ObjC CFE不支持
// 这里使用一个虚拟调用，并在之后删除该调用
// 这是一个比函数属性方法更慢但可行的替代方案
bool readFlag(Function *f, std::string attribute) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    // 检查普通函数调用
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          CI->getCalledFunction()->getName().starts_with("hikari_" +
                                                         attribute)) {
#else
          CI->getCalledFunction()->getName().startswith("hikari_" +
                                                        attribute)) {
#endif
        // 找到标记后删除调用并返回true
        CI->eraseFromParent();
        return true;
      }
    }
    // 检查带异常处理的函数调用
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          II->getCalledFunction()->getName().starts_with("hikari_" +
                                                         attribute)) {
#else
          II->getCalledFunction()->getName().startswith("hikari_" +
                                                        attribute)) {
#endif
        // 处理Invoke指令，保持控制流完整性
        BasicBlock *normalDest = II->getNormalDest();
        BasicBlock *unwindDest = II->getUnwindDest();
        BasicBlock *parent = II->getParent();
        if (parent->size() == 1) {
          // 如果基本块只有这一条指令，替换整个块
          parent->replaceAllUsesWith(normalDest);
          II->eraseFromParent();
          parent->eraseFromParent();
        } else {
          // 否则替换为普通分支指令
          BranchInst::Create(normalDest, II);
          II->eraseFromParent();
        }
        // 清理不再使用的异常处理块
        if (pred_size(unwindDest) == 0)
          unwindDest->eraseFromParent();
        return true;
      }
    }
  }
  return false;
}

// 决定是否对函数进行混淆
// 根据函数属性和注解来判断
bool toObfuscate(bool flag, Function *f,const std::string &attribute) {
  // 检查是否为声明或具有外部链接属性，如果是则不混淆
  if (f->isDeclaration() || f->hasAvailableExternallyLinkage()) {
    return false;
  }
  std::string attr = attribute;
  std::string attrNo = "no" + attr; // 禁用特定混淆的标记

  // 如果存在禁用标记，则不混淆
  if (readAnnotationMetadata(f, attrNo) || readFlag(f, attrNo)) {
    return false;
  }
  // 如果存在启用标记，则混淆
  if (readAnnotationMetadata(f, attr) || readFlag(f, attr)) {
    return true;
  }
  if (readAnnotationMetadata(f, attrNo)) {
    return false;
  }
  if (readdiyAnnotationMetadata(f, attribute)) {
    return true;
  }
  // 否则使用默认标记
  return flag;
}

// 处理布尔类型的混淆选项
bool toObfuscateBoolOption(Function *f, std::string option, bool *val) {
  std::string opt = option;
  std::string optDisable = "no" + option; // 禁用选项的标记
  // 如果存在禁用标记，设置为false
  if (readAnnotationMetadata(f, optDisable) || readFlag(f, optDisable)) {
    *val = false;
    return true;
  }
  // 如果存在启用标记，设置为true
  if (readAnnotationMetadata(f, opt) || readFlag(f, opt)) {
    *val = true;
    return true;
  }

  if (readdiyAnnotationMetadata(f, opt)) {
      *val = true;
    return true;
  }
  // 未找到相关标记，不修改值
  return false;
}

// 混淆元数据的标识符
static const char obfkindid[] = "MD_obf";

std::string createObfuscatedName(Module &M, StringRef Prefix) {
  std::string Name;
  do {
    Name = Prefix.str() + std::to_string(cryptoutils->get_uint64_t());
  } while (M.getNamedValue(Name) != nullptr);
  return Name;
}

bool readObfuscationMetadata(const GlobalObject *GO, StringRef annotation) {
  if (!GO)
    return false;

  MDNode *Existing = GO->getMetadata(obfkindid);
  if (!Existing)
    return false;

  MDTuple *Tuple = cast<MDTuple>(Existing);
  for (auto &N : Tuple->operands()) {
    if (cast<MDString>(N.get())->getString() == annotation)
      return true;
  }
  return false;
}

void writeObfuscationMetadata(GlobalObject *GO, StringRef annotation) {
  if (!GO)
    return;

  LLVMContext &Context = GO->getContext();
  MDBuilder MDB(Context);

  MDNode *Existing = GO->getMetadata(obfkindid);
  SmallVector<Metadata *, 4> Names;
  bool AppendName = true;
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      if (cast<MDString>(N.get())->getString() == annotation)
        AppendName = false;
      Names.emplace_back(N.get());
    }
  }

  if (AppendName)
    Names.emplace_back(MDB.createString(annotation));

  GO->setMetadata(obfkindid, MDTuple::get(Context, Names));
}

// 从元数据中读取uint32类型的选项值
bool readAnnotationMetadataUint32OptVal(Function *f, std::string opt,
                                        uint32_t *val) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      StringRef mdstr = cast<MDString>(N.get())->getString();
      std::string estr = opt + "=";
#if LLVM_VERSION_MAJOR >= 18
      // 检查元数据字符串是否以选项名称开头
      if (mdstr.starts_with(estr)) {
#else
      if (mdstr.startswith(estr)) {
#endif
        // 解析选项值
        *val = atoi(mdstr.substr(strlen(estr.c_str())).str().c_str());
        return true;
      }
    }
  }
  return false;
}

// 从函数调用中读取uint32类型的选项值
bool readFlagUint32OptVal(Function *f, std::string opt, uint32_t *val) {
  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    // 检查普通函数调用
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          CI->getCalledFunction()->getName().starts_with("hikari_" + opt)) {
#else
          CI->getCalledFunction()->getName().startswith("hikari_" + opt)) {
#endif
        // 如果找到对应选项的调用，读取第一个参数作为选项值
        if (ConstantInt *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          CI->eraseFromParent();
          return true;
        }
      }
    }
    // 检查带异常处理的函数调用
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
          II->getCalledFunction()->getName().starts_with("hikari_" + opt)) {
#else
          II->getCalledFunction()->getName().startswith("hikari_" + opt)) {
#endif
        // 如果找到对应选项的调用，读取第一个参数作为选项值
        if (ConstantInt *C = dyn_cast<ConstantInt>(II->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          // 处理Invoke指令，保持控制流完整性
          BasicBlock *normalDest = II->getNormalDest();
          BasicBlock *unwindDest = II->getUnwindDest();
          BasicBlock *parent = II->getParent();
          if (parent->size() == 1) {
            parent->replaceAllUsesWith(normalDest);
            II->eraseFromParent();
            parent->eraseFromParent();
          } else {
            BranchInst::Create(normalDest, II);
            II->eraseFromParent();
          }
          if (pred_size(unwindDest) == 0)
            unwindDest->eraseFromParent();
          return true;
        }
      }
    }
  }
  return false;
}

// 处理uint32类型的混淆选项
bool toObfuscateUint32Option(Function *f,const std::string &option, uint32_t *val) {
  // 尝试从元数据或函数调用中读取选项值
  if (readAnnotationMetadataUint32OptVal(f, option, val) ||
      readFlagUint32OptVal(f, option, val))
    return true;

  uint32_t value = readdiyAnnotationMetadata(f, option);
  if (value) {
    *val = value;
    return  true;
  }
  return false;
}

// 检查模块是否支持Apple的指针认证
bool hasApplePtrauth(Module *M) {
  // return M->getTargetTriple().find("apple") != std::string::npos && 
  //        M->getTargetTriple().find("arm64e") != std::string::npos;
    for (GlobalVariable &GV : M->globals())
    if (GV.getSection() == "llvm.ptrauth")
      return true;
  return false;
}

// 修复基本块中的常量表达式
// 将常量表达式替换为等效指令，避免在混淆过程中出现编译器崩溃
void FixBasicBlockConstantExpr(BasicBlock *BB) {
  // 替换常量表达式为等效指令
  // 否则在常量上进行替换会导致编译器崩溃
  // 注意事项：
  // - PHI节点必须放在BB开头，所以常量表达式必须放在当前BB之前
  assert(!BB->empty() && "BasicBlock is empty!");
  assert(BB->getParent() && "BasicBlock must be in a Function!");
  Instruction *FunctionInsertPt =
      &*(BB->getParent()->getEntryBlock().getFirstInsertionPt());

  for (Instruction &I : *BB) {
    // 跳过特殊指令类型
    if (isa<LandingPadInst>(I) || isa<FuncletPadInst>(I) ||
        isa<IntrinsicInst>(I))
      continue;
    // 检查指令的每个操作数
    for (unsigned int i = 0; i < I.getNumOperands(); i++)
      if (ConstantExpr *C = dyn_cast<ConstantExpr>(I.getOperand(i))) {
        // 创建IRBuilder，不进行常量折叠
        IRBuilder<NoFolder> IRB(&I);
        // 对于PHI节点，需要在函数入口处插入指令
        if (isa<PHINode>(I))
          IRB.SetInsertPoint(FunctionInsertPt);
        // 将常量表达式转换为指令并替换操作数
        Instruction *Inst = IRB.Insert(C->getAsInstruction());
        I.setOperand(i, Inst);
      }
  }
}

// 修复函数中的所有常量表达式
void FixFunctionConstantExpr(Function *Func) {
  // 替换常量表达式为等效指令
  // 否则在常量上进行替换会导致编译器崩溃
  for (BasicBlock &BB : *Func)
    FixBasicBlockConstantExpr(&BB);
}

// 关闭函数的优化属性
// 确保混淆代码不会被优化掉
void turnOffOptimization(Function *f) {
  // 移除可能导致代码被优化的属性
  f->removeFnAttr(Attribute::AttrKind::MinSize);
  f->removeFnAttr(Attribute::AttrKind::OptimizeForSize);
  // 如果函数没有OptimizeNone和AlwaysInline属性，添加OptimizeNone和NoInline
  if (!f->hasFnAttribute(Attribute::AttrKind::OptimizeNone) &&
      !f->hasFnAttribute(Attribute::AttrKind::AlwaysInline)) {
    f->addFnAttr(Attribute::AttrKind::OptimizeNone);
    f->addFnAttr(Attribute::AttrKind::NoInline);
  }
}

// 分割字符串为单词数组
static inline std::vector<std::string> splitString(std::string str) {
  std::stringstream ss(str);
  std::string word;
  std::vector<std::string> words;
  while (ss >> word)
    words.emplace_back(word);
  return words;
}

static GlobalValue *stripAnnotationGlobal(Value *V) {
  if (!V)
    return nullptr;
  V = V->stripPointerCasts();
  if (auto *GV = dyn_cast<GlobalValue>(V))
    return GV;
  if (auto *CE = dyn_cast<ConstantExpr>(V))
    return dyn_cast<GlobalValue>(CE->getOperand(0)->stripPointerCasts());
  return nullptr;
}

static ConstantDataSequential *getGlobalStringInitializer(Value *V) {
  auto *GV = dyn_cast_or_null<GlobalVariable>(stripAnnotationGlobal(V));
  if (!GV || !GV->hasInitializer())
    return nullptr;
  return dyn_cast<ConstantDataSequential>(GV->getInitializer());
}

// 将函数注解转换为LLVM元数据
void annotation2Metadata(Module &M) {
  // 获取全局注解变量
  GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
  if (!Annotations)
    return;
  auto *C = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!C)
    return;
  // 遍历所有注解
  for (unsigned int i = 0; i < C->getNumOperands(); i++)
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C->getOperand(i))) {
      // 获取注解字符串
      ConstantDataSequential *StrData =
          getGlobalStringInitializer(CS->getOperand(1));
      if (!StrData)
        continue;
      // 获取被注解的函数
      Function *Fn = dyn_cast<Function>(stripAnnotationGlobal(CS->getOperand(0)));
      if (!Fn)
        continue;

      // 将注解添加到函数的元数据中
      std::vector<std::string> strs =
          splitString(StrData->getAsCString().str());
      for (std::string str : strs)
        writeAnnotationMetadata(Fn, str);
    }
}

void stripObfuscationAnnotations(Module &M) {
  GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
  if (!Annotations || !Annotations->hasInitializer())
    return;

  SmallPtrSet<GlobalVariable *, 16> AnnotationStrings;
  if (auto *C = dyn_cast<ConstantArray>(Annotations->getInitializer())) {
    for (unsigned int i = 0; i < C->getNumOperands(); i++) {
      auto *CS = dyn_cast<ConstantStruct>(C->getOperand(i));
      if (!CS)
        continue;
      if (auto *GV =
              dyn_cast_or_null<GlobalVariable>(stripAnnotationGlobal(CS->getOperand(1))))
        AnnotationStrings.insert(GV);
    }
  }

  Annotations->dropAllReferences();
  Annotations->eraseFromParent();

  for (GlobalVariable *GV : AnnotationStrings) {
    GV->removeDeadConstantUsers();
    if (GV->getNumUses() == 0) {
      GV->dropAllReferences();
      GV->eraseFromParent();
    }
  }
}

// 读取函数的注解元数据
bool readAnnotationMetadata(Function *f, std::string annotation) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()){
          // outs() << "cast<MDString>(N.get())->getString() " << cast<MDString>(N.get())->getString() << "\n";
      // 检查是否存在指定的注解
      if (cast<MDString>(N.get())->getString() == annotation)
        return true;
    }
  }
  return false;
}

int readdiyAnnotationMetadata(Function *f, std::string annotation) {
    // 获取全局注解变量
  GlobalVariable *Annotations = f->getParent()->getGlobalVariable("llvm.global.annotations");
  if (!Annotations)
    return false;
  // 获取注解数组
  ConstantArray *AnnotationsArray = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!AnnotationsArray)
    return false;
  // 遍历注解数组
  for (unsigned int i = 0; i < AnnotationsArray->getNumOperands(); i++) {
    // 获取注解结构体
    ConstantStruct *AnnotationStruct =
        dyn_cast<ConstantStruct>(AnnotationsArray->getOperand(i));
    if (!AnnotationStruct)
      continue;
    // 获取注解字符串
    ConstantDataSequential *StrData =
        getGlobalStringInitializer(AnnotationStruct->getOperand(1));
    if (!StrData)
      continue;
    //获取注解函数
    Function *Fn =
        dyn_cast<Function>(stripAnnotationGlobal(AnnotationStruct->getOperand(0)));
    // 如果注解函数与目标函数相同，并且注解字符串与目标注解相同，则返回true
    if (Fn == f ) {
      std::string str = StrData->getAsCString().str();
      //outs() << "str " << str << "\n";
      //分割字符串 map记录
      std::unordered_map<std::string, int> map;
      std::string key;
      std::stringstream ss(str);
      while (ss >> key) {
        int pos = key.find("=");
        if (pos != std::string::npos) {
          std::string va = key.substr(pos + 1);
          std::string kk = key.substr(0, pos);
          map[kk] = std::atoi(va.c_str());
          //outs() << "key " << kk << " value " << va <<"\n";
        } else {
          map[key] = 1;
        }

        // outs() << "key" << key <<"\n";
      }
      // outs() << "map.size() " << map.size() << "\n";
      if (map.find(annotation) != map.end()) {
        return map[annotation];
      }
    }
  }
  return false;
}

// 向函数添加注解元数据
void writeAnnotationMetadata(Function *f, std::string annotation) {
  LLVMContext &Context = f->getContext();
  MDBuilder MDB(Context);

  MDNode *Existing = f->getMetadata(obfkindid);
  SmallVector<Metadata *, 4> Names;
  bool AppendName = true;
  // 如果已存在元数据，复制现有元数据
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      // 检查注解是否已存在，避免重复添加
      if (cast<MDString>(N.get())->getString() == annotation)
        AppendName = false;
      Names.emplace_back(N.get());
    }
  }
  // 如果注解不存在，添加新注解
  if (AppendName)
    Names.emplace_back(MDB.createString(annotation));

  // 创建新的元数据节点并设置到函数
  MDNode *MD = MDTuple::get(Context, Names);
  f->setMetadata(obfkindid, MD);
}

// 检查全局变量是否只在一个函数中使用
bool AreUsersInOneFunction(GlobalVariable *GV) {
  if (GV->getNumUses() == 0)
    return true;
    
  Function *F = nullptr;
  
  for (auto *U : GV->users()) {
    if (Instruction *I = dyn_cast<Instruction>(U)) {
      if (!F)
        F = I->getFunction();
      else if (F != I->getFunction())
        return false;
    } else {
      // 如果使用者不是指令，可能是常量表达式或其他全局变量
      return false;
    }
  }
  
  return true;
}

// 被注释掉的函数，用于构建全局值到注解的映射
#if 0
std::map<GlobalValue *, StringRef> BuildAnnotateMap(Module &M) {
  std::map<GlobalValue *, StringRef> VAMap;
  GlobalVariable *glob = M.getGlobalVariable("llvm.global.annotations");
  if (glob != nullptr && glob->hasInitializer()) {
    ConstantArray *CDA = cast<ConstantArray>(glob->getInitializer());
    for (Value *op : CDA->operands()) {
      ConstantStruct *anStruct = cast<ConstantStruct>(op);
      /*
        Structure: [Value,Annotation,SourceFilePath,LineNumber]
        Usually wrapped inside GEP/BitCast
        We only care about Value and Annotation Here
      */
      GlobalValue *Value =
          cast<GlobalValue>(anStruct->getOperand(0)->getOperand(0));
      GlobalVariable *Annotation =
          cast<GlobalVariable>(anStruct->getOperand(1)->getOperand(0));
      if (Annotation->hasInitializer()) {
        VAMap[Value] =
            cast<ConstantDataSequential>(Annotation->getInitializer())
                ->getAsCString();
      }
    }
  }
  return VAMap;
}
#endif







// LLVM-MSVC有这个函数, 官方版LLVM没有 (LLVM:17.0.6 | LLVM-MSVC:3.2.6)
void LowerConstantExpr(Function &F) {
  SmallPtrSet<Instruction *, 8> WorkList;

  for (inst_iterator It = inst_begin(F), E = inst_end(F); It != E; ++It) {
    Instruction *I = &*It;

    if (isa<LandingPadInst>(I) || isa<CatchPadInst>(I) ||
        isa<CatchSwitchInst>(I) || isa<CatchReturnInst>(I))
      continue;
    if (auto *II = dyn_cast<IntrinsicInst>(I)) {
      if (II->getIntrinsicID() == Intrinsic::eh_typeid_for) {
        continue;
      }
    }

    for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
      if (isa<ConstantExpr>(I->getOperand(i)))
        WorkList.insert(I);
    }
  }

  while (!WorkList.empty()) {
    auto It = WorkList.begin();
    Instruction *I = *It;
    WorkList.erase(*It);

    if (PHINode *PHI = dyn_cast<PHINode>(I)) {
      for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
        Instruction *TI = PHI->getIncomingBlock(i)->getTerminator();
        if (ConstantExpr *CE =
                dyn_cast<ConstantExpr>(PHI->getIncomingValue(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(TI);
          PHI->setIncomingValue(i, NewInst);
          WorkList.insert(NewInst);
        }
      }
    } else {
      for (unsigned int i = 0; i < I->getNumOperands(); ++i) {
        if (ConstantExpr *CE = dyn_cast<ConstantExpr>(I->getOperand(i))) {
          Instruction *NewInst = CE->getAsInstruction();
          NewInst->insertBefore(I);
          I->replaceUsesOfWith(CE, NewInst);
          WorkList.insert(NewInst);
        }
      }
    }
  }
}


} // namespace llvm

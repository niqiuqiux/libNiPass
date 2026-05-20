#ifndef _ENHANCED_STRING_ENCRYPTION_H_
#define _ENHANCED_STRING_ENCRYPTION_H_

#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include <unordered_map>
#include <unordered_set>

using namespace llvm;

namespace ni_pass {

// 多层异构加密模式
enum class StrEncPattern : uint8_t {
  XOR_ONLY = 0,    // enc = val ^ K1
  XOR_SUB = 1,     // enc = (val ^ K1) - K2
  XOR_ADD = 2,     // enc = (val ^ K1) + K2
  XOR_ADD_XOR = 3, // enc = ((val ^ K1) + K2) ^ K3
  COUNT = 4
};

// 每个字符串的加密信息
struct StrEncInfo {
  Constant *KeyConst = nullptr;          // 主 XOR 密钥数组
  GlobalVariable *EncryptedGV = nullptr; // 密文 GV
  Constant *Key2Const = nullptr;         // 第二密钥数组（SUB/ADD 用）
  Constant *Key3Const = nullptr;         // 第三密钥数组（XOR_ADD_XOR 用）
  StrEncPattern Pattern = StrEncPattern::XOR_ONLY;
  bool RollingKey = false;
  uint64_t RollingSeed = 0;
  uint64_t RollingMul = 0;
  uint64_t RollingInc = 0;
};

/**
 * @brief 增强型字符串加密Pass
 *
 * 相比原始 StringEncryption 的改进：
 * 1. GV/BB/指令名随机化，消除特征匹配
 * 2. XOR 密钥混淆（SubstituteImpl 集成）
 * 3. 多层异构加密（XOR/SUB/ADD 组合）
 * 4. DecryptSpace 生命周期管理（函数返回时清零）
 * 5. 每个函数独立副本，取消跨函数共享
 */
class EnhancedStringEncryptionPass
    : public PassInfoMixin<EnhancedStringEncryptionPass> {
public:
  bool flag;
  bool appleptrauth;
  bool opaquepointers;

  // 每个函数对应的解密状态全局变量（引用计数）
  std::unordered_map<Function *, GlobalVariable *> encstatus;

  // 解密空间对应的密钥和加密后的全局变量（仅用于跨函数 unhandleablegvs 查找）
  std::unordered_map<GlobalVariable *, std::pair<Constant *, GlobalVariable *>>
      mgv2keys;
  std::unordered_map<GlobalVariable *, StrEncInfo> mgv2info;

  // 每个常量中未加密的元素索引
  std::unordered_map<Constant *, SmallVector<unsigned int, 16>>
      unencryptedindex;

  // 所有生成的新全局变量
  SmallVector<GlobalVariable *, 32> genedgv;

  // 已处理过的全局变量（用于模块结束时清理）
  std::unordered_set<GlobalVariable *> globalProcessedGVs;

  EnhancedStringEncryptionPass()
      : flag(true), appleptrauth(false), opaquepointers(false) {}
  EnhancedStringEncryptionPass(bool flag)
      : flag(flag), appleptrauth(false), opaquepointers(false) {}

  bool handleableGV(GlobalVariable *GV);

  void processConstantAggregate(
      GlobalVariable *strGV, ConstantAggregate *CA,
      std::unordered_set<GlobalVariable *> *rawStrings,
      SmallVector<GlobalVariable *, 32> *unhandleablegvs,
      SmallVector<GlobalVariable *, 32> *Globals,
      std::unordered_set<User *> *Users, bool *breakFor);

  void HandleUser(User *U, SmallVector<GlobalVariable *, 32> &Globals,
                  std::unordered_set<User *> &Users,
                  std::unordered_set<User *> &VisitedUsers);

  void HandleFunction(Function *Func);

  GlobalVariable *ObjectiveCString(GlobalVariable *GV, std::string name,
                                   GlobalVariable *newString,
                                   ConstantStruct *CS);

  // 改动三：按 StrEncInfo 生成多层解密逻辑
  void HandleDecryptionBlock(
      BasicBlock *B, BasicBlock *C,
      std::unordered_map<GlobalVariable *, StrEncInfo> &GV2Info);

  // 改动四：在每个 ReturnInst 前插入清零逻辑
  void InsertCleanupAtReturns(
      Function *Func, GlobalVariable *StatusGV,
      std::unordered_map<GlobalVariable *, StrEncInfo> &GV2Info);

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

  static StringRef name() { return "EnhancedStringEncryption"; }
};

std::unique_ptr<EnhancedStringEncryptionPass>
createEnhancedStringEncryptionPass(bool flag = true);

} // namespace ni_pass

#endif // _ENHANCED_STRING_ENCRYPTION_H_

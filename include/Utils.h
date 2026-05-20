#ifndef _UTILS_H_
#define _UTILS_H_

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/GlobalObject.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include <string>

using namespace llvm;

namespace ni_pass {

void fixStack(Function *f);
bool toObfuscate(bool flag, Function *f, const std::string &feature);
bool toObfuscateBoolOption(Function *f, std::string option, bool *val);
bool toObfuscateUint32Option(Function *f, const std::string &option, uint32_t *value);
bool hasApplePtrauth(Module *M);
void FixFunctionConstantExpr(Function *F);
void turnOffOptimization(Function *f);
void annotation2Metadata(Module &M);
void stripObfuscationAnnotations(Module &M);
std::string createObfuscatedName(Module &M, StringRef Prefix = ".x");
bool readObfuscationMetadata(const GlobalObject *GO, StringRef annotation);
void writeObfuscationMetadata(GlobalObject *GO, StringRef annotation);
bool readAnnotationMetadata(Function *f, std::string annotation);
int readdiyAnnotationMetadata(Function *f, std::string annotation);
void writeAnnotationMetadata(Function *f, std::string annotation);
bool AreUsersInOneFunction(GlobalVariable *GV);
#if 0
std::map<GlobalValue*, StringRef> BuildAnnotateMap(Module& M);
#endif

    // LLVM-MSVC有这个函数, 官方版LLVM没有 (LLVM:17.0.6 | LLVM-MSVC:3.2.6)
    void LowerConstantExpr(Function &F);

} // namespace ni_pass

#endif

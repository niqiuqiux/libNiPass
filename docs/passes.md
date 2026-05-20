# NiPass 混淆 Pass 详解

本文档详细介绍 NiPass 中每个混淆 Pass 的原理、技术实现和安全特性。

---

## 1. EnhancedStringEncryption（增强字符串加密）

**开关**: `-enstrenc` | **注解**: `enstrenc` / `noenstrenc`

### 原理

将编译产物中的明文字符串在编译期加密存储，运行时按需解密到独立的 DecryptSpace，函数返回时自动清零，防止内存 dump 提取。

### 技术特性

- **多层异构加密** — 每个字符串随机选择以下模式之一：
  - `XOR_ONLY`: `enc = val ^ K1`
  - `XOR_SUB`: `enc = (val ^ K1) - K2`
  - `XOR_ADD`: `enc = (val ^ K1) + K2`
  - `XOR_ADD_XOR`: `enc = ((val ^ K1) + K2) ^ K3`
- **Rolling-key 模式** — 在全量元素加密时，部分字符串不再生成逐元素 KeyConst 表，而是使用 `seed/mul/inc` 生成运行时滚动密钥流，降低静态 key 表特征
- **XOR 密钥混淆** — 解密循环中的 XOR 操作通过 SubstituteImpl 替换为等价复杂表达式，增加逆向分析难度
- **运行时密钥拆分** — rolling-key 的 `seed/mul/inc` 通过 `emitSplitKey` 和 volatile noise 合成，避免以直接常量形式暴露完整三元组
- **GV/BB/指令名随机化** — 消除符号特征匹配；新生成的私有全局变量使用随机但非空的名字，避免污染 `llvm.compiler.used`
- **每函数独立副本** — 取消跨函数共享，同一字符串在不同函数中使用不同密钥
- **DecryptSpace 生命周期管理** — 函数返回前自动清零解密缓冲区；返回值逃逸追踪会识别 PHI/select/load/global initializer/aggregate 中指向 DecryptSpace 的路径，避免返回字符串指针被提前清零

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-enstrcry_prob` | 100 | 每个元素被加密的概率 (%) |
| `-enstrcry_subxor_prob` | 50 | XOR 操作被替换为复杂表达式的概率 (%) |
| `-enstrcry_cleanup` | true | 函数返回时是否清零 DecryptSpace |

---

## 2. FlatteningEnhanced（增强控制流平坦化）

**开关**: `-enfla` | **注解**: `enfla` / `noenfla`

### 原理

将函数的原始控制流图（CFG）打散为 switch-case 结构，所有基本块在同一层级由一个调度变量驱动跳转，破坏原始的分支/循环结构，使反编译器难以恢复高层逻辑。

### 技术特性

- **非线性哈希调度** — 状态变量通过非线性哈希函数 `(XOR → MUL 0x9E3779B9 → ROTL 13 → ADD 0xDEADBEEF)` 计算下一跳，而非简单赋值，防止模式匹配还原
- **按支配链顺序派生 key_map** — 编译期状态密钥按 `entry -> ... -> idom` 顺序累积，与运行时 key 更新顺序保持一致，避免 dispatcher 落入默认分支死循环
- **XOR 等价表达式混淆** — 调度逻辑中的 XOR 操作随机替换为 4 种等价变体：
  - `(a | b) - (a & b)`
  - `(a + b) - 2*(a & b)`
  - `(a & ~b) | (~a & b)`
  - `~(~a ^ b)` 双重否定展开
- **随机化 case 值** — 每个基本块的 case 标签使用密码学安全随机数生成
- **虚假 case 注入** — dispatcher 中额外插入 2~5 个 bogus case，执行看似合理的 keyArray/load/xor/store 逻辑后回到调度循环，干扰 switch case 语义识别
- **显式 case 映射维护** — 对后继块统一维护 `BasicBlock -> case` 映射，避免出现“生成了 fixNum 但目标块未注册到 switch”的无效状态
- **异常边降级** — 对 `invoke` 先降级为普通 `call + br` 并清理不可达 landing pad，降低 C++ 测试代码进入平坦化时的 CFG 复杂度

---

## 3. EnVMFlatten（增强 VM 平坦化）

**开关**: `-envmf` | **注解**: `envmf` / `noenvmf`

### 原理

将函数的控制流编译为自定义虚拟机字节码，运行时由一个解释器循环（dispatcher）逐条执行。相比普通平坦化，VM 化引入了额外的间接层，使静态分析必须先理解 VM 语义才能还原逻辑。

### 技术特性

- **多态指令编码** — 每个函数随机生成不同的指令类型映射（`VMTypeMap`），同一语义指令在不同函数中编码不同
  - `RunBlock` — 执行基本块
  - `JmpBoring` — 无条件跳转
  - `JmpSelect` — 条件跳转
  - `VmNop` — 空操作（干扰分析）
- **随机 bytecode 布局** — 每个函数随机选择 `type/op1/op2` 字段槽位，并随机 stride，padding 槽填充随机垃圾，避免固定三元组布局
- **Dummy 指令插入** — 在字节码序列中插入无效指令，增加字节码体积和分析噪声
- **操作数 XOR 编码** — 字节码中的操作数经过 XOR 密钥编码，运行时解码后使用
- **非线性 bytecode key stream** — 每函数生成 `seed/mul/inc/salt/rot/shift/variant`，按 flat index 派生解密 key，替代旧的 `baseKey ^ index * multiplier` 线性公式
- **固定特征清理** — VM 入口块、handler 块、pc/flag alloca、opcode 表名等均不再使用固定 `VMEntry`/`RunBlock`/`en_opcodes` 等特征名
- **前置 CFG 规整** — 对 `invoke` 做降级处理，并将 `switch` 展开为 if-else 链，保证 VM 生成阶段只处理 1~2 后继的基本块
- **SSA 值栈化修复** — VM 改写完成后对 PHI 和跨块逃逸寄存器值执行 DemotePHI/DemoteRegToStack，维持 VM dispatcher CFG 下的 SSA 合法性
- **组合保护** — VM flatten 后写入 `envmf.applied` metadata，`eibr` 会跳过已 VM 化函数，避免两类强控制流变换叠加导致后端不稳定

---

## 4. EnhancedIndirectCall（增强间接调用）

**开关**: `-eicall` | **注解**: `eicall` / `noeicall`

### 原理

将函数中的直接调用（`call @func`）替换为通过加密函数指针表的间接调用。表初始化为随机垃圾，函数入口懒初始化时写入加密后的真实函数地址，运行时从表中取出并解密后再调用。

### 技术特性

- **Per-entry 独立密钥** — 每个被调用函数拥有 4 个独立的 64 位密钥（`key1~key4`）
- **4 密钥 XOR-ADD 混合加密** —
  - 编译时：`combined = (key1 ^ key2) + (key3 ^ key4)`，`stored = ptr + combined`
  - 运行时：重建 `combined`，`ptr = stored - combined`
- **3 种多态解密变体** — 每个 entry 随机选择：
  - 变体 0：标准 XOR + ADD 重建，SUB 解密
  - 变体 1：NOT-XOR 恒等式重建，NEG 替代 SUB
  - 变体 2：OR-AND 分解 XOR，NOT 恒等式解密
- **密钥拆分与 runtime noise** — 每个密钥在运行时拆分为 2~4 个部分，通过带 volatile load/store 的 opaque const 合成，增加直接提取难度
- **表 slot 与索引混淆** — logical callee index 到 physical table slot 随机映射，调用点再使用每函数独立 XOR index key 还原真实 slot 后访问表项
- **随机化表名和指令名清理** — 全局表名使用通用随机名，去掉 `ECall_` 等固定输出特征
- **组合保护** — 遇到带 `envmf.applied` metadata 的函数会跳过，避免在 VM dispatcher 入口再插入懒初始化拆块逻辑

---

## 5. EnhancedIndirectBranch（增强间接分支）

**开关**: `-eibr` | **注解**: `eibr` / `noeibr`

### 原理

将函数内的条件/无条件分支替换为通过加密基本块地址表的间接跳转。全局表和局部表的 initializer 均为随机垃圾，运行时在函数入口或分支点写入加密后的真实 blockaddress，再通过 `indirectbr` 跳转，破坏 CFG 的静态可分析性。

### 技术特性

- **Per-BB 独立密钥** — 每个基本块拥有 4 个独立的 64 位密钥（`key1~key4`）
- **4 密钥 XOR-ADD 混合加密** — 与 EnhancedIndirectCall 共享 `emitDecrypt4Key` 模板：
  - 编译时：`combined = (key1 ^ key2) + (key3 ^ key4)`，`stored = ptr + combined`
  - 运行时：重建 `combined`，`ptr = stored - combined`
- **3 种多态解密变体** — 同 EnhancedIndirectCall
- **全局表索引 affine 编码** — 每个函数拥有独立 `BranchIndexCodec`，编译期使用 `encoded = ((real + addKey) * mulKey) ^ xorKey`，运行时通过 `invMulKey` 还原，替代单 XOR 索引混淆
- **条件分支局部表多态化** — 条件分支的局部表 physical slot 随机化，并拆成 true/false 两个独立 decode block；每个 decode block 只解自己的目标地址，不再使用固定“双解密 + select”模板
- **PHI/CFG 修复** — 新增 decode block 后同步迁移目标 PHI incoming block，并收窄 `indirectbr` destination list 到实际目标，满足 LLVM 后端 CFG 不变量
- **基本块乱序（BB Shuffle）** — 混淆后对函数内基本块重新排列，破坏原始布局顺序
- **栈模式间接跳转** — 可选通过 `-eibr-use-stack` 启用基于栈的间接跳转方式（默认开启）
- **LowerSwitch 前置** — 自动将 switch 指令降级为 if-else 链后再处理
- **组合保护** — 遇到带 `envmf.applied` metadata 的函数会跳过，避免与 VM flatten 叠加

---

## 加密基础设施

以上 Pass 共享以下底层加密工具：

### EncryptUtils（加密工具模板）

- **`emitRuntimeNoise` / `emitOpaqueConst`** — 通过 volatile store/load 构造运行时恒等噪声，使常量 key 不是单个裸常量
- **`emitSplitKey`** — 将单个密钥拆分为 2~4 个随机部分，运行时通过 XOR 合成还原，防止密钥被直接提取
- **`emitDecrypt4Key`** — 4 密钥 XOR-ADD 多态解密模板，被 EnhancedIndirectCall 和 EnhancedIndirectBranch 共用

### CryptoUtils

- 提供密码学安全的随机数生成（`get_uint32_t`、`get_uint64_t`、`get_range`）
- 所有密钥、case 值、表名后缀均由此生成

### SubstituteImpl

- 将简单的算术/逻辑运算替换为语义等价的复杂表达式
- 被 EnhancedStringEncryption 用于混淆解密循环中的 XOR 操作

---

## Pass 执行顺序

在 `PassRegistry` 中，各 Pass 按以下顺序注册执行：

```
1. EnhancedStringEncryption  (Module Pass)  — 字符串加密
2. EnVMFlatten               (Function Pass) — VM 平坦化
3. EnhancedIndirectCall       (Function Pass) — 间接调用
4. EnhancedIndirectBranch     (Function Pass) — 间接分支
5. FlatteningEnhanced         (Module Pass)  — 控制流平坦化
```

> 字符串加密最先执行以确保密文 GV 已就位；控制流类 Pass 在函数级执行后再进入模块级平坦化。

---

## 已移除 Pass

### EnhancedIndirectGlobalVariable

`-eigv` / `eigv` 已从构建、注册和文档示例中移除。该 Pass 会对函数内全局变量引用生成大量间接表和构造器逻辑，在复杂 C/C++ 测试中存在明显编译期内存膨胀风险。当前版本不再接受 `-mllvm -eigv`，误传该参数会触发 LLVM option parsing 的 unknown option 错误。

---

## 当前验证状态

- x86 使用系统 LLVM/clang；Android/ARM64 插件使用 `/home/qiu/llvm-toolchain/prebuilts/clang/host/linux-x86/clang-r530567` 构建。
- x86 已验证默认 `-enfla`、单 pass `-enstrenc`、`-envmf`、`-eicall`、`-eibr`。
- ARM64 设备 Pixel 6 (`arm64-v8a`) 已验证默认 `-enfla`、单 pass `-eibr`、`-enstrenc`，以及全量 `-enstrenc;-enfla;-envmf;-eicall;-eibr`，均为 5/5 passed。

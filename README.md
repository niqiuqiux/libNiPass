# NiPass - Enhanced LLVM Obfuscation Passes

基于 LLVM 19 的增强混淆 Pass 集合。

## 构建

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

当前默认产物：`lib/libNiPass-19.0.0.so`

## Pass 列表

| 开关 | 注解名 | 说明 |
|------|--------|------|
| `-enstrenc` | `enstrenc` | 增强字符串加密 |
| `-enfla` | `enfla` | 增强控制流平坦化 |
| `-envmf` | `envmf` | 增强 VM 平坦化 |
| `-eicall` | `eicall` | 增强间接调用 |
| `-eibr` | `eibr` | 增强间接分支 |

## 使用方式

### 方式一：命令行全局开关

使用 `-fplugin` 加载插件，通过 `-mllvm` 传递开关，对所有函数生效。
当前仓库内的 Android 测试工程也默认采用这条链路。

```bash
# 开启字符串加密 + 平坦化
clang-19 -fplugin=./lib/libNiPass-19.0.0.so -O1 \
  -mllvm -enstrenc -mllvm -enfla \
  test.c -o test

# 开启全部 pass
clang-19 -fplugin=./lib/libNiPass-19.0.0.so -O1 \
  -mllvm -enstrenc -mllvm -enfla -mllvm -envmf \
  -mllvm -eicall -mllvm -eibr \
  test.c -o test
```

> 注意：只要依赖 `-mllvm` 命令行开关，就必须用 `-fplugin`，因为 `-fpass-plugin` 加载时机晚于命令行解析，相关 `-mllvm` 选项不会被识别。

### 方式二：函数注解驱动

通过 `__attribute__((annotate(...)))` 逐函数控制。现在两种加载方式都可用：

- `-fpass-plugin`：纯后端 pass-plugin 路径
- `-fplugin`：通过内置 frontend bridge 转接到后端 pass 回调

如果同时还需要 `-mllvm` 全局开关，请优先使用 `-fplugin`。

```c
// 对该函数开启字符串加密
__attribute__((annotate("enstrenc")))
void secret_func() {
    const char *key = "my_secret_key";
    printf("%s\n", key);
}

// 对该函数开启 VM 平坦化
__attribute__((annotate("envmf")))
int compute(int x) {
    if (x > 10) return x * 2;
    return x + 1;
}

// 不加注解的函数不会被混淆
int normal(int x) {
    return x + 1;
}
```

```bash
clang-19 -fpass-plugin=./lib/libNiPass-19.0.0.so -O1 test.c -o test

# 或者统一走 -fplugin 桥接路径
clang-19 -fplugin=./lib/libNiPass-19.0.0.so -O1 test.c -o test
```

### 方式三：命令行 + 注解混合

用 `-fplugin` + `-mllvm` 设置全局默认，再用注解逐函数覆盖：

- 注解 `enstrenc` → 强制开启（即使全局未开）
- 注解 `noenstrenc` → 强制关闭（即使全局已开）

```bash
# 全局开启字符串加密，但个别函数可用 noenstrenc 关闭
clang-19 -fplugin=./lib/libNiPass-19.0.0.so -O1 \
  -mllvm -enstrenc \
  test.c -o test
```

```c
// 全局已开启 enstrenc，此函数强制关闭
__attribute__((annotate("noenstrenc")))
void skip_this() { ... }
```

## CMake 集成

项目提供了 CMake 脚本（`testarm64/CMakeLists.txt`）用于 Android ARM64 交叉编译。
当前测试工程统一使用 `-fplugin + -mllvm` 路径，不再切换 `PLUGIN_MODE`。

### CMake 变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ENABLE_OBFUSCATION` | `ON` | 是否启用 NiPass 混淆 |
| `NIPASS_LIB` | `../lib/libNiPass-19.0.0.so` | NiPass 插件路径 |
| `NIPASS_PASSES` | `-enfla` | 传递给编译器的 `-mllvm` 开关列表 |

### 全局开关（fplugin）

通过 `-fplugin` 加载插件，`-mllvm` 传递开关，对所有函数生效：

```bash
cmake -S testarm64 -B build \
  -DNIPASS_PASSES="-enstrenc;-enfla"
cmake --build build -j$(nproc)
```

开启全部 pass：

```bash
cmake -S testarm64 -B build \
  -DNIPASS_PASSES="-enstrenc;-enfla;-envmf;-eicall;-eibr"
cmake --build build -j$(nproc)
```

### 不启用混淆（对照组）

```bash
cmake -S testarm64 -B build \
  -DENABLE_OBFUSCATION=OFF
cmake --build build -j$(nproc)
```

### 自定义插件路径

```bash
cmake -S testarm64 -B build \
  -DNIPASS_LIB=/path/to/libNiPass-19.0.0.so
```

> CMake 脚本内部使用 `SHELL:` 前缀确保每个 `-mllvm <pass>` 参数正确配对，避免被 CMake 去重合并。
> 同时对测试源文件设置了 `OBJECT_DEPENDS=${NIPASS_LIB}`，插件 `.so` 更新后会自动触发相关目标重编。

## ARM64 测试脚本

`testarm64` 目录当前包含 5 个测试目标：

- `test_nipass`
- `test_annotate`
- `test_production`
- `test_stl`
- `test_template`

### 编译

```bash
cd testarm64

# 混淆版
./build.sh obf

# 基线版
./build.sh plain

# 同时编译两套并做对比
./build.sh both
```

### 推送到设备执行

```bash
cd testarm64

# 运行混淆版，单个程序超时 5 秒
./run_test.sh -t 5 obf

# 指定设备
./run_test.sh -s <serial> -t 5 obf

# 对比 plain / obf 两套结果
./run_test.sh -t 5 both
```

脚本会在设备侧使用 `timeout` 包裹执行，避免混淆回归导致测试卡死。

## 作者

Made By Ni-QiuQiu

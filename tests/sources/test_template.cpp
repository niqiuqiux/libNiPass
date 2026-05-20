/**
 * NiPass 模板元编程复杂仿真测试
 *
 * 覆盖场景：
 *   - 变参模板 (variadic templates)
 *   - SFINAE / if constexpr
 *   - CRTP (Curiously Recurring Template Pattern)
 *   - 模板特化 (full / partial specialization)
 *   - 类型萃取 (type traits)
 *   - 编译期计算 (constexpr)
 *   - 策略模式 (policy-based design)
 *   - 表达式模板 (expression templates)
 *   - 编译期字符串哈希
 *   - Tuple 操作与展开
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <array>
#include <tuple>
#include <type_traits>
#include <functional>
#include <memory>
#include <utility>
#include <numeric>
#include <algorithm>

/* ========================================================================
 * 敏感字符串 — 字符串加密目标
 * ======================================================================== */

static const char *CRYPTO_PRIVATE_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBkg...nipass...fake\n-----END EC PRIVATE KEY-----";
static const char *OAUTH_CLIENT_SECRET = "nipass_oauth_cKj9$mNx2Lp7Qr4Tn6Wv1Yz8Fb3Hd5";
static const char *INTERNAL_API_ENDPOINT = "https://internal-api.nipass.dev/v3/telemetry";
static const char *SYMMETRIC_KEY_256 = "\x4e\x69\x50\x61\x73\x73\x32\x30\x32\x34\x4b\x65\x79\x21\x40\x23"
                                       "\x24\x25\x5e\x26\x2a\x28\x29\x5f\x2b\x3d\x7b\x7d\x5b\x5d\x7c\x5c";

/* ========================================================================
 * 测试框架
 * ======================================================================== */

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { g_tests_passed++; } \
    else { g_tests_failed++; printf("  FAIL: %s (line %d)\n", msg, __LINE__); } \
} while(0)

/* ========================================================================
 * 1. 编译期计算 — constexpr 递归 + 查找表
 * ======================================================================== */

constexpr uint64_t ct_factorial(int n) {
    uint64_t r = 1;
    for (int i = 2; i <= n; i++) r *= i;
    return r;
}

constexpr uint64_t ct_fibonacci(int n) {
    if (n <= 1) return n;
    uint64_t a = 0, b = 1;
    for (int i = 2; i <= n; i++) { uint64_t t = a + b; a = b; b = t; }
    return b;
}

constexpr bool ct_is_prime(int n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (int i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0) return false;
    return true;
}

// 编译期生成素数表
template<int N>
constexpr auto make_prime_table() {
    std::array<int, N> primes{};
    int count = 0, candidate = 2;
    while (count < N) {
        if (ct_is_prime(candidate))
            primes[count++] = candidate;
        candidate++;
    }
    return primes;
}

// 编译期字符串哈希 (FNV-1a)
constexpr uint32_t ct_hash(const char *s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) { h ^= (uint8_t)*s++; h *= 0x01000193u; }
    return h;
}

/* ========================================================================
 * 2. 类型萃取与 SFINAE
 * ======================================================================== */

// 自定义 type traits
template<typename T> struct is_numeric : std::false_type {};
template<> struct is_numeric<int> : std::true_type {};
template<> struct is_numeric<float> : std::true_type {};
template<> struct is_numeric<double> : std::true_type {};
template<> struct is_numeric<int64_t> : std::true_type {};
template<> struct is_numeric<uint32_t> : std::true_type {};

template<typename T>
inline constexpr bool is_numeric_v = is_numeric<T>::value;

// SFINAE: 只对数值类型启用
template<typename T>
auto safe_divide(T a, T b) -> std::enable_if_t<is_numeric_v<T>, T> {
    if (b == T{}) return T{};
    return a / b;
}

// if constexpr 分发
template<typename T>
std::string type_describe(const T &val) {
    if constexpr (std::is_integral_v<T>) {
        return "int:" + std::to_string(val);
    } else if constexpr (std::is_floating_point_v<T>) {
        char buf[64];
        snprintf(buf, sizeof(buf), "float:%.4f", (double)val);
        return buf;
    } else if constexpr (std::is_same_v<T, std::string>) {
        return "string:" + val;
    } else {
        return "unknown";
    }
}

/* ========================================================================
 * 3. CRTP — 静态多态 + Mixin
 * ======================================================================== */

// 静态多态基类
template<typename Derived>
class Serializable {
public:
    std::string serialize() const {
        return static_cast<const Derived *>(this)->do_serialize();
    }
    size_t serialized_size() const {
        return serialize().size();
    }
};

// 计数 Mixin
template<typename Derived>
class InstanceCounter {
    static inline int count_ = 0;
public:
    InstanceCounter() { count_++; }
    InstanceCounter(const InstanceCounter &) { count_++; }
    ~InstanceCounter() { count_--; }
    static int instance_count() { return count_; }
};

// 具体类型
class UserProfile : public Serializable<UserProfile>, public InstanceCounter<UserProfile> {
    std::string name_;
    int age_;
    double score_;
public:
    UserProfile(std::string name, int age, double score)
        : name_(std::move(name)), age_(age), score_(score) {}

    std::string do_serialize() const {
        char buf[256];
        snprintf(buf, sizeof(buf), "{\"name\":\"%s\",\"age\":%d,\"score\":%.2f}",
                 name_.c_str(), age_, score_);
        return buf;
    }
    const std::string &name() const { return name_; }
    int age() const { return age_; }
};

class DeviceInfo : public Serializable<DeviceInfo>, public InstanceCounter<DeviceInfo> {
    std::string model_;
    uint32_t firmware_;
public:
    DeviceInfo(std::string model, uint32_t fw)
        : model_(std::move(model)), firmware_(fw) {}

    std::string do_serialize() const {
        char buf[256];
        snprintf(buf, sizeof(buf), "{\"model\":\"%s\",\"firmware\":%u}",
                 model_.c_str(), firmware_);
        return buf;
    }
};

/* ========================================================================
 * 4. 策略模式 (Policy-based design)
 * ======================================================================== */

// 排序策略
struct AscendingPolicy {
    template<typename T>
    static bool compare(const T &a, const T &b) { return a < b; }
    static const char *name() { return "ascending"; }
};

struct DescendingPolicy {
    template<typename T>
    static bool compare(const T &a, const T &b) { return a > b; }
    static const char *name() { return "descending"; }
};

struct AbsolutePolicy {
    template<typename T>
    static bool compare(const T &a, const T &b) {
        auto abs_a = a < T{} ? -a : a;
        auto abs_b = b < T{} ? -b : b;
        return abs_a < abs_b;
    }
    static const char *name() { return "absolute"; }
};

// 哈希策略
struct FNV1aHash {
    static uint32_t hash(const void *data, size_t len) {
        auto p = static_cast<const uint8_t *>(data);
        uint32_t h = 0x811c9dc5u;
        for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 0x01000193u; }
        return h;
    }
    static const char *name() { return "fnv1a"; }
};

struct DJB2Hash {
    static uint32_t hash(const void *data, size_t len) {
        auto p = static_cast<const uint8_t *>(data);
        uint32_t h = 5381;
        for (size_t i = 0; i < len; i++) h = ((h << 5) + h) + p[i];
        return h;
    }
    static const char *name() { return "djb2"; }
};

// 策略容器
template<typename SortPolicy, typename HashPolicy>
class DataProcessor {
    std::vector<int> data_;
public:
    void add(int val) { data_.push_back(val); }

    void sort() {
        std::sort(data_.begin(), data_.end(),
            [](const int &a, const int &b) { return SortPolicy::compare(a, b); });
    }

    uint32_t hash_all() const {
        return HashPolicy::hash(data_.data(), data_.size() * sizeof(int));
    }

    const std::vector<int> &data() const { return data_; }
    bool is_sorted() const {
        for (size_t i = 1; i < data_.size(); i++)
            if (!SortPolicy::compare(data_[i - 1], data_[i]) && data_[i - 1] != data_[i])
                return false;
        return true;
    }

    std::string describe() const {
        char buf[128];
        snprintf(buf, sizeof(buf), "DataProcessor<%s,%s> size=%zu",
                 SortPolicy::name(), HashPolicy::name(), data_.size());
        return buf;
    }
};

/* ========================================================================
 * 5. 变参模板 — 类型安全 printf / Tuple 操作
 * ======================================================================== */

// 变参求和
template<typename T>
T variadic_sum(T val) { return val; }

template<typename T, typename... Args>
T variadic_sum(T first, Args... rest) { return first + variadic_sum<T>(rest...); }

// 变参最大值
template<typename T>
T variadic_max(T val) { return val; }

template<typename T, typename... Args>
T variadic_max(T first, Args... rest) {
    T rest_max = variadic_max<T>(rest...);
    return first > rest_max ? first : rest_max;
}

// 类型安全格式化
class SafeFormatter {
    std::string result_;

    void append_arg(int val) {
        char buf[32]; snprintf(buf, sizeof(buf), "%d", val);
        result_ += buf;
    }
    void append_arg(double val) {
        char buf[64]; snprintf(buf, sizeof(buf), "%.4f", val);
        result_ += buf;
    }
    void append_arg(const char *val) { result_ += val; }
    void append_arg(const std::string &val) { result_ += val; }
    void append_arg(bool val) { result_ += val ? "true" : "false"; }

    void format_impl(const char *fmt) {
        while (*fmt) result_ += *fmt++;
    }

    template<typename T, typename... Args>
    void format_impl(const char *fmt, T &&val, Args &&...args) {
        while (*fmt) {
            if (*fmt == '{' && *(fmt + 1) == '}') {
                append_arg(std::forward<T>(val));
                format_impl(fmt + 2, std::forward<Args>(args)...);
                return;
            }
            result_ += *fmt++;
        }
    }

public:
    template<typename... Args>
    static std::string format(const char *fmt, Args &&...args) {
        SafeFormatter sf;
        sf.format_impl(fmt, std::forward<Args>(args)...);
        return sf.result_;
    }
};

// Tuple for_each
template<typename Tuple, typename Func, size_t... Is>
void tuple_for_each_impl(const Tuple &t, Func &&f, std::index_sequence<Is...>) {
    (f(std::get<Is>(t)), ...);
}

template<typename... Args, typename Func>
void tuple_for_each(const std::tuple<Args...> &t, Func &&f) {
    tuple_for_each_impl(t, std::forward<Func>(f), std::index_sequence_for<Args...>{});
}

// Tuple transform
template<typename Tuple, typename Func, size_t... Is>
auto tuple_transform_impl(const Tuple &t, Func &&f, std::index_sequence<Is...>) {
    return std::make_tuple(f(std::get<Is>(t))...);
}

template<typename... Args, typename Func>
auto tuple_transform(const std::tuple<Args...> &t, Func &&f) {
    return tuple_transform_impl(t, std::forward<Func>(f), std::index_sequence_for<Args...>{});
}

/* ========================================================================
 * 6. 表达式模板 — 延迟求值向量运算
 * ======================================================================== */

template<typename E>
class VecExpr {
public:
    double operator[](size_t i) const { return static_cast<const E &>(*this)[i]; }
    size_t size() const { return static_cast<const E &>(*this).size(); }
};

class Vec : public VecExpr<Vec> {
    std::vector<double> data_;
public:
    Vec() = default;
    explicit Vec(size_t n, double val = 0.0) : data_(n, val) {}
    Vec(std::initializer_list<double> il) : data_(il) {}

    template<typename E>
    Vec(const VecExpr<E> &expr) : data_(expr.size()) {
        for (size_t i = 0; i < data_.size(); i++) data_[i] = expr[i];
    }

    template<typename E>
    Vec &operator=(const VecExpr<E> &expr) {
        data_.resize(expr.size());
        for (size_t i = 0; i < data_.size(); i++) data_[i] = expr[i];
        return *this;
    }

    double operator[](size_t i) const { return data_[i]; }
    double &operator[](size_t i) { return data_[i]; }
    size_t size() const { return data_.size(); }

    double dot(const Vec &other) const {
        double s = 0;
        for (size_t i = 0; i < data_.size() && i < other.size(); i++)
            s += data_[i] * other[i];
        return s;
    }

    double norm() const { return std::sqrt(dot(*this)); }
};

template<typename E1, typename E2>
class VecAdd : public VecExpr<VecAdd<E1, E2>> {
    const E1 &a_; const E2 &b_;
public:
    VecAdd(const E1 &a, const E2 &b) : a_(a), b_(b) {}
    double operator[](size_t i) const { return a_[i] + b_[i]; }
    size_t size() const { return a_.size(); }
};

template<typename E1, typename E2>
class VecMul : public VecExpr<VecMul<E1, E2>> {
    const E1 &a_; const E2 &b_;
public:
    VecMul(const E1 &a, const E2 &b) : a_(a), b_(b) {}
    double operator[](size_t i) const { return a_[i] * b_[i]; }
    size_t size() const { return a_.size(); }
};

template<typename E>
class VecScale : public VecExpr<VecScale<E>> {
    double s_; const E &e_;
public:
    VecScale(double s, const E &e) : s_(s), e_(e) {}
    double operator[](size_t i) const { return s_ * e_[i]; }
    size_t size() const { return e_.size(); }
};

template<typename E1, typename E2>
VecAdd<E1, E2> operator+(const VecExpr<E1> &a, const VecExpr<E2> &b) {
    return VecAdd<E1, E2>(static_cast<const E1 &>(a), static_cast<const E2 &>(b));
}

template<typename E1, typename E2>
VecMul<E1, E2> operator*(const VecExpr<E1> &a, const VecExpr<E2> &b) {
    return VecMul<E1, E2>(static_cast<const E1 &>(a), static_cast<const E2 &>(b));
}

template<typename E>
VecScale<E> operator*(double s, const VecExpr<E> &e) {
    return VecScale<E>(s, static_cast<const E &>(e));
}

/* ========================================================================
 * 7. 编译期状态机 — 模板特化 + 递归
 * ======================================================================== */

enum class FSMState { Idle, Running, Paused, Stopped, Error };
enum class FSMEvent { Start, Pause, Resume, Stop, Fail, Reset };

// 默认转换：进入 Error
template<FSMState S, FSMEvent E>
struct Transition {
    static constexpr FSMState next = FSMState::Error;
    static constexpr bool valid = false;
};

// 合法转换特化
template<> struct Transition<FSMState::Idle, FSMEvent::Start> {
    static constexpr FSMState next = FSMState::Running; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Running, FSMEvent::Pause> {
    static constexpr FSMState next = FSMState::Paused; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Running, FSMEvent::Stop> {
    static constexpr FSMState next = FSMState::Stopped; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Running, FSMEvent::Fail> {
    static constexpr FSMState next = FSMState::Error; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Paused, FSMEvent::Resume> {
    static constexpr FSMState next = FSMState::Running; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Paused, FSMEvent::Stop> {
    static constexpr FSMState next = FSMState::Stopped; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Error, FSMEvent::Reset> {
    static constexpr FSMState next = FSMState::Idle; static constexpr bool valid = true;
};
template<> struct Transition<FSMState::Stopped, FSMEvent::Reset> {
    static constexpr FSMState next = FSMState::Idle; static constexpr bool valid = true;
};

// 运行时状态机（使用编译期表驱动）
class StateMachine {
    FSMState state_ = FSMState::Idle;
    std::vector<std::pair<FSMEvent, bool>> history_;

    bool try_transition(FSMEvent event) {
        FSMState next = FSMState::Error;
        bool valid = false;

        switch (state_) {
        case FSMState::Idle:
            if (event == FSMEvent::Start) { next = Transition<FSMState::Idle, FSMEvent::Start>::next; valid = true; }
            break;
        case FSMState::Running:
            if (event == FSMEvent::Pause) { next = Transition<FSMState::Running, FSMEvent::Pause>::next; valid = true; }
            else if (event == FSMEvent::Stop) { next = Transition<FSMState::Running, FSMEvent::Stop>::next; valid = true; }
            else if (event == FSMEvent::Fail) { next = Transition<FSMState::Running, FSMEvent::Fail>::next; valid = true; }
            break;
        case FSMState::Paused:
            if (event == FSMEvent::Resume) { next = Transition<FSMState::Paused, FSMEvent::Resume>::next; valid = true; }
            else if (event == FSMEvent::Stop) { next = Transition<FSMState::Paused, FSMEvent::Stop>::next; valid = true; }
            break;
        case FSMState::Error:
            if (event == FSMEvent::Reset) { next = Transition<FSMState::Error, FSMEvent::Reset>::next; valid = true; }
            break;
        case FSMState::Stopped:
            if (event == FSMEvent::Reset) { next = Transition<FSMState::Stopped, FSMEvent::Reset>::next; valid = true; }
            break;
        }

        history_.push_back({event, valid});
        if (valid) state_ = next;
        return valid;
    }

public:
    bool send(FSMEvent e) { return try_transition(e); }
    FSMState state() const { return state_; }
    size_t history_size() const { return history_.size(); }
};

/* ========================================================================
 * 8. 类型擦除容器 — 小对象优化
 * ======================================================================== */

class AnyCallable {
    struct Concept {
        virtual ~Concept() = default;
        virtual int invoke(int) const = 0;
        virtual std::unique_ptr<Concept> clone() const = 0;
        virtual const char *type_name() const = 0;
    };

    template<typename F>
    struct Model : Concept {
        F func_;
        explicit Model(F f) : func_(std::move(f)) {}
        int invoke(int x) const override { return func_(x); }
        std::unique_ptr<Concept> clone() const override {
            return std::make_unique<Model>(func_);
        }
        const char *type_name() const override { return "lambda"; }
    };

    std::unique_ptr<Concept> impl_;

public:
    AnyCallable() = default;

    template<typename F>
    AnyCallable(F f) : impl_(std::make_unique<Model<F>>(std::move(f))) {}

    AnyCallable(const AnyCallable &other) : impl_(other.impl_ ? other.impl_->clone() : nullptr) {}
    AnyCallable &operator=(const AnyCallable &other) {
        impl_ = other.impl_ ? other.impl_->clone() : nullptr;
        return *this;
    }
    AnyCallable(AnyCallable &&) = default;
    AnyCallable &operator=(AnyCallable &&) = default;

    int operator()(int x) const { return impl_ ? impl_->invoke(x) : 0; }
    explicit operator bool() const { return impl_ != nullptr; }
    const char *type_name() const { return impl_ ? impl_->type_name() : "empty"; }
};

/* ========================================================================
 * 9. 测试用例
 * ======================================================================== */

static void test_constexpr_computation() {
    printf("[TEST] Constexpr Computation\n");

    // 编译期阶乘
    constexpr auto f10 = ct_factorial(10);
    TEST_ASSERT(f10 == 3628800, "10! = 3628800");
    constexpr auto f0 = ct_factorial(0);
    TEST_ASSERT(f0 == 1, "0! = 1");

    // 编译期斐波那契
    constexpr auto fib10 = ct_fibonacci(10);
    TEST_ASSERT(fib10 == 55, "fib(10) = 55");
    constexpr auto fib20 = ct_fibonacci(20);
    TEST_ASSERT(fib20 == 6765, "fib(20) = 6765");

    // 编译期素数判定
    static_assert(ct_is_prime(2), "2 is prime");
    static_assert(ct_is_prime(97), "97 is prime");
    static_assert(!ct_is_prime(100), "100 is not prime");
    TEST_ASSERT(ct_is_prime(7919), "7919 is prime");
    TEST_ASSERT(!ct_is_prime(7920), "7920 is not prime");

    // 编译期素数表
    constexpr auto primes = make_prime_table<20>();
    TEST_ASSERT(primes[0] == 2, "first prime is 2");
    TEST_ASSERT(primes[7] == 19, "8th prime is 19");
    TEST_ASSERT(primes[19] == 71, "20th prime is 71");

    // 编译期字符串哈希
    constexpr auto h1 = ct_hash("NiPass");
    constexpr auto h2 = ct_hash("NiPass");
    constexpr auto h3 = ct_hash("nipass");
    TEST_ASSERT(h1 == h2, "ct_hash deterministic");
    TEST_ASSERT(h1 != h3, "ct_hash case sensitive");
    TEST_ASSERT(h1 != 0, "ct_hash non-zero");

    // 编译期哈希做 switch
    uint32_t cmd_hash = ct_hash("encrypt");
    const char *result = "unknown";
    switch (cmd_hash) {
        case ct_hash("hash"):    result = "hash"; break;
        case ct_hash("encrypt"): result = "encrypt"; break;
        case ct_hash("decrypt"): result = "decrypt"; break;
    }
    TEST_ASSERT(strcmp(result, "encrypt") == 0, "ct_hash switch dispatch");
}

static void test_sfinae_and_traits() {
    printf("[TEST] SFINAE & Type Traits\n");

    TEST_ASSERT(is_numeric_v<int>, "int is numeric");
    TEST_ASSERT(is_numeric_v<double>, "double is numeric");
    TEST_ASSERT(!is_numeric_v<std::string>, "string is not numeric");
    TEST_ASSERT(!is_numeric_v<char>, "char is not numeric");

    TEST_ASSERT(safe_divide(10, 3) == 3, "int divide");
    TEST_ASSERT(safe_divide(10, 0) == 0, "int divide by zero");
    double d = safe_divide(10.0, 3.0);
    TEST_ASSERT(d > 3.33 && d < 3.34, "double divide");
    TEST_ASSERT(safe_divide(1.0, 0.0) == 0.0, "double divide by zero");

    auto s1 = type_describe(42);
    TEST_ASSERT(s1 == "int:42", "describe int");
    auto s2 = type_describe(3.14);
    TEST_ASSERT(s2.find("float:3.14") != std::string::npos, "describe double");
    auto s3 = type_describe(std::string("hello"));
    TEST_ASSERT(s3 == "string:hello", "describe string");
}

static void test_crtp() {
    printf("[TEST] CRTP (Serializable + InstanceCounter)\n");

    {
        UserProfile u1("alice", 30, 95.5);
        UserProfile u2("bob", 25, 88.0);
        TEST_ASSERT(UserProfile::instance_count() == 2, "2 UserProfile instances");

        auto json1 = u1.serialize();
        TEST_ASSERT(json1.find("\"name\":\"alice\"") != std::string::npos, "serialize name");
        TEST_ASSERT(json1.find("\"age\":30") != std::string::npos, "serialize age");
        TEST_ASSERT(u1.serialized_size() > 20, "serialized_size > 20");

        DeviceInfo d1("Pixel-7", 20240101);
        TEST_ASSERT(DeviceInfo::instance_count() == 1, "1 DeviceInfo instance");
        auto json2 = d1.serialize();
        TEST_ASSERT(json2.find("Pixel-7") != std::string::npos, "device model");
    }
    TEST_ASSERT(UserProfile::instance_count() == 0, "0 after scope exit");
    TEST_ASSERT(DeviceInfo::instance_count() == 0, "0 devices after scope exit");
}

static void test_policy_design() {
    printf("[TEST] Policy-Based Design\n");

    DataProcessor<AscendingPolicy, FNV1aHash> asc;
    for (int v : {5, 3, 8, 1, 9, 2, 7}) asc.add(v);
    asc.sort();
    TEST_ASSERT(asc.is_sorted(), "ascending sorted");
    TEST_ASSERT(asc.data().front() == 1, "ascending first = 1");
    TEST_ASSERT(asc.data().back() == 9, "ascending last = 9");

    DataProcessor<DescendingPolicy, DJB2Hash> desc;
    for (int v : {5, 3, 8, 1, 9, 2, 7}) desc.add(v);
    desc.sort();
    TEST_ASSERT(desc.is_sorted(), "descending sorted");
    TEST_ASSERT(desc.data().front() == 9, "descending first = 9");

    DataProcessor<AbsolutePolicy, FNV1aHash> abs_proc;
    for (int v : {-5, 3, -8, 1, -9, 2, 7}) abs_proc.add(v);
    abs_proc.sort();
    TEST_ASSERT(abs_proc.data().front() == 1, "absolute first = 1");

    // 不同哈希策略产生不同结果
    uint32_t h1 = asc.hash_all();
    uint32_t h2 = desc.hash_all();
    TEST_ASSERT(h1 != 0 && h2 != 0, "hashes non-zero");

    auto d = asc.describe();
    TEST_ASSERT(d.find("ascending") != std::string::npos, "describe contains policy name");
}

static void test_variadic_templates() {
    printf("[TEST] Variadic Templates\n");

    TEST_ASSERT(variadic_sum(1, 2, 3, 4, 5) == 15, "variadic sum 1..5");
    TEST_ASSERT(variadic_sum(100) == 100, "variadic sum single");
    TEST_ASSERT(variadic_max(3, 7, 2, 9, 1, 8) == 9, "variadic max = 9");
    TEST_ASSERT(variadic_max(42) == 42, "variadic max single");

    // SafeFormatter
    auto s1 = SafeFormatter::format("Hello {} you are {} years old", "alice", 30);
    TEST_ASSERT(s1 == "Hello alice you are 30 years old", "format string+int");

    auto s2 = SafeFormatter::format("pi={} e={} ok={}", 3.1416, 2.7183, true);
    TEST_ASSERT(s2.find("3.1416") != std::string::npos, "format double");
    TEST_ASSERT(s2.find("true") != std::string::npos, "format bool");

    auto s3 = SafeFormatter::format("no placeholders here");
    TEST_ASSERT(s3 == "no placeholders here", "format no args");

    // Tuple for_each
    auto tup = std::make_tuple(10, 3.14, std::string("hello"));
    int count = 0;
    tuple_for_each(tup, [&count](const auto &) { count++; });
    TEST_ASSERT(count == 3, "tuple_for_each visits 3 elements");

    // Tuple transform
    auto nums = std::make_tuple(1, 2, 3);
    auto doubled = tuple_transform(nums, [](auto x) { return x * 2; });
    TEST_ASSERT(std::get<0>(doubled) == 2, "tuple transform [0]");
    TEST_ASSERT(std::get<1>(doubled) == 4, "tuple transform [1]");
    TEST_ASSERT(std::get<2>(doubled) == 6, "tuple transform [2]");
}

static void test_expression_templates() {
    printf("[TEST] Expression Templates (Vec)\n");

    Vec a = {1.0, 2.0, 3.0, 4.0};
    Vec b = {5.0, 6.0, 7.0, 8.0};

    // a + b (延迟求值)
    Vec c = a + b;
    TEST_ASSERT(c[0] == 6.0 && c[1] == 8.0 && c[2] == 10.0 && c[3] == 12.0, "vec add");

    // a * b (逐元素乘)
    Vec d = a * b;
    TEST_ASSERT(d[0] == 5.0 && d[1] == 12.0 && d[2] == 21.0 && d[3] == 32.0, "vec mul");

    // 标量乘
    Vec e = 2.0 * a;
    TEST_ASSERT(e[0] == 2.0 && e[3] == 8.0, "vec scale");

    // 复合表达式: 2*a + b (单次遍历求值)
    Vec f = 2.0 * a + b;
    TEST_ASSERT(f[0] == 7.0 && f[1] == 10.0 && f[2] == 13.0 && f[3] == 16.0, "vec compound expr");

    // dot product
    double dp = a.dot(b);
    TEST_ASSERT(dp == 70.0, "dot product = 70");

    // norm
    Vec unit = {3.0, 4.0};
    double n = unit.norm();
    TEST_ASSERT(n > 4.99 && n < 5.01, "norm of (3,4) = 5");
}

static void test_state_machine() {
    printf("[TEST] Template State Machine\n");

    // 编译期验证
    static_assert(Transition<FSMState::Idle, FSMEvent::Start>::valid, "Idle->Start valid");
    static_assert(Transition<FSMState::Idle, FSMEvent::Start>::next == FSMState::Running, "Idle->Start->Running");
    static_assert(!Transition<FSMState::Idle, FSMEvent::Pause>::valid, "Idle->Pause invalid");

    StateMachine sm;
    TEST_ASSERT(sm.state() == FSMState::Idle, "initial state Idle");

    TEST_ASSERT(sm.send(FSMEvent::Start), "Idle -> Running");
    TEST_ASSERT(sm.state() == FSMState::Running, "state is Running");

    TEST_ASSERT(!sm.send(FSMEvent::Start), "Running -> Start invalid");
    TEST_ASSERT(sm.state() == FSMState::Running, "still Running");

    TEST_ASSERT(sm.send(FSMEvent::Pause), "Running -> Paused");
    TEST_ASSERT(sm.state() == FSMState::Paused, "state is Paused");

    TEST_ASSERT(sm.send(FSMEvent::Resume), "Paused -> Running");
    TEST_ASSERT(sm.state() == FSMState::Running, "back to Running");

    TEST_ASSERT(sm.send(FSMEvent::Fail), "Running -> Error");
    TEST_ASSERT(sm.state() == FSMState::Error, "state is Error");

    TEST_ASSERT(!sm.send(FSMEvent::Start), "Error -> Start invalid");
    TEST_ASSERT(sm.send(FSMEvent::Reset), "Error -> Idle");
    TEST_ASSERT(sm.state() == FSMState::Idle, "back to Idle");

    TEST_ASSERT(sm.send(FSMEvent::Start), "restart");
    TEST_ASSERT(sm.send(FSMEvent::Stop), "Running -> Stopped");
    TEST_ASSERT(sm.state() == FSMState::Stopped, "state is Stopped");
    TEST_ASSERT(sm.send(FSMEvent::Reset), "Stopped -> Idle");

    TEST_ASSERT(sm.history_size() == 10, "10 events in history");
}

static void test_type_erasure() {
    printf("[TEST] Type Erasure (AnyCallable)\n");

    AnyCallable f1([](int x) { return x * 2; });
    TEST_ASSERT(f1(5) == 10, "lambda *2");
    TEST_ASSERT(static_cast<bool>(f1), "f1 is valid");

    AnyCallable f2([](int x) { return x * x + 1; });
    TEST_ASSERT(f2(4) == 17, "lambda x^2+1");

    // 拷贝
    AnyCallable f3 = f1;
    TEST_ASSERT(f3(7) == 14, "copy works");

    // 容器
    std::vector<AnyCallable> pipeline;
    pipeline.push_back([](int x) { return x + 10; });
    pipeline.push_back([](int x) { return x * 3; });
    pipeline.push_back([](int x) { return x - 5; });

    int val = 1;
    for (auto &fn : pipeline) val = fn(val);
    TEST_ASSERT(val == 28, "pipeline: (1+10)*3-5 = 28");

    // 空
    AnyCallable empty;
    TEST_ASSERT(!static_cast<bool>(empty), "empty callable");
    TEST_ASSERT(empty(42) == 0, "empty returns 0");
}

static void test_string_constants() {
    printf("[TEST] String Constants Visibility\n");

    TEST_ASSERT(strlen(CRYPTO_PRIVATE_KEY) > 30, "private key present");
    TEST_ASSERT(strlen(OAUTH_CLIENT_SECRET) > 20, "oauth secret present");
    TEST_ASSERT(strlen(INTERNAL_API_ENDPOINT) > 20, "api endpoint present");
    TEST_ASSERT(strlen(SYMMETRIC_KEY_256) == 32, "symmetric key 32 bytes");

    TEST_ASSERT(std::string(CRYPTO_PRIVATE_KEY).find("BEGIN EC PRIVATE KEY") != std::string::npos,
                "private key content");
    TEST_ASSERT(std::string(OAUTH_CLIENT_SECRET).find("nipass_oauth") != std::string::npos,
                "oauth secret content");
    TEST_ASSERT(std::string(INTERNAL_API_ENDPOINT).find("nipass.dev") != std::string::npos,
                "api endpoint content");
}

/* ========================================================================
 * main
 * ======================================================================== */

int main() {
    printf("========================================\n");
    printf("  NiPass Template Metaprogramming Test\n");
    printf("========================================\n\n");

    test_constexpr_computation();
    test_sfinae_and_traits();
    test_crtp();
    test_policy_design();
    test_variadic_templates();
    test_expression_templates();
    test_state_machine();
    test_type_erasure();
    test_string_constants();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}

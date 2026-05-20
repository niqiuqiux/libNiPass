/**
 * NiPass 注解驱动子选项测试
 *
 * 方式二：通过 -fpass-plugin 加载插件，使用 __attribute__((annotate(...))) 逐函数控制
 * 测试所有子配置选项的注解形式：
 *   - enstrenc + enstrcry_prob=N
 *   - enstrenc + enstrcry_subxor_prob=N
 *   - enstrenc + noenstrcry_cleanup
 *   - enfla (注解开启平坦化)
 *   - eibr + noeibr_use_stack
 *   - 混合注解：同时开启多个 pass
 *   - noenstrenc 强制关闭
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define _noinline __attribute__((noinline))

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
 * 1. enstrenc + enstrcry_prob=50
 * ======================================================================== */

__attribute__((annotate("enstrenc"), annotate("enstrcry_prob=50")))
_noinline static const char *func_strenc_prob50(void) {
    static const char *secret = "prob50_secret_key_nipass_2024";
    static const char *token  = "prob50_token_abc123xyz789";
    /* 50% 概率加密，部分字符串可能未加密，但运行时值必须正确 */
    if (strlen(secret) < 10 || strlen(token) < 10)
        return NULL;
    return secret;
}

/* ========================================================================
 * 2. enstrenc + enstrcry_subxor_prob=100
 * ======================================================================== */

__attribute__((annotate("enstrenc"), annotate("enstrcry_subxor_prob=100")))
_noinline static const char *func_strenc_subxor100(void) {
    static const char *api_key = "subxor100_sk_live_9f8E3kLm2Xp7Qr4T";
    static const char *db_url  = "subxor100_postgresql://admin:pass@db.internal:5432";
    if (strlen(api_key) < 10 || strlen(db_url) < 10)
        return NULL;
    return api_key;
}

/* ========================================================================
 * 3. enstrenc + noenstrcry_cleanup (不清理解密空间)
 * ======================================================================== */

__attribute__((annotate("enstrenc"), annotate("noenstrcry_cleanup")))
_noinline static const char *func_strenc_no_cleanup(void) {
    static const char *hmac_salt = "noclean_NiPass::HMAC::Salt::2024";
    static const char *jwt_key   = "noclean_HS256::jwt-secret-key-do-not-leak";
    if (strlen(hmac_salt) < 10 || strlen(jwt_key) < 10)
        return NULL;
    return hmac_salt;
}

/* ========================================================================
 * 4. enfla (注解开启平坦化)
 * ======================================================================== */

__attribute__((annotate("enfla")))
_noinline static int func_flatten(int x, int y) {
    int result = 0;
    if (x > 100) {
        if (y > 50) result = x + y;
        else result = x - y;
    } else if (x > 50) {
        switch (y % 4) {
            case 0: result = x * 2; break;
            case 1: result = y * 3; break;
            case 2: result = x + y + 10; break;
            default: result = x ^ y; break;
        }
    } else if (x > 0) {
        for (int i = 0; i < x % 5; i++)
            result += y + i;
    } else {
        result = -x * y;
    }
    return result;
}

/* ========================================================================
 * 5. eibr + noeibr_use_stack (不使用栈模式)
 * ======================================================================== */

typedef int (*op_func)(int, int);

_noinline static int op_add(int a, int b) { return a + b; }
_noinline static int op_sub(int a, int b) { return a - b; }
_noinline static int op_mul(int a, int b) { return a * b; }

__attribute__((annotate("eibr"), annotate("noeibr_use_stack")))
_noinline static int func_eibr_no_stack(int choice, int a, int b) {
    op_func ops[] = {op_add, op_sub, op_mul};
    if (choice < 0 || choice > 2) choice = 0;
    int r1 = ops[choice](a, b);

    if (a > b) {
        return r1 + ops[0](a, b);
    } else if (a < b) {
        return r1 + ops[1](a, b);
    } else {
        return r1 + ops[2](a, b);
    }
}

/* ========================================================================
 * 6. 混合注解：enstrenc + enfla 同时开启
 * ======================================================================== */

__attribute__((annotate("enstrenc"), annotate("enfla"), annotate("enstrcry_prob=80")))
_noinline static int func_mixed(int x) {
    const char *magic = "mixed_mode_secret_NiPass_2024!";
    int len = (int)strlen(magic);

    int result = 0;
    if (x > len) {
        result = x - len;
    } else if (x > 0) {
        for (int i = 0; i < x; i++)
            result += magic[i % len];
    } else {
        result = len * (-x);
    }
    return result;
}

/* ========================================================================
 * 7. noenstrenc 强制关闭（验证注解可以禁用 pass）
 * ======================================================================== */

__attribute__((annotate("noenstrenc")))
_noinline static const char *func_no_strenc(void) {
    /* 此函数即使全局开启 enstrenc 也不应被加密 */
    static const char *visible = "this_string_should_remain_visible";
    return visible;
}

/* ========================================================================
 * 8. eibr + eibr_use_stack (使用栈模式，默认行为)
 * ======================================================================== */

__attribute__((annotate("eibr"), annotate("eibr_use_stack")))
_noinline static int func_eibr_with_stack(int choice, int a, int b) {
    op_func ops[] = {op_add, op_sub, op_mul};
    if (choice < 0 || choice > 2) choice = 0;
    int r1 = ops[choice](a, b);

    if (a > b) {
        return r1 * 2;
    } else {
        return r1 + 1;
    }
}

/* ========================================================================
 * 测试用例
 * ======================================================================== */

_noinline static void test_strenc_prob50(void) {
    printf("[TEST] enstrenc + enstrcry_prob=50\n");
    const char *r = func_strenc_prob50();
    TEST_ASSERT(r != NULL, "prob50 returned non-null");
    TEST_ASSERT(strcmp(r, "prob50_secret_key_nipass_2024") == 0, "prob50 value correct");
}

_noinline static void test_strenc_subxor100(void) {
    printf("[TEST] enstrenc + enstrcry_subxor_prob=100\n");
    const char *r = func_strenc_subxor100();
    TEST_ASSERT(r != NULL, "subxor100 returned non-null");
    TEST_ASSERT(strcmp(r, "subxor100_sk_live_9f8E3kLm2Xp7Qr4T") == 0, "subxor100 value correct");
}

_noinline static void test_strenc_no_cleanup(void) {
    printf("[TEST] enstrenc + noenstrcry_cleanup\n");
    const char *r = func_strenc_no_cleanup();
    TEST_ASSERT(r != NULL, "no_cleanup returned non-null");
    TEST_ASSERT(strcmp(r, "noclean_NiPass::HMAC::Salt::2024") == 0, "no_cleanup value correct");
}

_noinline static void test_flatten(void) {
    printf("[TEST] enfla (annotate)\n");
    TEST_ASSERT(func_flatten(150, 60) == 210, "flatten: 150+60=210");
    TEST_ASSERT(func_flatten(150, 30) == 120, "flatten: 150-30=120");
    TEST_ASSERT(func_flatten(75, 4) == 150, "flatten: 75*2=150 (y%4==0)");
    TEST_ASSERT(func_flatten(75, 5) == 15, "flatten: 5*3=15 (y%4==1)");
    TEST_ASSERT(func_flatten(75, 6) == 91, "flatten: 75+6+10=91 (y%4==2)");
    TEST_ASSERT(func_flatten(30, 10) == 0, "flatten: loop 0 iters");
    TEST_ASSERT(func_flatten(-3, 7) == 21, "flatten: -(-3)*7=21");
}

_noinline static void test_eibr_no_stack(void) {
    printf("[TEST] eibr + noeibr_use_stack\n");
    TEST_ASSERT(func_eibr_no_stack(0, 10, 5) == 30, "eibr_no_stack: add(10,5)+add(10,5)=30");
    TEST_ASSERT(func_eibr_no_stack(1, 3, 7) == -8, "eibr_no_stack: sub(3,7)+sub(3,7)=-8");
    TEST_ASSERT(func_eibr_no_stack(2, 4, 4) == 32, "eibr_no_stack: mul(4,4)+mul(4,4)=32");
}

_noinline static void test_mixed(void) {
    printf("[TEST] enstrenc + enfla mixed\n");
    int r1 = func_mixed(100);
    TEST_ASSERT(r1 == 70, "mixed: 100-30=70");
    int r2 = func_mixed(0);
    TEST_ASSERT(r2 == 0, "mixed: 30*0=0");
    int r3 = func_mixed(-2);
    TEST_ASSERT(r3 == 60, "mixed: 30*2=60");
}

_noinline static void test_no_strenc(void) {
    printf("[TEST] noenstrenc (force disable)\n");
    const char *r = func_no_strenc();
    TEST_ASSERT(r != NULL, "no_strenc returned non-null");
    TEST_ASSERT(strcmp(r, "this_string_should_remain_visible") == 0, "no_strenc value correct");
}

_noinline static void test_eibr_with_stack(void) {
    printf("[TEST] eibr + eibr_use_stack\n");
    TEST_ASSERT(func_eibr_with_stack(0, 10, 5) == 30, "eibr_stack: add(10,5)*2=30");
    TEST_ASSERT(func_eibr_with_stack(1, 3, 7) == -3, "eibr_stack: sub(3,7)+1=-3");
    TEST_ASSERT(func_eibr_with_stack(2, 4, 4) == 17, "eibr_stack: mul(4,4)+1=17");
}

/* ========================================================================
 * main
 * ======================================================================== */

_noinline int main(void) {
    printf("========================================\n");
    printf("  NiPass Annotate Sub-Options Test\n");
    printf("========================================\n\n");

    test_strenc_prob50();
    test_strenc_subxor100();
    test_strenc_no_cleanup();
    test_flatten();
    test_eibr_no_stack();
    test_mixed();
    test_no_strenc();
    test_eibr_with_stack();

    printf("\n========================================\n");
    printf("  Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
        printf(", %d FAILED", g_tests_failed);
    printf("\n========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}

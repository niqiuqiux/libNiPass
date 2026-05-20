#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define _noinline __attribute__((noinline))

// 测试字符串加密
const char *secret_key = "NiPass_Secret_Key_2024";
const char *api_url = "https://api.example.com/v1/auth";

// 测试常量加密
static int magic_number = 0xDEADBEEF;
static int lookup_table[] = {10, 20, 30, 40, 50, 60, 70, 80};

// 简单函数 - 测试基本混淆
_noinline int add(int a, int b) {
    return a + b;
}

_noinline int sub(int a, int b) {
    return a - b;
}

// 带分支的函数 - 测试控制流平坦化
_noinline int classify(int x) {
    if (x > 100) {
        return 3;
    } else if (x > 50) {
        return 2;
    } else if (x > 0) {
        return 1;
    } else {
        return 0;
    }
}

// switch 语句 - 测试平坦化
_noinline const char *day_name(int day) {
    switch (day) {
        case 1: return "Monday";
        case 2: return "Tuesday";
        case 3: return "Wednesday";
        case 4: return "Thursday";
        case 5: return "Friday";
        case 6: return "Saturday";
        case 7: return "Sunday";
        default: return "Unknown";
    }
}

// 循环 - 测试 MBA / 替换
_noinline int sum_array(int *arr, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i];
    }
    return total;
}

// 间接调用测试
typedef int (*op_func)(int, int);

_noinline int dispatch(op_func fn, int a, int b) {
    return fn(a, b);
}

// 复杂控制流 - 测试 BCF + 平坦化组合
_noinline int complex_logic(int a, int b, int c) {
    int result = 0;
    if (a > b) {
        if (b > c) {
            result = a + b + c;
        } else {
            result = a * 2 - c;
        }
    } else {
        if (a > c) {
            result = b - a + c;
        } else {
            result = c * 3;
        }
    }
    for (int i = 0; i < result % 10; i++) {
        result ^= (i * 7 + 3);
    }
    return result;
}

// 字符串操作 - 测试字符串加密效果
_noinline int check_password(const char *input) {
    if (strcmp(input, "p@ssw0rd_123!") == 0) {
        printf("Access granted: %s\n", secret_key);
        return 1;
    }
    printf("Access denied. Try again.\n");
    return 0;
}

_noinline int main(int argc, char *argv[]) {
    printf("=== NiPass ARM64 Test ===\n");
    printf("API: %s\n", api_url);
    printf("Magic: 0x%X\n", magic_number);

    printf("\nadd(3, 5) = %d\n", add(3, 5));
    printf("sub(10, 4) = %d\n", sub(10, 4));
    printf("classify(75) = %d\n", classify(75));
    printf("day_name(3) = %s\n", day_name(3));

    int arr[] = {1, 2, 3, 4, 5};
    printf("sum_array = %d\n", sum_array(arr, 5));

    printf("dispatch(add, 7, 8) = %d\n", dispatch(add, 7, 8));
    printf("complex_logic(10, 5, 3) = %d\n", complex_logic(10, 5, 3));

    check_password(argc > 1 ? argv[1] : "wrong");

    printf("\nLookup table: ");
    for (int i = 0; i < 8; i++) {
        printf("%d ", lookup_table[i]);
    }
    printf("\n");

    return 0;
}

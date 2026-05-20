#!/bin/bash
# NiPass ARM64 测试编译脚本
# 基于 CMake + NDK 工具链交叉编译
#
# 用法:
#   ./build.sh              # 带混淆编译
#   ./build.sh plain        # 不带混淆编译（对照组）
#   ./build.sh both         # 同时编译两个版本并对比
#   ./build.sh clean        # 清理构建目录

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PASS_LIB="${NIPASS_LIB:-${PROJECT_ROOT}/lib/libNiPass-19.0.0.so}"
NIPASS_PASSES="${NIPASS_PASSES:--enfla}"

BUILD_OBF="${SCRIPT_DIR}/build_obf"
BUILD_PLAIN="${SCRIPT_DIR}/build_plain"

MODE="${1:-obf}"

# 所有测试二进制名
TARGETS="test_nipass test_annotate test_production test_stl test_template"

do_build() {
    local build_dir="$1"
    local enable_obf="$2"
    local label="$3"

    echo ""
    echo "========================================"
    echo "  Building: ${label}"
    echo "  Output:   ${build_dir}"
    echo "========================================"

    cmake -S "$SCRIPT_DIR" -B "$build_dir" \
        -DENABLE_OBFUSCATION="${enable_obf}" \
        -DNIPASS_LIB="${PASS_LIB}" \
        -DNIPASS_PASSES="${NIPASS_PASSES}" 2>&1

    cmake --build "$build_dir" -- -j$(nproc) 2>&1

    echo "  Done."
}

do_compare() {
    local plain_bin="${BUILD_PLAIN}/../bin/test_nipass"
    local obf_bin="${BUILD_OBF}/../bin/test_nipass"

    # 因为 CMAKE_RUNTIME_OUTPUT_DIRECTORY 是 ${CMAKE_SOURCE_DIR}/bin
    # 两次构建会覆盖同一个 bin 目录，所以需要分别拷贝
    # 先编译 plain，拷贝出来，再编译 obf
    echo ""
    echo "========================================"
    echo "  Comparison"
    echo "========================================"

    local bin_dir="${SCRIPT_DIR}/bin"
    for t in $TARGETS; do
        if [ -f "${bin_dir}/${t}_plain" ] && [ -f "${bin_dir}/${t}_obf" ]; then
            echo ""
            echo "--- ${t} ---"
            local plain_size=$(stat -c%s "${bin_dir}/${t}_plain" 2>/dev/null)
            local obf_size=$(stat -c%s "${bin_dir}/${t}_obf" 2>/dev/null)
            echo "  Plain:      ${plain_size} bytes"
            echo "  Obfuscated: ${obf_size} bytes"
            file "${bin_dir}/${t}_obf"
        fi
    done

    echo ""
    echo "--- String visibility (test_nipass) ---"
    if [ -f "${bin_dir}/test_nipass_plain" ]; then
        echo "Plain:"
        strings "${bin_dir}/test_nipass_plain" | grep -E "(p@ssw0rd|Secret_Key|api\.example)" || echo "  (none)"
    fi
    if [ -f "${bin_dir}/test_nipass_obf" ]; then
        echo "Obfuscated:"
        strings "${bin_dir}/test_nipass_obf" | grep -E "(p@ssw0rd|Secret_Key|api\.example)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_production) ---"
    if [ -f "${bin_dir}/test_production_plain" ]; then
        echo "Plain:"
        strings "${bin_dir}/test_production_plain" | grep -E "(sk_live_|nipass\.dev|HMAC::Salt|AES)" || echo "  (none)"
    fi
    if [ -f "${bin_dir}/test_production_obf" ]; then
        echo "Obfuscated:"
        strings "${bin_dir}/test_production_obf" | grep -E "(sk_live_|nipass\.dev|HMAC::Salt|AES)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_stl) ---"
    if [ -f "${bin_dir}/test_stl_plain" ]; then
        echo "Plain:"
        strings "${bin_dir}/test_stl_plain" | grep -E "(postgresql://|redis://|jwt-secret|nipass\.internal)" || echo "  (none)"
    fi
    if [ -f "${bin_dir}/test_stl_obf" ]; then
        echo "Obfuscated:"
        strings "${bin_dir}/test_stl_obf" | grep -E "(postgresql://|redis://|jwt-secret|nipass\.internal)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_template) ---"
    if [ -f "${bin_dir}/test_template_plain" ]; then
        echo "Plain:"
        strings "${bin_dir}/test_template_plain" | grep -E "(PRIVATE KEY|nipass_oauth|nipass\.dev|telemetry)" || echo "  (none)"
    fi
    if [ -f "${bin_dir}/test_template_obf" ]; then
        echo "Obfuscated:"
        strings "${bin_dir}/test_template_obf" | grep -E "(PRIVATE KEY|nipass_oauth|nipass\.dev|telemetry)" || echo "  (none - encrypted)"
    fi
}

case "$MODE" in
    obf)
        do_build "$BUILD_OBF" ON "WITH obfuscation"
        ;;
    plain)
        do_build "$BUILD_PLAIN" OFF "WITHOUT obfuscation (baseline)"
        ;;
    both)
        # 先编译 plain
        do_build "$BUILD_PLAIN" OFF "WITHOUT obfuscation (baseline)"
        for t in $TARGETS; do
            cp "${SCRIPT_DIR}/bin/${t}" "${SCRIPT_DIR}/bin/${t}_plain"
        done

        # 再编译 obf
        do_build "$BUILD_OBF" ON "WITH obfuscation"
        for t in $TARGETS; do
            cp "${SCRIPT_DIR}/bin/${t}" "${SCRIPT_DIR}/bin/${t}_obf"
        done

        do_compare
        ;;
    clean)
        echo "Cleaning build directories..."
        rm -rf "$BUILD_OBF" "$BUILD_PLAIN" "${SCRIPT_DIR}/bin"
        echo "Done."
        ;;
    *)
        echo "Usage: $0 [obf|plain|both|clean]"
        exit 1
        ;;
esac

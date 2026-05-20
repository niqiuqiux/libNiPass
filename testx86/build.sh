#!/bin/bash
# NiPass x86_64 local test build script.
#
# Usage:
#   ./build.sh              # build obfuscated binaries
#   ./build.sh plain        # build baseline binaries
#   ./build.sh both         # build both and compare basic properties
#   ./build.sh clean        # remove build outputs

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLANG="${CLANG:-$(command -v clang-19 || command -v clang)}"
CLANGXX="${CLANGXX:-$(command -v clang++-19 || command -v clang++)}"
if [ -z "${NIPASS_LIB:-}" ]; then
    PASS_LIB="$(ls -1 "${PROJECT_ROOT}"/lib/libNiPass-*.so 2>/dev/null | sort -V | tail -n 1)"
else
    PASS_LIB="${NIPASS_LIB}"
fi

BUILD_OBF="${SCRIPT_DIR}/build_obf"
BUILD_PLAIN="${SCRIPT_DIR}/build_plain"
BIN_DIR="${SCRIPT_DIR}/bin"
NIPASS_PASSES="${NIPASS_PASSES:--enfla}"

MODE="${1:-obf}"
TARGETS="test_nipass test_annotate test_production test_stl test_template"

do_build() {
    local build_dir="$1"
    local enable_obf="$2"
    local label="$3"

    echo ""
    echo "========================================"
    echo "  Building x86: ${label}"
    echo "  Output:       ${build_dir}"
    echo "========================================"

    cmake -S "$SCRIPT_DIR" -B "$build_dir" \
        -DENABLE_OBFUSCATION="${enable_obf}" \
        -DNIPASS_LIB="${PASS_LIB}" \
        -DNIPASS_PASSES="${NIPASS_PASSES}" \
        -DCMAKE_C_COMPILER="${CLANG}" \
        -DCMAKE_CXX_COMPILER="${CLANGXX}" \
        -DCMAKE_BUILD_TYPE=Release

    cmake --build "$build_dir" -- -j"$(nproc)"

    echo "  Done."
}

do_compare() {
    echo ""
    echo "========================================"
    echo "  Comparison"
    echo "========================================"

    for t in $TARGETS; do
        if [ -f "${BIN_DIR}/${t}_plain" ] && [ -f "${BIN_DIR}/${t}_obf" ]; then
            echo ""
            echo "--- ${t} ---"
            echo "  Plain:      $(stat -c%s "${BIN_DIR}/${t}_plain") bytes"
            echo "  Obfuscated: $(stat -c%s "${BIN_DIR}/${t}_obf") bytes"
            file "${BIN_DIR}/${t}_obf"
        fi
    done

    echo ""
    echo "--- String visibility (test_nipass) ---"
    if [ -f "${BIN_DIR}/test_nipass_plain" ]; then
        echo "Plain:"
        strings "${BIN_DIR}/test_nipass_plain" | grep -E "(p@ssw0rd|Secret_Key|api\.example)" || echo "  (none)"
    fi
    if [ -f "${BIN_DIR}/test_nipass_obf" ]; then
        echo "Obfuscated:"
        strings "${BIN_DIR}/test_nipass_obf" | grep -E "(p@ssw0rd|Secret_Key|api\.example)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_production) ---"
    if [ -f "${BIN_DIR}/test_production_plain" ]; then
        echo "Plain:"
        strings "${BIN_DIR}/test_production_plain" | grep -E "(sk_live_|nipass\.dev|HMAC::Salt|AES)" || echo "  (none)"
    fi
    if [ -f "${BIN_DIR}/test_production_obf" ]; then
        echo "Obfuscated:"
        strings "${BIN_DIR}/test_production_obf" | grep -E "(sk_live_|nipass\.dev|HMAC::Salt|AES)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_stl) ---"
    if [ -f "${BIN_DIR}/test_stl_plain" ]; then
        echo "Plain:"
        strings "${BIN_DIR}/test_stl_plain" | grep -E "(postgresql://|redis://|jwt-secret|nipass\.internal)" || echo "  (none)"
    fi
    if [ -f "${BIN_DIR}/test_stl_obf" ]; then
        echo "Obfuscated:"
        strings "${BIN_DIR}/test_stl_obf" | grep -E "(postgresql://|redis://|jwt-secret|nipass\.internal)" || echo "  (none - encrypted)"
    fi

    echo ""
    echo "--- String visibility (test_template) ---"
    if [ -f "${BIN_DIR}/test_template_plain" ]; then
        echo "Plain:"
        strings "${BIN_DIR}/test_template_plain" | grep -E "(PRIVATE KEY|nipass_oauth|nipass\.dev|telemetry)" || echo "  (none)"
    fi
    if [ -f "${BIN_DIR}/test_template_obf" ]; then
        echo "Obfuscated:"
        strings "${BIN_DIR}/test_template_obf" | grep -E "(PRIVATE KEY|nipass_oauth|nipass\.dev|telemetry)" || echo "  (none - encrypted)"
    fi
}

case "$MODE" in
    obf)
        do_build "$BUILD_OBF" ON "WITH obfuscation"
        ;;
    plain)
        do_build "$BUILD_PLAIN" OFF "WITHOUT obfuscation"
        ;;
    both)
        do_build "$BUILD_PLAIN" OFF "WITHOUT obfuscation"
        for t in $TARGETS; do
            cp "${BIN_DIR}/${t}" "${BIN_DIR}/${t}_plain"
        done

        do_build "$BUILD_OBF" ON "WITH obfuscation"
        for t in $TARGETS; do
            cp "${BIN_DIR}/${t}" "${BIN_DIR}/${t}_obf"
        done

        do_compare
        ;;
    clean)
        echo "Cleaning x86 build outputs..."
        rm -rf "$BUILD_OBF" "$BUILD_PLAIN" "$BIN_DIR"
        echo "Done."
        ;;
    *)
        echo "Usage: $0 [obf|plain|both|clean]"
        exit 1
        ;;
esac

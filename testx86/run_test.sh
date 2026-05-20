#!/bin/bash
# NiPass x86_64 local test runner.
#
# Usage:
#   ./run_test.sh              # run obfuscated binaries from bin/
#   ./run_test.sh plain        # run baseline binaries from bin/
#   ./run_test.sh both         # run *_plain and *_obf binaries
#   ./run_test.sh -t 5 both    # set per-binary timeout in seconds

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
TIMEOUT="${TIMEOUT_SECONDS:-10}"
TARGETS="test_nipass test_annotate test_production test_stl test_template"

MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            MODE="$1"
            shift
            ;;
    esac
done
MODE="${MODE:-obf}"

if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -le 0 ]; then
    echo "[ERROR] Timeout must be a positive integer, got: ${TIMEOUT}"
    exit 1
fi

run_local() {
    local local_bin="$1"
    local label="$2"
    local output_file
    output_file="$(mktemp)"

    if [ ! -f "$local_bin" ]; then
        echo "[ERROR] Binary not found: $local_bin"
        echo "  Run './build.sh ${MODE}' first."
        rm -f "$output_file"
        return 1
    fi

    echo ""
    echo "----------------------------------------"
    echo "  ${label}"
    echo "----------------------------------------"
    echo "  Running (timeout=${TIMEOUT}s)..."
    echo ""

    local exit_code=0
    timeout "${TIMEOUT}" "$local_bin" >"$output_file" 2>&1 || exit_code=$?
    cat "$output_file"

    echo ""
    if [ "$exit_code" -eq 124 ]; then
        echo "  [TIMEOUT] Process killed after ${TIMEOUT}s - possible infinite loop!"
        rm -f "$output_file"
        return 1
    elif [ "$exit_code" -ne 0 ]; then
        echo "  [FAIL] Exit code: ${exit_code}"
        rm -f "$output_file"
        return 1
    elif [ "$(basename "$local_bin" | sed 's/^\(test_nipass\).*/\1/')" = "test_nipass" ] &&
         ! grep -q "day_name(3) = Wednesday" "$output_file"; then
        echo "  [FAIL] Missing expected output: day_name(3) = Wednesday"
        rm -f "$output_file"
        return 1
    else
        echo "  [PASS] Exit code: 0"
    fi
    rm -f "$output_file"
    return 0
}

run_targets() {
    local suffix="$1"
    local label_suffix="$2"

    for t in $TARGETS; do
        if run_local "${BIN_DIR}/${t}${suffix}" "${t} (${label_suffix})"; then
            PASSED=$((PASSED + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    done
}

print_summary() {
    echo ""
    echo "========================================"
    echo "  Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
    echo "========================================"

    if [ "$FAILED" -gt 0 ]; then
        return 1
    fi
}

echo "========================================"
echo "  NiPass x86_64 Local Test"
echo "========================================"
echo "  Timeout: ${TIMEOUT}s per binary"

TOTAL=0
PASSED=0
FAILED=0

case "$MODE" in
    obf)
        TOTAL=5
        run_targets "" "obfuscated"
        ;;
    plain)
        TOTAL=5
        run_targets "" "plain"
        ;;
    both)
        TOTAL=10
        for t in $TARGETS; do
            if [ ! -f "${BIN_DIR}/${t}_plain" ] || [ ! -f "${BIN_DIR}/${t}_obf" ]; then
                echo ""
                echo "[ERROR] Missing ${t}_plain or ${t}_obf. Run './build.sh both' first."
                exit 1
            fi
        done
        run_targets "_plain" "plain"
        run_targets "_obf" "obfuscated"
        ;;
    *)
        echo "Usage: $0 [-t seconds] [obf|plain|both]"
        exit 1
        ;;
esac

print_summary

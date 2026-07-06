#!/usr/bin/env bash
# Build and/or run the Mimic browser (WASM) file scanner.
# Usage:
#   ./build-and-run.sh              # build (dev) then run (default)
#   ./build-and-run.sh --release    # build in release mode then run
#   ./build-and-run.sh --build      # only build
#   ./build-and-run.sh --build --release  # only build in release mode
#   ./build-and-run.sh --run        # only run (assumes already built)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PORT="${MIMIC_BROWSER_PORT:-8765}"

RELEASE=""
for arg in "$@"; do
    if [[ "$arg" == "--release" || "$arg" == "-r" ]]; then
        RELEASE="--release"
        break
    fi
done

build() {
    if ! command -v wasm-pack &>/dev/null; then
        echo "error: wasm-pack not found. Install from https://rustwasm.github.io/wasm-pack/installer/" >&2
        exit 1
    fi
    if [[ -n "$RELEASE" ]]; then
        echo "[*] Building WASM (mimic-browser) in release mode..."
    else
        echo "[*] Building WASM (mimic-browser)..."
    fi
    wasm-pack build --target web --out-dir www/pkg $RELEASE
    echo "[*] Build complete. Output: www/pkg/"

    if [[ -n "$RELEASE" ]]; then
        echo "[*] Building WASM (mimic-view) in release mode..."
    else
        echo "[*] Building WASM (mimic-view)..."
    fi
    wasm-pack build --target web --out-dir "$SCRIPT_DIR/www/view-pkg" $RELEASE "$SCRIPT_DIR/../mimic-view"
    echo "[*] Build complete. Output: www/view-pkg/"
}

run_server() {
    if [[ ! -d www/pkg ]] || [[ ! -f www/pkg/mimic_browser_bg.wasm ]]; then
        echo "error: WASM not built. Run with --build first or run without --run-only." >&2
        exit 1
    fi
    echo "[*] Serving browser UI at http://localhost:${PORT}/"
    echo "[*] Open the URL in your browser. Stop with Ctrl+C."
    if command -v python3 &>/dev/null; then
        exec python3 -m http.server "$PORT" --directory www
    elif command -v python &>/dev/null; then
        exec python -m http.server "$PORT" --directory www
    else
        echo "error: python3 or python not found." >&2
        exit 1
    fi
}

MODE=""
for arg in "$@"; do
    if [[ "$arg" == "--build" ]]; then MODE="build"; fi
    if [[ "$arg" == "--run" ]]; then MODE="run"; fi
done

case "$MODE" in
    build)
        build
        ;;
    run)
        run_server
        ;;
    *)
        build
        run_server
        ;;
esac

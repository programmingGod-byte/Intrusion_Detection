#!/usr/bin/env bash
set -e

# Always run from the project root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BUILD_TYPE="Debug"

# Parse optional arguments
for arg in "$@"; do
  case $arg in
    --release|-r)
      BUILD_TYPE="Release"
      ;;
    --clean|-c)
      echo "🧹 Cleaning build directory..."
      rm -rf build
      ;;
    --help|-h)
      echo "Usage: ./build.sh [options]"
      echo "Options:"
      echo "  --release, -r    Build with Release mode (-O3)"
      echo "  --clean,   -c    Remove build directory before building"
      echo "  --help,    -h    Show this help message"
      exit 0
      ;;
  esac
done

echo "🔧 Configuring project (${BUILD_TYPE})..."
cmake -B build -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

echo "🚀 Compiling with all available cores..."
cmake --build build -j

echo "✅ Build completed successfully!"
echo "   - Library:       build/aethon/libaethon_lib.a"
echo "   - Benchmark:     build/benchmarks/aethon_benchmark"
echo "   - AF_XDP Engine: build/src/afxdp_control"


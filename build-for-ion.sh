#!/bin/bash
# Build BSL with ION memory allocators
set -e

# Detect ION installation
ION_ROOT="${ION_ROOT:-$(cd ../../ && pwd)}"
echo "Using ION_ROOT: $ION_ROOT"

# Clean previous build
./build.sh clean

# Rebuild all dependencies
./build.sh deps

# Prepare with ION integration enabled
./build.sh prep \
    -DION_INTEGRATION=ON \
    -DION_ROOT="$ION_ROOT" \
    -DBUILD_TESTING=OFF

# Build
./build.sh

# Install to testroot
./build.sh install

echo "BSL built successfully with ION memory allocators"
echo "Libraries installed to: $(pwd)/testroot/usr/lib"

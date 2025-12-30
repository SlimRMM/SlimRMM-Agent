#!/bin/bash
#
# SlimRMM Agent - Linux Build Script (Docker-based)
# Copyright (c) 2025 Kiefer Networks
#
# This script uses Docker to build DEB and RPM packages
# Works on any system with Docker installed (macOS, Linux, Windows)
#

set -e

# Configuration
VERSION="${1:-1.0.0}"
BUILD_TYPE="${2:-all}"  # all, deb, rpm
ARCH_DEB="${3:-amd64}"
ARCH_RPM="${4:-x86_64}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="slimrmm-agent-builder"
CONTAINER_NAME="slimrmm-build-$$"

echo "================================================"
echo "  SlimRMM Agent - Linux Builder (Docker)"
echo "  Version: ${VERSION}"
echo "  Build Type: ${BUILD_TYPE}"
echo "================================================"
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo ""
    echo "Please install Docker:"
    echo "  - macOS: https://docs.docker.com/desktop/mac/install/"
    echo "  - Linux: https://docs.docker.com/engine/install/"
    echo ""
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo "ERROR: Docker daemon is not running"
    echo "Please start Docker and try again."
    exit 1
fi

# Create dist directory
mkdir -p "${SCRIPT_DIR}/dist"

# Build the Docker image
echo "[1/4] Building Docker image..."
docker build \
    -t "${IMAGE_NAME}" \
    -f "${SCRIPT_DIR}/Dockerfile.build" \
    --target builder \
    "${SCRIPT_DIR}"

echo ""
echo "[2/4] Starting build container..."

# Function to build DEB package
build_deb() {
    echo ""
    echo "Building DEB package (${ARCH_DEB})..."

    docker run --rm \
        --name "${CONTAINER_NAME}-deb" \
        -v "${SCRIPT_DIR}/dist:/output" \
        -e VERSION="${VERSION}" \
        -e ARCH="${ARCH_DEB}" \
        "${IMAGE_NAME}" \
        bash -c "./build-linux-deb.sh ${VERSION} ${ARCH_DEB} && cp dist/*.deb /output/"

    echo "DEB package built successfully!"
}

# Function to build RPM package
build_rpm() {
    echo ""
    echo "Building RPM package (${ARCH_RPM})..."

    docker run --rm \
        --name "${CONTAINER_NAME}-rpm" \
        -v "${SCRIPT_DIR}/dist:/output" \
        -e VERSION="${VERSION}" \
        -e ARCH="${ARCH_RPM}" \
        "${IMAGE_NAME}" \
        bash -c "./build-linux-rpm.sh ${VERSION} ${ARCH_RPM} && cp dist/*.rpm /output/"

    echo "RPM package built successfully!"
}

# Execute builds based on type
case "${BUILD_TYPE}" in
    deb)
        build_deb
        ;;
    rpm)
        build_rpm
        ;;
    all)
        build_deb
        build_rpm
        ;;
    *)
        echo "Unknown build type: ${BUILD_TYPE}"
        echo "Usage: $0 [version] [all|deb|rpm] [deb-arch] [rpm-arch]"
        exit 1
        ;;
esac

echo ""
echo "[3/4] Build complete!"
echo ""

# List built packages
echo "[4/4] Built packages:"
echo "================================================"
ls -lah "${SCRIPT_DIR}/dist/"*.deb "${SCRIPT_DIR}/dist/"*.rpm 2>/dev/null || echo "No packages found"
echo "================================================"
echo ""
echo "Packages are in: ${SCRIPT_DIR}/dist/"
echo ""
echo "Installation commands:"
echo ""
echo "  DEB (Debian/Ubuntu):"
echo "    sudo dpkg -i dist/slimrmm-agent_${VERSION}_${ARCH_DEB}.deb"
echo ""
echo "  RPM (RHEL/Fedora):"
echo "    sudo rpm -i dist/slimrmm-agent-${VERSION}-1.${ARCH_RPM}.rpm"
echo ""
echo "  Silent installation (both):"
echo "    SLIMRMM_SERVER=\"https://...\" SLIMRMM_KEY=\"...\" sudo dpkg -i ..."
echo ""

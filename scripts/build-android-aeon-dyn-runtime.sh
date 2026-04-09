#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="aarch64-linux-android"
API_LEVEL="${ANDROID_API_LEVEL:-24}"
NDK_DIR="${ANDROID_NDK_ROOT:-${NDK_ROOT:-${NDKROOT:-}}}"
HOST_TAG="linux-x86_64"

if [[ -z "${NDK_DIR}" ]]; then
  echo "missing Android NDK path: set ANDROID_NDK_ROOT, NDK_ROOT, or NDKROOT" >&2
  exit 1
fi

TOOLCHAIN_BIN="${NDK_DIR}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
LINKER="${TOOLCHAIN_BIN}/aarch64-linux-android${API_LEVEL}-clang"
AR="${TOOLCHAIN_BIN}/llvm-ar"
SYSROOT="${NDK_DIR}/toolchains/llvm/prebuilt/${HOST_TAG}/sysroot"
CLANG_TARGET="aarch64-linux-android${API_LEVEL}"
CLANG_ARGS="--target=${CLANG_TARGET} --sysroot=${SYSROOT} -D__ANDROID_API__=${API_LEVEL}"

if [[ ! -x "${LINKER}" ]]; then
  echo "missing Android linker: ${LINKER}" >&2
  exit 1
fi

if ! rustup target list --installed | grep -qx "${TARGET}"; then
  rustup target add "${TARGET}"
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${LINKER}"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="${AR}"
export CC_aarch64_linux_android="${LINKER}"
export AR_aarch64_linux_android="${AR}"
export CFLAGS_aarch64_linux_android="${CLANG_ARGS}"
export BINDGEN_EXTRA_CLANG_ARGS="${CLANG_ARGS}"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="${CLANG_ARGS}"

cd "${ROOT_DIR}"
cargo build -p aeon-instrument --lib --target "${TARGET}" "$@"

echo "built: ${ROOT_DIR}/target/${TARGET}/debug/libaeon_instrument.so"

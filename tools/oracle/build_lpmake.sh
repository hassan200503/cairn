#!/usr/bin/env bash
# Build the official AOSP host `lpmake` from pinned source as a differential
# oracle (AGENTS.md rule 9). See tools/oracle/PINNED.md for the pins and the
# shim rationale. Output: "$build_dir/bin/lpmake".
#
# Usage: tools/oracle/build_lpmake.sh [aosp_root] [build_dir]
set -euo pipefail

AOSP_ROOT="${1:-${CAIRN_AOSP_ROOT:-$HOME/.cache/cairn-aosp-oracle}}"
BUILD_DIR="${2:-$(mktemp -d)}"
HERE="$(cd "$(dirname "$0")" && pwd)"

PINS=(
  "https://android.googlesource.com/platform/system/core a3b721a32242006b59cb12bd62c9133632af3a2d"
  "https://android.googlesource.com/platform/system/libbase 6d19b5c690fa4220c10e42c2326150bbd4d4b7bb"
  "https://android.googlesource.com/platform/system/logging bcac7c30d88a3773a7c0bc9f5617a23a886331fd"
  "https://android.googlesource.com/platform/system/extras fc2494a2abd7ab21774d03deb09c1362bbb0bba8"
  "https://github.com/madler/zlib.git a28e8d5acad59823917e4e556a87584a803ac15e"
  "https://github.com/fmtlib/fmt.git eda105459b7be42e72ec6337ccb388b098a2acbe"
)
FMT="eda105459b7be42e72ec6337ccb388b098a2acbe"

# Which subtrees of each pinned repo the build needs (keeps the clone light).
SPARSE_core="fs_mgr/liblp libsparse"
SPARSE_extras="partition_tools ext4_utils"

for pin in "${PINS[@]}"; do
  url="${pin%% *}"; sha="${pin##* }"
  name="$(basename "${url%.git}")"
  sparse_var="SPARSE_${name}"
  dir="$AOSP_ROOT/$sha"
  if [ ! -d "$dir/.git" ]; then
    git clone --filter=blob:none --no-checkout --depth 1 "$url" "$dir"
    git -C "$dir" sparse-checkout set ${!sparse_var:-.}
    git -C "$dir" checkout "$sha" 2>/dev/null || {
      git -C "$dir" fetch --depth 1 origin "$sha"
      git -C "$dir" checkout "$sha"
    }
  fi
done

mkdir -p "$BUILD_DIR/obj" "$BUILD_DIR/bin"

CXXINC="-I$HERE/openssl \
  -I$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/include \
  -I$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/libsparse/include \
  -I$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/libsparse \
  -I$AOSP_ROOT/a28e8d5acad59823917e4e556a87584a803ac15e \
  -I$AOSP_ROOT/6d19b5c690fa4220c10e42c2326150bbd4d4b7bb/include \
  -I$AOSP_ROOT/bcac7c30d88a3773a7c0bc9f5617a23a886331fd/liblog/include \
  -I$AOSP_ROOT/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/partition_tools \
  -I$AOSP_ROOT/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/ext4_utils/include \
  -I$AOSP_ROOT/eda105459b7be42e72ec6337ccb388b098a2acbe/include \
  -I$HERE"
CXXFLAGS="-std=c++20 -O1 -g0 -w -D_FILE_OFFSET_BITS=64 -DFMT_HEADER_ONLY -include $HERE/sha256_shim.h"

compile() { # compile <output.o> <source.cpp> [extra includes...]
  local out="$1"; shift
  g++ $CXXFLAGS $CXXINC -c "$@" -o "$out"
}

# liblp (the metadata model; the part we differential-test against)
compile "$BUILD_DIR/obj/builder.o"               "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/builder.cpp"
compile "$BUILD_DIR/obj/super_layout_builder.o" "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/super_layout_builder.cpp"
compile "$BUILD_DIR/obj/images.o"               "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/images.cpp"
compile "$BUILD_DIR/obj/partition_opener.o"     "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/partition_opener.cpp"
compile "$BUILD_DIR/obj/property_fetcher.o"     "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/property_fetcher.cpp"
compile "$BUILD_DIR/obj/reader.o"               "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/reader.cpp"
compile "$BUILD_DIR/obj/utility.o"              "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/utility.cpp"
compile "$BUILD_DIR/obj/writer.o"               "$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/writer.cpp"

# libbase (subset used by liblp/lpmake)
LB="$AOSP_ROOT/6d19b5c690fa4220c10e42c2326150bbd4d4b7bb"
compile "$BUILD_DIR/obj/base_file.o"          "$LB/file.cpp"
compile "$BUILD_DIR/obj/base_strings.o"       "$LB/strings.cpp"
compile "$BUILD_DIR/obj/base_stringprintf.o"  "$LB/stringprintf.cpp"
compile "$BUILD_DIR/obj/base_logging.o"       "$LB/logging.cpp"
compile "$BUILD_DIR/obj/base_errors_unix.o"   "$LB/errors_unix.cpp"
compile "$BUILD_DIR/obj/base_posix_strerror_r.o" "$LB/posix_strerror_r.cpp" "-U_GNU_SOURCE" "-D_POSIX_C_SOURCE=200112L"
compile "$BUILD_DIR/obj/base_threads.o"       "$LB/threads.cpp"
compile "$BUILD_DIR/obj/base_mapped_file.o"   "$LB/mapped_file.cpp"
compile "$BUILD_DIR/obj/base_properties.o"    "$LB/properties.cpp"
compile "$BUILD_DIR/obj/base_parsebool.o"     "$LB/parsebool.cpp"

# libsparse (sparse output support for lpmake --output-sparse)
LS="$AOSP_ROOT/a3b721a32242006b59cb12bd62c9133632af3a2d/libsparse"
compile "$BUILD_DIR/obj/sparse_backed_block.o" "$LS/backed_block.cpp"
compile "$BUILD_DIR/obj/sparse_output_file.o"  "$LS/output_file.cpp"
compile "$BUILD_DIR/obj/sparse_sparse.o"       "$LS/sparse.cpp"
compile "$BUILD_DIR/obj/sparse_crc32.o"        "$LS/sparse_crc32.cpp"
compile "$BUILD_DIR/obj/sparse_read.o"         "$LS/sparse_read.cpp"
compile "$BUILD_DIR/obj/sparse_err.o"          "$LS/sparse_err.cpp"

# zlib (pinned madler/zlib; used by libsparse output_file)
Z="$AOSP_ROOT/a28e8d5acad59823917e4e556a87584a803ac15e"
for zsrc in adler32 crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil compress; do
  cc -O1 -g0 -w -D_GNU_SOURCE -I"$Z" -c "$Z/$zsrc.c" -o "$BUILD_DIR/obj/z_$zsrc.o"
done

# ext4_utils (get_block_device_size used by liblp utility.cpp)
compile "$BUILD_DIR/obj/ext4_utils.o" \
  "$AOSP_ROOT/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/ext4_utils/ext4_utils.cpp"
compile "$BUILD_DIR/obj/ext4_sb.o" \
  "$AOSP_ROOT/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/ext4_utils/ext4_sb.cpp"

# SHA-256 shim + host liblog stub
cc -O1 -g0 -w -I"$HERE" -c "$HERE/sha256_shim.c" -o "$BUILD_DIR/obj/sha256_shim.o"
compile "$BUILD_DIR/obj/liblog_stub.o" "$HERE/liblog_stub.cpp" \
  "-I$AOSP_ROOT/bcac7c30d88a3773a7c0bc9f5617a23a886331fd/liblog/include"

# partition_tools: lpmake
compile "$BUILD_DIR/obj/lpmake.o" "$AOSP_ROOT/fc2494a2abd7ab21774d03deb09c1362bbb0bba8/partition_tools/lpmake.cc"

g++ "$BUILD_DIR"/obj/*.o -o "$BUILD_DIR/bin/lpmake" -lpthread
echo "built: $BUILD_DIR/bin/lpmake"

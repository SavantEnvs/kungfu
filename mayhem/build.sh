#!/usr/bin/env bash
#
# mayhem/build.sh — build kungfu::view's three libFuzzer harnesses (framework/core/fuzz) + the view probe.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# kungfu's fuzz surface is the self-contained kungfu::view module (framework/core/src/libkungfu/src/
# view/schema.cpp) over FlatBuffers + SQLite. Upstream builds it with conan; here FlatBuffers 25.9.23
# (the version upstream pins) is compiled from the source the Dockerfile fetched into /opt/toolchains,
# so the parser itself (the main target of fuzz_compile_schema) is sanitizer-instrumented. Everything
# resolves from the image — no network. Build dirs are build-*/ (gitignored upstream).
FB_SRC=/opt/toolchains/flatbuffers/src
CORE="$SRC/framework/core"
FUZZ="$CORE/fuzz"
VIEW_SRC="$CORE/src/libkungfu/src/view/schema.cpp"
VIEW_INC="$CORE/src/libkungfu/include"
OUT="$SRC"
TARGETS="fuzz_compile_schema fuzz_from_bytes fuzz_bind_frame"

build_flatbuffers() {  # <build dir> <install prefix> <flags...>
  local bdir="$1" prefix="$2"; shift 2
  # Fresh configure every run: a re-run may resolve the compiler differently (ccache masquerade vs
  # /usr/bin), which makes cmake discard its cache and lose the install prefix.
  rm -rf "$bdir"
  cmake -S "$FB_SRC" -B "$bdir" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="$*" -DCMAKE_CXX_FLAGS="$*" \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
        -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATC=OFF -DFLATBUFFERS_BUILD_FLATHASH=OFF \
        -DFLATBUFFERS_BUILD_FLATLIB=ON -DFLATBUFFERS_BUILD_SHAREDLIB=OFF -DFLATBUFFERS_INSTALL=ON
  cmake --build "$bdir" -j"$MAYHEM_JOBS" --target flatbuffers
  cmake --install "$bdir" --prefix "$prefix" >/dev/null
}

# 1) FlatBuffers, sanitized + DWARF 3 (for the fuzz targets).
build_flatbuffers "$SRC/build-mayhem-fb-san" "$SRC/build-mayhem-fb-san/install" \
  $SANITIZER_FLAGS $DEBUG_FLAGS -O1

# 2) Harnesses: each one twice (libFuzzer + standalone run-once reproducer), each with the view module
#    compiled in under $SANITIZER_FLAGS, leak detection off at build time (lsan_off.cc).
FBSAN="$SRC/build-mayhem-fb-san/install"
OBJ="$SRC/build-mayhem-fuzz-obj"
mkdir -p "$OBJ"
COMMON="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -std=c++20 -I$VIEW_INC -I$FBSAN/include"
$CXX $COMMON -c "$VIEW_SRC" -o "$OBJ/schema.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for t in $TARGETS; do
  src="$FUZZ/$t.cpp"; [ -f "$SRC/mayhem/harnesses/$t.cpp" ] && src="$SRC/mayhem/harnesses/$t.cpp"
  $CXX $COMMON -c "$src" -o "$OBJ/$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$t.o" "$OBJ/schema.o" "$OBJ/lsan_off.o" \
       "$FBSAN/lib/libflatbuffers.a" -lsqlite3 -o "$OUT/$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/$t.o" "$OBJ/schema.o" "$OBJ/lsan_off.o" "$OBJ/standalone_main.o" \
       "$FBSAN/lib/libflatbuffers.a" -lsqlite3 -o "$OUT/$t-standalone"
done

# 3) Test oracle: upstream's own view-encapsulation probe (framework/core/slices/view-encapsulation),
#    built with the project's NORMAL flags against a plain FlatBuffers build; test.sh only runs it.
build_flatbuffers "$SRC/build-mayhem-fb-plain" "$SRC/build-mayhem-fb-plain/install" $COVERAGE_FLAGS
FBPLAIN="$SRC/build-mayhem-fb-plain/install"
$CXX -O2 -std=c++20 $COVERAGE_FLAGS -I"$VIEW_INC" -I"$FBPLAIN/include" \
     "$CORE/slices/view-encapsulation/probe.cpp" "$VIEW_SRC" "$FBPLAIN/lib/libflatbuffers.a" -lsqlite3 \
     -o "$OUT/view_encapsulation_probe"

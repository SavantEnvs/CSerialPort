#!/usr/bin/env bash
# mayhem/build.sh — build CSerialPort's fuzz harnesses and upstream's own doctest suites.
# CSerialPort's input-processing code (RingBuffer, protocol parsers) is header-only, so the
# harness TUs compile that library code with $SANITIZER_FLAGS + $DEBUG_FLAGS.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
cd "$SRC"

# Everything goes under build/ (gitignored upstream) so `git clean -ffdX` removes it.
OBJ="$SRC/build/mayhem-obj"
mkdir -p "$OBJ"

# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

for h in fuzz_protocol_parser fuzz_ringbuffer; do
  # fuzzer build: compile+link with $LIB_FUZZING_ENGINE so the (header-only) library code gets SanCov
  # shellcheck disable=SC2086
  $CXX -std=c++11 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC/include" \
      "$SRC/mayhem/harnesses/$h.cpp" "$OBJ/lsan_off.o" -o "$SRC/$h"
  # standalone reproducer: same harness, LLVM's run-once driver, no libFuzzer runtime
  # shellcheck disable=SC2086
  $CXX -std=c++11 $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/include" \
      "$SRC/mayhem/harnesses/$h.cpp" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" -o "$SRC/$h-standalone"
done

# End-to-end target: the library's Linux async sources (the set cmake/cserialport_src.cmake selects on
# UNIX without CSERIALPORT_ENABLE_NATIVE_SYNC), instrumented, plus a pty-driven harness.
LIBSRC=(src/SerialPort.cpp src/SerialPortBase.cpp src/SerialPortInfo.cpp src/SerialPortInfoBase.cpp
        src/SerialPortAsyncBase.cpp src/SerialPortUnixBase.cpp src/SerialPortInfoUnixBase.cpp)
h=fuzz_serialport_pty
# shellcheck disable=SC2086
$CXX -std=c++11 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC/include" \
    "$SRC/mayhem/harnesses/$h.cpp" "${LIBSRC[@]}" "$OBJ/lsan_off.o" -o "$SRC/$h" -lutil -lpthread
# shellcheck disable=SC2086
$CXX -std=c++11 $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/include" \
    "$SRC/mayhem/harnesses/$h.cpp" "${LIBSRC[@]}" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" \
    -o "$SRC/$h-standalone" -lutil -lpthread

# Upstream's functional suites (doctest), with the project's normal flags:
#   test/RingBufferTest  — RingBuffer unit tests
#   test/                — CSerialPort over virtual (pty) port pairs, incl. protocol-parser tests
cmake -S "$SRC/test/RingBufferTest" -B "$SRC/build/rbtest" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build "$SRC/build/rbtest" -j"$MAYHEM_JOBS"
cmake -S "$SRC/test" -B "$SRC/build/test" -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build "$SRC/build/test" -j"$MAYHEM_JOBS"

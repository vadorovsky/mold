#!/bin/bash
export LC_ALL=C
set -e
CC="${TEST_CC:-cc}"
CXX="${TEST_CXX:-c++}"
GCC="${TEST_GCC:-gcc}"
GXX="${TEST_GXX:-g++}"
MACHINE="${MACHINE:-$(uname -m)}"
testname=$(basename "$0" .sh)
echo -n "Testing $testname ... "
t=out/test/elf/$MACHINE/$testname
mkdir -p $t

cat <<EOF | $CC -o $t/a.o -c -xc -
volatile char arr[0x800000000];
int main() {
  arr[sizeof(arr) - 1] = 5;
  return arr[100];
}
EOF

$CC -B. -o $t/exe $t/a.o
$QEMU $t/exe

echo OK

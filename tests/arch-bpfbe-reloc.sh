#!/usr/bin/env bash
. $(dirname $0)/common.inc

command -v clang >/dev/null || skip "clang is required"

# Big-endian BPF objects are combined the same way as little-endian
# ones. The output must be a big-endian ELF64 BPF object with the
# relocations preserved.

cat <<'EOF' | clang -target bpfeb -c -o $t/a.o -xc -
int g = 7;
int foo(void) { return g + 1; }
EOF

cat <<'EOF' | clang -target bpfeb -c -o $t/b.o -xc -
int foo(void);
int bar(void) { return foo() + 1; }
EOF

./mold -r $t/a.o $t/b.o -o $t/c.o

readelf -h $t/c.o | grep -F 'Class:                             ELF64'
readelf -h $t/c.o | grep -F 'Data:                              2'"'"'s complement, big endian'
readelf -h $t/c.o | grep -F 'Machine:                           Linux BPF'
readelf -SW $t/c.o | grep -Fw .rel.text | grep -w REL
readelf -r $t/c.o | grep -F R_BPF_64_64 | grep -Fw g
readelf -r $t/c.o | grep -F R_BPF_64_32 | grep -Fw foo

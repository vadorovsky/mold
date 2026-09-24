#!/usr/bin/env bash
. $(dirname $0)/common.inc

command -v clang >/dev/null || skip "clang is required"

# Combining BPF objects with -r is the main use case of a BPF linker.
# The output must be a valid relocatable BPF object: the section contents
# are copied as-is and the relocations are preserved.

cat <<'EOF' | clang -target bpf -c -o $t/a.o -xc -
int g = 7;
int foo(void) { return g + 1; }
EOF

cat <<'EOF' | clang -target bpf -c -o $t/b.o -xc -
int foo(void);
int bar(void) { return foo() + 1; }
EOF

./mold -r $t/a.o $t/b.o -o $t/c.o

readelf -h $t/c.o | grep -F 'Class:                             ELF64'
readelf -h $t/c.o | grep -F 'Machine:                           Linux BPF'
readelf -S $t/c.o | grep -Fw .text
readelf -S $t/c.o | grep -Fw .data

# Relocations must be preserved with their symbols remapped. clang emits
# SHT_REL sections for BPF, so the output must use SHT_REL as well.
readelf -SW $t/c.o | grep -Fw .rel.text | grep -w REL
readelf -r $t/c.o | grep -F R_BPF_64_64 | grep -Fw g
readelf -r $t/c.o | grep -F R_BPF_64_32 | grep -Fw foo

# The call instruction must be left as the compiler emitted it, i.e.,
# 'call -1' with an unresolved target.
readelf -x .text $t/c.o | grep -F '85100000 ffffffff'

# The symbols of both input files must be exported.
readelf -s $t/c.o | grep -Fw foo
readelf -s $t/c.o | grep -Fw bar
readelf -s $t/c.o | grep -Fw g

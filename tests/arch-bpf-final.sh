#!/usr/bin/env bash
. $(dirname $0)/common.inc

command -v clang >/dev/null || skip "clang is required"

# Final (non-relocatable) BPF links apply all relocations. BPF has no
# implicit entry point, so mold warns about the missing _start symbol.

cat <<'EOF' | clang -target bpf -c -o $t/a.o -xc -
int g = 7;
int foo(void) { return g + 1; }
EOF

cat <<'EOF' | clang -target bpf -c -o $t/b.o -xc -
int foo(void);
int bar(void) { return foo() + 1; }
EOF

./mold $t/a.o $t/b.o -o $t/out 2> $t/err
grep -F 'entry symbol is not defined: _start' $t/err

# All relocations must have been applied.
readelf -r $t/out | not grep -F R_BPF

# The instruction that loads g must now contain g's address.
gaddr=$((16#$(readelf -sW $t/out | awk '$8 == "g" { print $2 }')))
imm=$(printf '%02x%02x%02x%02x' $((gaddr & 255)) $(((gaddr >> 8) & 255)) \
    $(((gaddr >> 16) & 255)) $(((gaddr >> 24) & 255)))
readelf -x .text $t/out | grep -F $imm

# The call instruction must contain the distance to foo in units of
# 8-byte instructions, minus one.
fooaddr=$((16#$(readelf -sW $t/out | awk '$8 == "foo" { print $2 }')))
callimm=$(printf '%02x%02x%02x%02x' $(((fooaddr / 8 - 1) & 255)) \
    $((((fooaddr / 8 - 1) >> 8) & 255)) $((((fooaddr / 8 - 1) >> 16) & 255)) \
    $((((fooaddr / 8 - 1) >> 24) & 255)))
readelf -x .text $t/out | grep -F $callimm

# Objects with debug info must be linkable too. The relocations in the
# debug sections are resolved against the final section addresses.
cat <<'EOF' | clang -target bpf -g -c -o $t/adbg.o -xc -
int g = 7;
int foo(void) { return g + 1; }
EOF
./mold $t/adbg.o $t/b.o -o $t/out2 2> $t/err2
readelf -r $t/out2 | not grep -F R_BPF
readelf -S $t/out2 | grep -Fw .debug_info
readelf -S $t/out2 | grep -Fw .BTF

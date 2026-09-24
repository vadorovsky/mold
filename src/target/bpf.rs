//! This file contains code for BPF, the Linux kernel's in-kernel virtual
//! machine. A BPF program is an ELF file whose allocated sections contain
//! 64-bit instructions. Programs are loaded into the kernel by libbpf,
//! which applies the remaining relocations at load time.
//!
//! From the linker's point of view, BPF is one of the simplest targets:
//! it is 64-bit, has no dynamic linking, thunks or TLS, and uses REL
//! relocations, whose addend field is always zero. Every relocation
//! resolves to S + I, where I is an implicit addend the compiler left in
//! the instruction itself (see `get_addend`). Most of them patch only the
//! 32-bit `imm32` field, which occupies the last 4 bytes of the 8-byte
//! instruction.
//!
//! The main use of a BPF linker is to combine several relocatable objects
//! into a single one (-r), which is what bpftool and libbpf expect.
//!
//! https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
//! https://sourceware.org/git/binutils-gdb.git/blob/HEAD:/include/elf/bpf.h

use crate::chunks::eh_frame;
use crate::context::Context;
use crate::elf::*;
use crate::input_sections::NonAllocReloc;
use crate::input_sections::{InputSection, scan_absrel};
use crate::symbol::Symbol;
use crate::target::{Family, Target};
use crate::{error, fatal};

/// BPF of a given byte order.
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfTarget<const LE: bool>;

pub type Bpf = BpfTarget<true>;
pub type BpfBe = BpfTarget<false>;

impl<const LE: bool> Target for BpfTarget<LE> {
    const IS_LITTLE: bool = LE;
    type Word = U64<Self>;
    type Sym = Elf64Sym<Self>;
    type Phdr = Elf64Phdr<Self>;
    type Chdr = Elf64Chdr<Self>;
    // BPF objects use SHT_REL sections. The addend field of a relocation
    // entry is always zero; the actual addend is implicit and stored in
    // the instruction (see get_addend).
    type Rel = ElfRelNoAddend<Self>;

    type InputSectionExtra = ();

    const NAME: &'static str = if LE { "bpf" } else { "bpfbe" };
    const FAMILY: Family = Family::Bpf;
    const PAGE_SIZE: u64 = 4096;
    const E_MACHINE: u32 = EM_BPF;

    // BPF objects are never dynamically linked, so no PLT or GOT is
    // ever created.
    const PLT_HDR_SIZE: u64 = 0;
    const PLT_SIZE: u64 = 0;
    const PLTGOT_SIZE: u64 = 0;

    // An `exit` instruction, used to fill padding in executable sections.
    const TRAP: &'static [u8] = &[0x95, 0, 0, 0, 0, 0, 0, 0];

    // BPF has no dynamic relocations. These constants are never used.
    const R_COPY: u32 = 0;
    const R_GLOB_DAT: u32 = 0;
    const R_JUMP_SLOT: u32 = 0;
    const R_ABS: u32 = 0;
    const R_RELATIVE: u32 = 0;
    const R_DTPOFF: u32 = 0;
    const R_TPOFF: u32 = 0;
    const R_DTPMOD: u32 = 0;
    const R_FUNCALL: &'static [u32] = &[];

    fn rel_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        bpf_rel_to_string(r_type)
    }

    // The implicit addend the compiler left in the instruction.
    fn get_addend(loc: &[u8], rel: &ElfRel<Self>) -> i64 {
        match rel.r_type() {
            R_BPF_64_64 => Self::read_u32(&loc[4..]) as i64,
            R_BPF_64_ABS64 => Self::read_u64(loc) as i64,
            R_BPF_64_ABS32 | R_BPF_64_NODYLD32 => Self::read_u32(loc) as i64,
            // The addend of a call instruction is the distance to the
            // target in units of 8-byte instructions, so it could be
            // negative.
            R_BPF_64_32 => Self::read_u32(&loc[4..]).wrapping_mul(8) as i32 as i64,
            _ => 0,
        }
    }

    // No BPF relocation can be promoted to a dynamic relocation, so the
    // generic word-size absolute relocation path is not used. All
    // relocations are applied in apply_reloc_alloc.
    fn is_absrel(_rel: &ElfRel<Self>) -> bool {
        false
    }

    fn write_plt_header(_ctx: &Context<Self>, _buf: &mut [u8]) {
        unreachable!("{} has no PLT", Self::NAME);
    }

    fn write_plt_entry(_ctx: &Context<Self>, _buf: &mut [u8], _sym: &Symbol) {
        unreachable!("{} has no PLT", Self::NAME);
    }

    fn write_pltgot_entry(_ctx: &Context<Self>, _buf: &mut [u8], _sym: &Symbol) {
        unreachable!("{} has no PLT", Self::NAME);
    }

    fn apply_eh_reloc(
        _ctx: &Context<Self>,
        _isec: &InputSection<Self>,
        rel: &ElfRel<Self>,
        loc: &mut [u8],
        _p: u64,
        val: u64,
    ) {
        match rel.r_type() {
            R_BPF_NONE => {}
            R_BPF_64_64 => Self::write_u32(&mut loc[4..], val as u32),
            R_BPF_64_ABS64 => Self::write_u64(loc, val),
            R_BPF_64_ABS32 | R_BPF_64_NODYLD32 => Self::write_u32(loc, val as u32),
            R_BPF_64_32 => Self::write_u32(&mut loc[4..], (val / 8) as u32),
            _ => eh_frame::unsupported::<Self>(rel),
        }
    }

    fn scan_relocations(ctx: &Context<Self>, isec: &InputSection<Self>) {
        debug_assert!(isec.is_alloc());
        let file = &ctx.objs[isec.file.index()];
        for rel in isec.relocations(ctx) {
            if rel.r_type() == R_BPF_NONE || isec.record_undef_error(ctx, &rel) {
                continue;
            }
            let sym = &ctx.symbols[file.base.symbols[rel.r_sym() as usize]];
            if sym.is_ifunc() {
                error!("{sym}: GNU ifunc symbol is not supported on BPF");
            }

            match rel.r_type() {
                // All BPF relocations are absolute. They cannot be made
                // dynamic, so report an error if the symbol's address is
                // not known at link time, i.e., when producing a shared
                // object or a position-independent executable.
                R_BPF_64_64 | R_BPF_64_ABS64 | R_BPF_64_ABS32 | R_BPF_64_NODYLD32 | R_BPF_64_32 => {
                    scan_absrel(ctx, isec, sym, &rel)
                }
                _ => error!(
                    "{}: unknown relocation: {}",
                    isec.display(file),
                    rel.type_name::<Self>()
                ),
            }
        }
    }

    fn apply_reloc_alloc(
        ctx: &Context<Self>,
        isec: &InputSection<Self>,
        rels: &mut [ElfRel<Self>],
        buf: &mut [u8],
    ) {
        let file = &ctx.objs[isec.file.index()];
        for rel in rels.iter() {
            if rel.r_type() == R_BPF_NONE || Self::is_absrel(rel) {
                continue;
            }
            let sym = &ctx.symbols[file.base.symbols[rel.r_sym() as usize]];
            let off = rel.r_offset() as usize;
            // The relocation resolves to the sum of the symbol's address
            // and the implicit addend stored in the instruction.
            let val = sym.addr(ctx).wrapping_add(isec.rel_addend(rel) as u64);

            match rel.r_type() {
                // Most relocations patch the 32-bit `imm32` field of the
                // instruction, which occupies the last 4 bytes of it.
                R_BPF_64_64 => Self::write_u32(&mut buf[off + 4..], val as u32),
                R_BPF_64_ABS64 => Self::write_u64(&mut buf[off..], val),
                R_BPF_64_ABS32 | R_BPF_64_NODYLD32 => Self::write_u32(&mut buf[off..], val as u32),
                // The target of a call instruction. `imm32` holds the
                // distance to the target in units of 8-byte instructions,
                // so the result is the total distance divided by 8.
                R_BPF_64_32 => Self::write_u32(&mut buf[off + 4..], (val / 8) as u32),
                _ => unreachable!("unexpected relocation {}", rel.type_name::<Self>()),
            }
        }
    }

    fn apply_reloc_nonalloc(ctx: &Context<Self>, isec: &InputSection<Self>, buf: &mut [u8]) {
        let mut fragment_cache = crate::input_sections::FragmentLookup::default();
        let file = &ctx.objs[isec.file.index()];
        for rel in isec.rels(file) {
            let Some(NonAllocReloc { sym, s, a, frag }) =
                isec.resolve_nonalloc(ctx, file, rel, &mut fragment_cache)
            else {
                continue;
            };
            let sa = s.wrapping_add(a);
            let tombstone = isec.tombstone(ctx, sym, frag);
            let loc = &mut buf[rel.r_offset() as usize..];

            match rel.r_type() {
                R_BPF_64_64 => Self::write_u32(&mut loc[4..], tombstone.unwrap_or(sa) as u32),
                R_BPF_64_ABS64 => Self::write_u64(loc, tombstone.unwrap_or(sa)),
                R_BPF_64_ABS32 | R_BPF_64_NODYLD32 => {
                    Self::write_u32(loc, tombstone.unwrap_or(sa) as u32)
                }
                _ => fatal!(
                    "{}: invalid relocation for non-allocated sections: {}",
                    isec.display(file),
                    rel.type_name::<Self>()
                ),
            }
        }
    }
}

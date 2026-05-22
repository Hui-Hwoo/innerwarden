// types.h — minimal kernel typedefs needed to compile shim.c.
//
// The shim is only here to make the eBPF object's BTF section non-empty
// so the kernel verifier on ≥ 6.4 accepts LSM programs. We deliberately
// avoid pulling vmlinux.h because the goal is the smallest readable
// surface that produces the right BTF, not full kernel-API access.
//
// Pattern mirrors how the Bombini project (also aya-based, also targets
// kernel 6.8) keeps its shim source tiny: a stub typedefs file, then
// `shim.c` declares the kernel structs with __attribute__((preserve_access_index))
// so the BPF target's BTF emission includes them.

#ifndef INNERWARDEN_SHIM_TYPES_H
#define INNERWARDEN_SHIM_TYPES_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

typedef unsigned int umode_t;
typedef long long loff_t;

#endif // INNERWARDEN_SHIM_TYPES_H

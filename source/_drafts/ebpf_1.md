---
title: eBPF - Part 1
readtime: true
date: 2024-04-05
tags: [linux,eBPF,low-level]
---

Hey everyone! Welcome to the first part of this blog series on `eBPF`.

## Pre-Requisites
System calls, C, basics of low-level programming.

## Introduction
eBPF (Extended Berkeley Packet Filter) is a technology that allows users to run custom programs within the kernel. BPF / or cBPF (classic BPF), the predecessor of eBPF provided a simple and efficient way to filter packets based on predefined rules. eBPF programs offer enhanced safety, portability, and maintainability as compared to kernel modules. There are several high-level methods available for working with eBPF programs, such as [Cilium's go library](https://github.com/cilium/ebpf), [bpftrace](https://github.com/bpftrace/bpftrace), [libbpf](https://github.com/libbpf/libbpf), etc. In this blog post, we'll explore eBPF at the lowest level possible, setting the stage for upcoming posts in this series.

## Working
`eBPF` is a custom, lightweight 64-bit RISC-like register-based virtual machine within the Linux kernel. It is designed to execute userland programs within the Linux kernel. The eBPF verifier checks the bytecode and ensures that only valid and safe programs are executed, that run to completion. Unsafe programs such as infinite loops, infinite recursions,etc. are rejected by the verifer. This means that eBPF, by design, is not Turing complete. Here's a quote from the [BPF Design QA](https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-what-are-the-verifier-limits) section of the Linux kernel documentation:

```
The verifier is steadily getting ‘smarter’. The limits are being removed. The only way to know that the program is going to be accepted by the verifier is to try to load it. 
```
With BPF being used in various areas like packet filtering and seccomp, interpreting the BPF bytecode everytime can slow down execution. Therefore, the BPF bytecode that passes verification is converted into machine code, which the CPU can interpret, via a Just-in-Time (JIT) compiler. 

## Instruction Set
While BPF operated on a 32-bit architecture, eBPF has been upgraded to a 64-bit architecture to ensure compatibility with modern systems. BPF programs are limited to 4096 instructions. First of all, let's have a look on the eBPF instruction set.

The struct `bpf_insn`, defined at [linux/bpf.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L72) defines a valid instruction in the eBPF instruction set.
```c
struct bpf_insn {
	__u8	code;		/* opcode, bits 0-7 */
	__u8	dst_reg:4;	/* destination register, bits 8-11 */
	__u8	src_reg:4;	/* source register, bits 12-15 */
	__s16	off;		/* signed offset, bits 16-31 */
	__s32	imm;		/* signed immediate constant, bits 32-63 */
};
```
The three LSB bits of the `opcode` field store the instruction class. There are different instruction classes, defined at [linux/bpf_common.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf_common.h#L13)

```c
/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC    0x07
```
Two more instruction classes, `BPF_JMP32` and `BPF_ALU64` are defined at [linux/bpf.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L16).

```c
/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */
```

## Registers
The eBPF VM consists of 10 general purpose registers, and a read-only frame pointer register. A 512-byte stack is available for an eBPF program. The following table shows various eBPF registers and their corresponding x64 registers.

    R0                  rax
    R1                  rdi
    R2                  rsi
    R3                  rdx
    R4                  rcx
    R5                  r8
    R6                  rbx
    R7                  r13
    R8                  r14
    R9                  r15
    R10                 rbp

`R0`: Stores return values from function calls, and exit code of programs. For example, in the case of seccomp, the stored exit code informs the kernel whether to allow or deny a system call.

`R1-R5`: These registers stores the function arguments. Apart from that, the R1 register stores a pointer to bpf context (of the type `PTR_TO_CTX`) at the start of the program.

`R10`: Stores the read-only frame pointer to access the stack.






## References
https://ebpf.io/what-is-ebpf/

https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html

https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/

https://blog.trailofbits.com/2023/01/19/ebpf-verifier-harness/

https://pawnyable.cafe/linux-kernel/LK06/ebpf.html

https://ortiz.sh/linux/2023/03/13/CBPF-VS-EBPF.html
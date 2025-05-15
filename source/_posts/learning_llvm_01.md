---
title: Learning LLVM (Part-1) - Writing a simple LLVM pass
readtime: true
date: 2024-06-29
tags: [llvm,low-level]
---

## Introduction
Welcome to the first part of this series on learning about LLVM. In this post, we'll learn how to write LLVM passes.

## About LLVM
LLVM (Low-Level Virtual Machine) is a collection of modular and reusable compiler and toolchain technologies. It has a wide range of uses due to its versatile architecture. LLVM serves as the backend for major programming languages such as Rust and Swift because of its capability to generate machine-native code. It is also used for JIT compilation and various other tasks such as static analysis, dynamic analysis, shader compilation, etc.

## Compiler in Layman's Terms
A compiler is a software program that translates the source code written in a high-level programming language into a form that can be executed by the computer's processor. A compiler is typically made up of three things: 

1. Frontend: The frontend of a compiler analyzes the source code and converts it into an intermediate representation (IR). The IR is typically independent of the source programming language and target architecture, allowing for the application of multiple optimizations and improving portability.

2. Middle-end: The middle-end of a compiler performs optimizations on the IR that are independent of the target CPU architecture. This phase focuses on general optimizations to improve performance and efficiency.

3. Backend: The backend of a compiler converts the optimized IR into machine code or assembly code specific to the target architecture. It is also responsible for applying target-specific optimizations to ensure the generated code runs efficiently on the given hardware.

## LLVM Passes
A `pass` is a modular and reusable component designed to perform transformations or analysis on the IR of a program.

According to the official [LLVM documentation](https://llvm.org/docs/Passes.html), there are two major types of passes: `Analysis Passes` and `Transform Passes`. There also exists another category of passes known as `Utility Passes`.

- `Analysis Passes`: They are designed to collect information and analyze the code without modifying anything.

- `Transform Passes`: The are designed to modify the IR of a program to improve performance, reduce code size, or setup the code for further optimizations. 

## Writing LLVM Passes
Before actually writing LLVM passes, get familiar with the concepts of Mixins in C++. [Here's](https://stackoverflow.com/questions/18773367/what-are-mixins-as-a-concept) a great explanation for the same. Don't forget to install llvm, clang and cmake. For this post, I'm using llvm-16.

```bash
#!/bin/bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 16
```
Running these commands will install llvm-16, clang-16, clang++-16, and other related tools. The LLVM headers will likely be stored in `/usr/include/llvm-16/llvm`. We need to move them directly to the `/usr/include` directory to make things easy.
```bash
mv /usr/include/llvm-16/llvm /usr/include/llvm
mv /usr/include/llvm-c-16/llvm-c /usr/include/llvm-c
```

LLVM contains two pass managers, the legacy pass manager (legacy PM) and the new pass manager (new PM). The middle-end uses the new PM, whereas the backend target-dependent code generation uses the legacy PM. We can either use the legacy pass manager or the new pass manager for writing our pass. In this post, we'll be using the new pass manager.

### LLVM Pass for printing function names
```cpp
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

namespace
{
  // All LLVM passes must inherit from the CRTP mixin PassInfoMixin
  struct FunctionListerPass : public PassInfoMixin<FunctionListerPass>
  {
    // A pass should have a run method
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM)
    {
      // outs() returns a reference to a raw_fd_ostream for standard output.
      outs() << F.getName() << '\n';
      return PreservedAnalyses::all();
    }
  };

}

PassPluginLibraryInfo getPassPluginInfo()
{
  const auto callback = [](PassBuilder &PB)
  {
    PB.registerPipelineStartEPCallback(
        [&](ModulePassManager &MPM, auto)
        {
          MPM.addPass(createModuleToFunctionPassAdaptor(FunctionListerPass()));
          return true;
        });
  };

  return {LLVM_PLUGIN_API_VERSION, "name", "0.0.1", callback};
};

/* When a plugin is loaded by the driver, it will call this entry point to
obtain information about this plugin and about how to register its passes.
*/
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
  return getPassPluginInfo();
}
```

Now, we must compile this program as a shared library. The following command can be used to do the same:
```bash
clang-16 -shared -o func_lister.so func_lister.cpp -fPIC
```

Let's create a file `test.c` and add some code in it.
```c
// test.c
void testFunctionOne()
{
}

void testFunctionTwo()
{
}

int main()
{
  return 0;
}
```
Running the following command will run the pass. Please note that the `-O1` flag is necessary. `-O2`, `-O3` flags will also work.

```bash
clang-16 -O1 -fpass-plugin=./func_lister.so test.c -o test
```
![](/images/llvm_learning/llvm_learning_01.png)

This was all about running a simple LLVM pass for printing the function names. The source code, alongwith the Dockerfile for running everything smoothly can be found [in this GitHub repository](https://github.com/0xSh4dy/learning_llvm). In the upcoming posts, we will explore even more fascinating applications of LLVM passes, including anti-reverse engineering and code obfuscation 😉.


References:

https://llvm.org/docs/WritingAnLLVMNewPMPass.html

https://blog.llvm.org/posts/2021-03-26-the-new-pass-manager/

https://stackoverflow.com/questions/54447985/how-to-automatically-register-and-load-modern-pass-in-clang
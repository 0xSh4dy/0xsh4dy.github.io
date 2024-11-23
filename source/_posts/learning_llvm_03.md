---
title: Learning LLVM (Part-3)
readtime: true
date: 2024-11-24
tags: [llvm,low-level]
---

## Intro to JIT
A JIT (Just-In-Time) compiler generates machine code dynamically after the program has started executing. In contrast, AOT (Ahead-Of-Time) compilers translate source code into executable code before the program is executed (the executable code is stored within the compiled binary itself).

## ORC
ORC, which stands for `On-Request Compilation`, is the third generation of the LLVM JIT API. It was preceded by MCJIT, and before that, by the Legacy JIT. In this post, we will develop a tiny calculator that uses the ORC JIT API to generate machine code on the fly.

## Setting up the layout
Let's define four instructions: `add`, `sub`, `mul`, and `xor`. Each line will contain one type of instruction:
```s
add val1, val2  
sub val1, val2  
mul val1, val2  
xor val1, val2  
```
Our program will read these instructions from a file line by line, JIT-compile each instruction, and print the result after execution. To represent the syntax shown above, we will create a struct named `Instruction` to define each line of code.

```cpp
struct Instruction {
    std::string name;
    int64_t val1;
    int64_t val2;

    Instruction(const std::string &name, int64_t val1, int64_t val2) 
        : name(name), val1(val1), val2(val2) {}
};
```

Since we'll be reading these instructions from a file, let's write a function which reads all these instructions from a file and returns a vector of these instructions.

```cpp
std::vector<std::unique_ptr<Instruction>> GetInstructions(const std::string &file_name) {
    std::ifstream ifile(file_name);
    std::string instruction_line;
    std::vector<std::unique_ptr<Instruction>> instructions;

    if (!ifile.is_open()) {
        fatal_error("Failed to open file: " + file_name);
    }

    while (std::getline(ifile, instruction_line)) {
        std::istringstream stream(instruction_line);
        std::string instruction_type;
        int64_t val1, val2;
        char comma;

        if (stream >> instruction_type >> val1 >> comma >> val2) {
            instructions.push_back(std::make_unique<Instruction>(instruction_type, val1, val2));
        } else {
            fatal_error("Invalid instruction format: " + instruction_line);
        }
    }
    return instructions;
}
```
We need one more thing for the basic setup: a simple function that throws errors and terminates the program.

```cpp
void fatal_error(const std::string &message) {
    std::cerr << message << std::endl;
    std::exit(1);
}
```

Now that we’ve covered the basics, we can start working on the LLVM-specific tasks. Before JIT-compiling our code, we need to generate the corresponding LLVM IR (Intermediate Representation) for all the functions we want to JIT-compile. To generate the LLVM IR, we first need to create an LLVM `context`, an LLVM `module`, and an `IR builder`.

- `Context`: The context serves as a container that owns and manages LLVM-specific core data structures.

- `Module`: An LLVM Module is a top-level container that represents a compilation unit containing functions, global variables, and other program elements such as a list of libraries (or other modules) this module depends on, a symbol table, etc.

- `Basic Block`: A basic block is a straight-line sequence of instructions with no branches, meaning that execution starts at a single entry point and proceeds sequentially to a single exit point, where it then continues to the next basic block. Basic blocks belong to functions and cannot have jumps into their middle, ensuring that once execution starts, it will proceed through all instructions in the block. The first instruction of a basic block is known as the leader.

Our goal is to generate a separate function in the form of LLVM IR for each instruction. For instance, the function corresponding to the add instruction will look like this:
```s
define i64 @add(i64 %0, i64 %1) {
entry:
  %2 = add i64 %0, %1
  ret i64 %2
}
``` 

Similarly, we need to generate LLVM IR functions for the other instructions. Let’s create a function that generates the LLVM IR for the valid instructions (add, sub, mul, and xor in this case).

```cpp
void AddFunctionsToIR(llvm::LLVMContext &ctx, llvm::Module *module, const std::string &function_name) {
    auto int64_type = llvm::Type::getInt64Ty(ctx);
    std::vector<llvm::Type *> params(2, int64_type);
    llvm::IRBuilder<> ir_builder(ctx);

    llvm::FunctionType *function_type = llvm::FunctionType::get(int64_type, params, false);
    llvm::Function *func = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage, function_name, module);

    // Create the entry block for the function
    llvm::BasicBlock *basic_block = llvm::BasicBlock::Create(ctx, "entry", func);
   
    // Append instructions to the basic block
    ir_builder.SetInsertPoint(basic_block);

    auto args = func->args();
    auto arg_iter = args.begin();
    llvm::Argument *arg1 = arg_iter++;
    llvm::Argument *arg2 = arg_iter;

    llvm::Value *result = nullptr;

    if (function_name == "add") {
        result = ir_builder.CreateAdd(arg1, arg2);
    } else if (function_name == "sub") {
        result = ir_builder.CreateSub(arg1, arg2);
    } else if (function_name == "mul") {
        result = ir_builder.CreateMul(arg1, arg2);
    } else if (function_name == "xor") {
        result = ir_builder.CreateXor(arg1, arg2);
    } else {
        fatal_error("Invalid function name: " + function_name);
    }

    // return the value
    ir_builder.CreateRet(result);
}
```
This piece of code generates functions for each of our instructions. Each function accepts two arguments and returns a value based on the operation. Now that we have created this function, let's proceed with writing the code for the main function.

We'll start by creating an LLVM context and a module:

```cpp
llvm::LLVMContext ctx;
auto module = std::make_unique<llvm::Module>("neko_module", ctx);
```
Now, let's call two important functions which are crucial for JIT compilation.
```cpp

/*
Initialize the native target corresponding to the host
*/
llvm::InitializeNativeTarget();


/* Calling this function is also necessary for code generation.
 It sets up the assembly printer for the native host architecture.
*/
llvm::InitializeNativeTargetAsmPrinter();
```
Now let's generate the IR for our four instructions using the `AddFunctionsToIR` function we defined above.
```cpp
AddFunctionsToIR(ctx, module.get(), "add");
AddFunctionsToIR(ctx, module.get(), "sub");
AddFunctionsToIR(ctx, module.get(), "mul");
AddFunctionsToIR(ctx, module.get(), "xor");
```

Now, we can create an instance of the LLJIT builder. LLJIT is part of LLVM’s ORC (On-Request Compilation) JIT engine, which provides a modern, flexible, and modular infrastructure for JIT compilation, as a suitable replacement for MCJIT.

```cpp
auto jit_builder = llvm::orc::LLJITBuilder();
auto jit = jit_builder.create();
```
Now, let's add our module to the main `JITDylib` (a JITDylib represents a JIT'd dynamic library).
```cpp
if (auto err = jit->get()->addIRModule(llvm::orc::ThreadSafeModule(std::move(module), std::make_unique<llvm::LLVMContext>()))) {
    fatal_error("Failed to add IR module for JIT compilation: " + llvm::toString(std::move(err)));
}
```

Now, with all the setup ready, we're ready to parse the code file, JIT-compile each function, execute it and print the result.
```cpp
llvm::orc::ExecutorAddr GetExecutorAddr(llvm::orc::LLJIT &jit, const std::string &function_name) {
    auto sym = jit.lookup(function_name).get();
    if (!sym) {
        fatal_error("Function not found in JIT: " + function_name);
    }
    return sym;
}
```
```cpp
// main
auto instructions = GetInstructions("code.txt");
std::unordered_map<std::string, llvm::orc::ExecutorAddr> fn_symbols;

for (const auto &instruction : instructions) {
    if (fn_symbols.find(instruction->name) == fn_symbols.end()) {
        fn_symbols[instruction->name] = GetExecutorAddr(*jit->get(), instruction->name);
    }

    auto *fn = reinterpret_cast<int64_t (*)(int64_t, int64_t)>(fn_symbols[instruction->name].getValue());
    int64_t value = fn(instruction->val1, instruction->val2);
    std::cout << value << std::endl;
}
```

In order to prevent the function lookup multiple times, we're using an `unordered_map` to cache the executor address, in case the same instruction occurs again. Here's the entire source code for this program:

```cpp
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <memory>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>

struct Instruction {
    std::string name;
    int64_t val1;
    int64_t val2;

    Instruction(const std::string &name, int64_t val1, int64_t val2) 
        : name(name), val1(val1), val2(val2) {}
};

void fatal_error(const std::string &message) {
    std::cerr << message << std::endl;
    std::exit(1);
}

std::vector<std::unique_ptr<Instruction>> GetInstructions(const std::string &file_name) {
    std::ifstream ifile(file_name);
    std::string instruction_line;
    std::vector<std::unique_ptr<Instruction>> instructions;

    if (!ifile.is_open()) {
        fatal_error("Failed to open file: " + file_name);
    }

    while (std::getline(ifile, instruction_line)) {
        std::istringstream stream(instruction_line);
        std::string instruction_type;
        int64_t val1, val2;
        char comma;

        if (stream >> instruction_type >> val1 >> comma >> val2) {
            instructions.push_back(std::make_unique<Instruction>(instruction_type, val1, val2));
        } else {
            fatal_error("Invalid instruction format: " + instruction_line);
        }
    }
    return instructions;
}

void AddFunctionsToIR(llvm::LLVMContext &ctx, llvm::Module *module, const std::string &function_name) {
    auto int64_type = llvm::Type::getInt64Ty(ctx);
    std::vector<llvm::Type *> params(2, int64_type);
    llvm::IRBuilder<> ir_builder(ctx);

    llvm::FunctionType *function_type = llvm::FunctionType::get(int64_type, params, false);
    llvm::Function *func = llvm::Function::Create(function_type, llvm::Function::ExternalLinkage, function_name, module);

    llvm::BasicBlock *basic_block = llvm::BasicBlock::Create(ctx, "entry", func);

    // Append instructions to the basic block
    ir_builder.SetInsertPoint(basic_block);

    auto args = func->args();
    auto arg_iter = args.begin();
    llvm::Argument *arg1 = arg_iter++;
    llvm::Argument *arg2 = arg_iter;

    llvm::Value *result = nullptr;

    if (function_name == "add") {
        result = ir_builder.CreateAdd(arg1, arg2);
    } else if (function_name == "sub") {
        result = ir_builder.CreateSub(arg1, arg2);
    } else if (function_name == "mul") {
        result = ir_builder.CreateMul(arg1, arg2);
    } else if (function_name == "xor") {
        result = ir_builder.CreateXor(arg1, arg2);
    } else {
        fatal_error("Invalid function name: " + function_name);
    }

    ir_builder.CreateRet(result);
 }

llvm::orc::ExecutorAddr GetExecutorAddr(llvm::orc::LLJIT &jit, const std::string &function_name) {
    auto sym = jit.lookup(function_name).get();
    if (!sym) {
        fatal_error("Function not found in JIT: " + function_name);
    }
    return sym;
}

int main() {
    llvm::LLVMContext ctx;
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();

    auto module = std::make_unique<llvm::Module>("neko_module", ctx);

    AddFunctionsToIR(ctx, module.get(), "add");
    AddFunctionsToIR(ctx, module.get(), "sub");
    AddFunctionsToIR(ctx, module.get(), "mul");
    AddFunctionsToIR(ctx, module.get(), "xor");

    auto jit_builder = llvm::orc::LLJITBuilder();
    auto jit = jit_builder.create();
    if (!jit) {
        fatal_error("Failed to create JIT: " + llvm::toString(jit.takeError()));
    }

    if (auto err = jit->get()->addIRModule(llvm::orc::ThreadSafeModule(std::move(module), std::make_unique<llvm::LLVMContext>()))) {
        fatal_error("Failed to add IR module for JIT compilation: " + llvm::toString(std::move(err)));
    }

    auto instructions = GetInstructions("code.txt");
    std::unordered_map<std::string, llvm::orc::ExecutorAddr> fn_symbols;

    for (const auto &instruction : instructions) {
        if (fn_symbols.find(instruction->name) == fn_symbols.end()) {
            fn_symbols[instruction->name] = GetExecutorAddr(*jit->get(), instruction->name);
        }

        auto *fn = reinterpret_cast<int64_t (*)(int64_t, int64_t)>(fn_symbols[instruction->name].getValue());
        int64_t value = fn(instruction->val1, instruction->val2);
        std::cout << value << std::endl;
    }

    return 0;
}

```

Now let's come to the main part, compiling this code. We'll use CMake to build the binary.
```
cmake_minimum_required(VERSION 3.13)
project(main)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM 16 REQUIRED CONFIG)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} main.cpp)

llvm_map_components_to_libnames(
    llvm_libs
    core
    orcjit
    native
)

target_link_libraries(${PROJECT_NAME} ${llvm_libs})
```

```sh
cmake .
cmake --build .
```

Let's create a `code.txt` file containing all the instructions. After creating this file, we can execute the binary.
```
add 1,2
sub 10,5
mul 10,20
xor 5,5
add 5,10
xor 10,5
```
![](/images/llvm_learning/llvm_learning_08.png)


Now let's load the binary in gdb and view the JIT'd code. 

![](/images/llvm_learning/llvm_learning_05.png)

In the image above, we can see the `call r12` instruction which calls the JIT'd code. Setting a breakpoint on this instruction, running the process, and by dumping instructions from the memory address stored in r12, we can see the following code:

![](/images/llvm_learning/llvm_learning_06.png)
![](/images/llvm_learning/llvm_learning_07.png)


It corresponds to the code for the functions that were JIT compiled. They are stored in a region whose permissions are later set to read-execute once the JIT compiler writes code into it. 

So, that's all for this post. It was a brief introduction to the powerful and advanced JIT execution engine in LLVM. In upcoming posts, we’ll explore more exciting features of the LLVM JIT API. Source code and CMakeLists.txt for this blog can be found [here](https://github.com/0xSh4dy/learning_llvm/tree/master/part_3).

References:

https://llvm.org/docs/ORCv2.html

https://liuyehcf.github.io/2023/07/10/LLVM-JIT/



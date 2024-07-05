---
title: Learning LLVM (Part-2)
readtime: true
date: 2024-07-06
tags: [llvm,low-level]
---

## Introduction
In the [first part](https://sh4dy.com/2024/06/29/learning_llvm_01/) of my blog series on compilers and LLVM, I provided a brief introduction to compiler fundamentals and LLVM. We also wrote a simple LLVM analysis pass to print function names. In this post, we will explore more concepts and create additional analysis passes to perform specific tasks.

## Module
In LLVM, a `Module` is a top-level container that encapsulates all the information related to an entire program or a significant portion of a program. It is the top-level container for LLVM Intermediate Representation (IR) objects. Each `Module` contains a list of global variables, a list of functions, a list of libraries (or other modules) this module depends on, a symbol table, and metadata about the target's characteristics.

## Basic Block
A basic block is a straight-line sequence of instructions with no branches, meaning that execution starts at a single entry point and proceeds sequentially to a single exit point, where it then continues to the next basic block. Basic blocks belong to functions and cannot have jumps into their middle, ensuring that once execution starts, it will proceed through all instructions in the block. The first instruction of a basic block is known as the leader.

## Control Flow Graph (CFG)
A CFG is a directed graph whose nodes represent basic blocks. The edges between the nodes represent control flow paths, indicating how execution can proceed from one basic block to another.

![](/images/llvm_learning/llvm_learning_02.png)

## Writing Passes
Note: In the previous blog post, we used `registerPipelineStartEPCallback` which registers a callback for a default optimizer pipeline extension point, and thus requires optimization levels `-O1 / -O2 / -O3` in order to run. Now, we're gonna use `registerPipelineParsingCallback` which will be helpful later on. Please note that I'll not be writing the entire program again and again. Instead I'll only show the actual implementation of the pass. Complete programs can be found [here](https://github.com/0xSh4dy/learning_llvm/tree/master/part_2).

```cpp
PassPluginLibraryInfo getPassPluginInfo()
{
    const auto callback = [](PassBuilder &PB)
    {
        PB.registerPipelineParsingCallback(
            [&](StringRef name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>)
            {
                if (name == "run-pass")
                {
                    MPM.addPass(SomePass());
                    return true;
                }
                return false;
            });
    };

    return {LLVM_PLUGIN_API_VERSION, "SomePass", LLVM_VERSION_STRING, callback};
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
    return getPassPluginInfo();
}
```
To run it, we can generate a `.ll` file containing the LLVM IR and then use `opt` to execute it.

```sh
clang-16 -S -emit-llvm test.c -o test.ll
opt-16 -load-pass-plugin ./lib.so -passes=run-pass -disable-output test.ll
```
Also, we need to add the `isRequired` function; otherwise, the `run()` function will not get called.
```cpp
struct SomePass: public PassInfoMixin<SomePass>{
  ...
  static bool isRequired()
  {
    return true;
  }
}
```


### Writing a pass for printing global variables and their type
Here's a simple LLVM pass that prints out all the global variables in a program alongwith their types. The code loops through all the globals, grabs their names and types, and prints them out. 

```cpp
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
    {
      auto globals = M.globals();
      for(auto itr = globals.begin();itr!=globals.end();itr++){
        StringRef varName = itr->getName();
        Type* ty = itr->getType();
        outs()<<"Variable Name: "<<varName<<"\n";
        outs()<<"Variable Type: ";
        ty->print(outs());
        outs()<<"\n";
      }
      return PreservedAnalyses::all();
    }
```

### Writing a pass for detecting unused global variables
This code iterates through all the globals and calls the `use_empty` function. This function returns true if there are no users of the value.

```cpp
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
    {
      auto globalVars = M.globals();
      for(GlobalVariable &gvar: globalVars){
        if(gvar.use_empty()){
            outs()<<"Unused global variable: "<<gvar.getName()<<"\n";
        }
      }
      return PreservedAnalyses::all();
    }
```

### Writing a pass for counting and printing all the basic blocks within functions
We go through every function in the module, then look at each basic block inside those functions. It's crucial to check if a function is just a declaration. This is because modules often includes declarations of library functions that are used in the code, but their full implementations aren't part of this module. Checking for declarations helps us avoid trying to analyze functions that don't have any actual code in this module.

```cpp
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
    {
        for (Function &F : M)
        {
            if (!F.isDeclaration())
            {
                int nBlocks = 0;
                outs() << "----------------------------------------------------------------------\n";
                outs() << "Counting and printing basic blocks in the function " << F.getName() << "\n";
                for (BasicBlock &BB : F)
                {
                    BB.print(outs());
                    outs() << "\n";
                    nBlocks++;
                }
                outs() << "Number of basic blocks: " << nBlocks << "\n";
            }
        }
        return PreservedAnalyses::all();
    }
```

### Detecting recursion
To determine if a function is recursive, we need to iterate through all the instructions in its basic blocks and check for call instructions. When an instruction with a call opcode `(Instruction::Call in LLVM)` is found, we can extract the called function by first casting the instruction to `CallInst` using `dyn_cast`(defined in llvm/Support/Casting.h) and then invoking `getCalledFunction`.

```cpp
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
    {
      for (Function &F : M)
      {
        bool recursionDetected = false;

        for (BasicBlock &BB : F)
        {
          for (Instruction &instr : BB)
          {
            if (instr.getOpcode() == Instruction::Call)
            {
              CallInst *callInstr = dyn_cast<CallInst>(&instr);
              if (callInstr)
              {
                Function *calledFunction = callInstr->getCalledFunction();
                if (calledFunction && calledFunction->getName() == F.getName())
                {
                  outs() << "Recursion detected: " << calledFunction->getName() << "\n";
                  recursionDetected = true;
                  break;
                }
              }
            }
          }
          if (recursionDetected)
            break;
        }
      }
      return PreservedAnalyses::all();
    }
```

### Depth-First Search on the Control Flow Graph
For each function, we can grab the first basic block, also known as the entry block, using `F.getEntryBlock()`. Then we call the `Dfs` function mentioned below.

```cpp
  void Dfs(BasicBlock *currentBlock)
  {
    static std::unordered_map<BasicBlock *, bool> visited;
    visited[currentBlock] = true;
    currentBlock->print(outs());
    for (BasicBlock *bb : successors(currentBlock))
    {
      if (!visited[bb])
      {
          Dfs(bb);
      }
    }
  }
  
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
  {
    for (Function &F : M)
    {
      if (!F.isDeclaration())
      {
        outs() << "----------------------------------------------------------------\n";
        outs() << "Running DFS for the function " << F.getName() << "\n";
        BasicBlock &entryBlock = F.getEntryBlock();
        Dfs(&entryBlock);
      }
    }
    return PreservedAnalyses::all();
  }

```
```
> opt-16 -load-pass-plugin ./lib.so -passes=run-pass -disable-output test.ll
----------------------------------------------------------------
Running DFS for the function testFunction

  %1 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  br label %2

2:                                                ; preds = %8, %0
  %3 = load i32, ptr %1, align 4
  %4 = icmp slt i32 %3, 10
  br i1 %4, label %5, label %11

5:                                                ; preds = %2
  %6 = load i32, ptr %1, align 4
  %7 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %6)
  br label %8

8:                                                ; preds = %5
  %9 = load i32, ptr %1, align 4
  %10 = add nsw i32 %9, 1
  store i32 %10, ptr %1, align 4
  br label %2, !llvm.loop !6

11:                                               ; preds = %2
  ret i32 1337
----------------------------------------------------------------
Running DFS for the function main

  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  %3 = call i32 @testFunction()
  store i32 %3, ptr %2, align 4
  %4 = load i32, ptr %2, align 4
  %5 = icmp sgt i32 %4, 1000
  br i1 %5, label %6, label %8

6:                                                ; preds = %0
  %7 = call i32 @puts(ptr noundef @.str.1)
  br label %10

10:                                               ; preds = %8, %6
  ret i32 0

8:                                                ; preds = %0
  %9 = call i32 @puts(ptr noundef @.str.2)
  br label %10

```
There are four basic blocks in the `main` function. Let's generate a visual representation of the control flow graph.
```bash
# Generate the LLVM IR
clang-16 -S -emit-llvm test.c -o test.ll

# Print Control-Flow Graph to 'dot' file.
opt-16 -dot-cfg -disable-output -enable-new-pm=0 test.ll

# Generate an image from the 'dot' file
dot -Tpng -o img.png .main.dot
```
This is how the control flow graph for the `main` function looks like, which matches with the graph that we printed using Depth-First Search.

![](/images/llvm_learning/llvm_learning_03.png)

That’s all for this post. In the next one, we’ll explore `Transform Passes` and various compiler optimization techniques. Source code for all the passes, with Dockerfile can be found [here](https://github.com/0xSh4dy/learning_llvm/blob/master/part_2)

## References
https://llvm.org/doxygen


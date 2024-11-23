## 1.Function Inlining
You must have seen inline functions in languages like C and C++. Ever wondered what they are? Whenever a function is called, a stack frame is created and push onto the stack. The return address, the base pointer are saved, function arguments are either populated into the CPU registers on pushed onto the stack, depending on the calling convention, and space is reserved for local variables. Doing all these steps generate something known as a function call overhead which may reduce the performance in case of small and simple functions. Larger functions This is where inlining comes into play. Inline functions eliminate the function call overhead. Function inlining is a classical compiler optimization which replaces function calls with the body of the called function in order to remove the overhead of making the call at runtime.

Note: Recursive functions can either not be inlined at all or inlined to a certain depth. If not taken care properly, inlining them may cause an infinite expansion of code.

Now let's write our first transform pass - a pass for function inlining which inlines functions containing less than 10 instructions. LLVM contains a function `InlineFunction` defined at `llvm/lib/Transforms/Utils/InlineFunction.cpp`, which wisely determines if a function is a suitable candidate for inlining, and if yes, inlines the function. This function does one level of inlining. For example, consider three functions: A,B,C. Let's say A calls B and B calls C. Then, after inlining function B, the call to B within A will be replaced with the body of the function B but a call instruction to C will still exist within B (inlining depth is 1). The same would happen with recursive functions to prevent an infinite expansion.

```cpp
PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
{
    bool changed = false;
    InlineFunctionInfo ifi;
    for (Function &F : M)
    {
        if (!F.isDeclaration())
        {
            StringRef function_name = F.getName();
            for (auto &usage : F.uses())
            {
                if (auto *callBase = dyn_cast<CallBase>(usage.getUser()))
                {
                    InlineResult inlined = InlineFunction(*callBase, ifi);
                    if (inlined.isSuccess())
                    {
                        changed = true;
                        outs() << "Inlined a call to " << F.getName() << "\n";
                    }
                }
            }
        }
    }
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
```

Here's a script for doing the job
```bash
#!/bin/bash
clang-16 -shared -o lib.so main.cpp -fPIC
clang-16 -S -emit-llvm test.c -o test.ll
opt-16 -load-pass-plugin ./lib.so -passes=run-pass -S -o test_inline.ll test.ll
```
Here, `test.ll` contains the original IR whereas `test_inline.ll` contains the updated IR, after applying the transform pass.

![](/images/llvm_learning/llvm_learning_04.png)

Booyah! Our first transform pass successfully worked and it is clear that the calls to the functions `add` and `multiply` have been inlined.


## Data-Flow Analysis
- Data-flow analysis is a technique for gathering information about values at different points in a program.
- We need to properly understand data-flow analysis in order to understand compiler optimizations later on.
- In data-flow analysis, we do not distinguish among the paths taken to reach a program point. We do not keep entire track of the states, but we abstract out details needed for the analysis.
- We wanna find out what are all the values a variable may have at a program point, and where these values may be defined.
- The definitions that may reach a program point along some path are known as `reaching definitions`.
- If several definitions of a variable may reach a single program point, then we cannot constant fold the variable.
- For constant folding we need to find definitions that are the unique definitions of their variable to reach a given program point, no matter which execution path is taken.
- In each application of data-flow analysis, we associate with each program point a data-flow value that represents an abstraction of the set of all possible program states that can be observed at that point. The set of all possible data-flow values is the domain of this application.
- Domain of data-flow values for reaching definitions is the set of all subsets of definitions in the program.
- A particular data-flow value is a set of definitions, and we want to associate with each point in the program the exact set of definitions that can reach that point.
- We denote the data-flow values before and after each statement `s` as `IN[s]` and `OUT[s]` respectively.
- The data-flow problem is to find a solution to a set of constraints on the ins and outs, for all statements.
- There are two constraints: those based on the semantics of statements (transfer functions) and those based on flow of control.

### Transfer Functions
- The data-flow values before and after a statement are constrained by the semantics of the statement.
- Relationship between the data-flow values before and after a statement is known as the transfer function. 
- Information may propagate forward along execution paths, or it may flow backwards up the execution paths.
- Let's denote the transfer function by fs.
- Forward flow: `Out[s] = fs(In[s])`.
- Backward flow: `In[s] = fs(Out[s])`.


### Control Flow Constraints
- Consider a basic block consisting of n statements. Then, the data flow out of a statement si is same as the data flow into a statement si+1 i.e In[Si+1] = Out[Si].

### Data flow in basic blocks
- Control flows from the beginning to the end of the block, without interruption or branching.
- `In[B] and Out[B]` denotes the data-flow values immediately before and after a basic block respectively.
- Data-flow equations usually do not have a unique solution. The goal is to find the most precise solution that satisfies the two set of constratins: transfer and control-flow constraints.
- Thus, we need a solution that does valid code improvements, instead of making improper transformations.

### Reaching definitions
- Reaching definitions is one of the most common and useful data-flow schemas.
- A definition `d` reaches a point `p` if there exists a path from the point immediately following `d` to `p` such that `d` is not `killed` along that path. The definition `d` is said to be killed if there is another definition of the same variable along the path. Each definition can assign value to a single variable, let's say `x`.
- A definition of a variable `x` is a statement that assigns or may assign a value to `x`.
- If we do not know if `d` is assigning a value to x, we must assume that it may assign.
- We assume that every path in the flow graph can be followed in some execution of the program. It is conservative to assume that a definition can reach a point even if it might not.
- For reaching definitions, transfer function is `fi(x) = geni(x) U (x-killi(x))`. `geni` is the set of definitions generated by the statement. `killi` is the set of all other definitions of `x` in the program.
- For basic blocks, the `gen` set contains all the definitions inside the block that visible immediately after the block. They are known as `downwards exposed`. A definition is downwards exposed in a basic block only if it is not killed by a subsequent definition to the same variable inside the same basic block. 
- A basic block's kill set is the union of all the definitions killed by individual statements.

## Live-Variable Analysis
- Some code improving transformations depend on information computed in the direction opposite to the flow of control in a program.
- In live-variable analysis, we wish to know for variable `x` and point `p` whether the value of `x` at `p` could be used along some path in the flow graph starting at `p`. If so, we say that the variable `x` is live at `p` otherwise it is dead at `p`.
- A use of live-variable analysis comes in register allocation for basic blocks.
- Here, we use the use-def model. `defB` represents the set of variables (definitely assigned values) in B prior to any use of that variable in B. `useB` is the set of variables whose values may be used in B prior to any definition of the variable.
- Any variable in `useB` must be considered live on entrance to the block `B`.
- Membership in `defB` kills any opportunity for a variable to be live because of the paths that begin at B.
- In[EXIT] = NULL : Boundary condition
- In[B] = useB U (out[B]-defB) : a variable is live coming into a block if it either is used before redefinition in the block or it is live coming out of the block and is not redefined in the block.
- Out[B] = (union of successors S) In[S]: a variable is live coming out of a block if and only if it is live coming into one of its successors.
- Information flow for liveness travels backwards, opposite to the direction of control flow, because in this problem we want to make sure that the use of a variable `x` at a point `p` is transmitted to all points prior to `p` in an execution path, so that we may know at the prior point that `x` will have its value used.
- To solve a backward flow problem iteratively, we initialize `In[EXIT]` instead of initializing `Out[ENTRY]`. In backward flow, we use `use-def` instead of `gen-kill`.

## Available Expressions
- An expression `x+y` is available at a point `p` if every path from the entry node to `p` evaluates `x+y`, and after the last such evaluation of `x+y` prior to reaching `p`, there are no subsequent assignments to `x` or `y`. Here, `+` is a general operator, not the addition operator. A block kills an expression `x+y` if it assigns or may assign `x` or `y` and does not subsequently recompute `x+y`.
- A block generates an expression `x+y` if it definitely evaluates `x+y` and does not subsequently define `x` or `y`.
- The primary use of available expression information is for detecting `global common subexpressions`.
- An expression is available at the beginning of a block if and only if it is available at the end of each of its predecessors.

## 1. Constant Folding
`Constant-expression evaluation`, or `constant folding` is an optimization technique to evaluate expressions at compile time whose operands are known to be constants. After evaluation, the expressions are replaced with the computed constant value. For boolean values, this optimization is always applicable. For integer values, it is almost always applicable other than the cases that generate runtime exceptions such as division by zero or overflows. For floating point values, one must ensure that the evaluation obeys the processor-specific floating point standards.
We can perform constant folding on multiple operations. For example,
```c
void func(){
    int x = 2+3; // constant folded to 5
    int y = 2*5; // constant folded to 10
}
```
Quoting from [this link](https://lists.llvm.org/pipermail/llvm-dev/2019-January/129450.html), we see that constant folding is such a common optimization that it is enabled by default, and occurs even before the IR is generated. The following code from LLVM source code proves it.
```c
// llvm/IR/IRBuilder.h

Value *CreateAdd(Value *LHS, Value *RHS, const Twine &Name = "",
                bool HasNUW = false, bool HasNSW = false) {
if (Value *V =
        Folder.FoldNoWrapBinOp(Instruction::Add, LHS, RHS, HasNUW, HasNSW))
    return V;
return CreateInsertNUWNSWBinOp(Instruction::Add, LHS, RHS, Name, HasNUW,
                                HasNSW);
}

Value *CreateSub(Value *LHS, Value *RHS, const Twine &Name = "",
                bool HasNUW = false, bool HasNSW = false) {
if (Value *V =
        Folder.FoldNoWrapBinOp(Instruction::Sub, LHS, RHS, HasNUW, HasNSW))
    return V;
return CreateInsertNUWNSWBinOp(Instruction::Sub, LHS, RHS, Name, HasNUW,
                                HasNSW);
}
....

```

# Prof Uday Khedker

- Edges between basic blocks indicates control transfer.
- Basic blocks form nodes in a Control Flow Graph.
- We define sets associated with each basic block.

## Live Variable Analysis
- Program point is a position in the execution of a program.
A variable `v` is live at a program point `p`, if some path from p to program exit contains an rvalue occurence of v which is not preceded by an lvalue occurence of v.
- A variable is live at p if some path from p to program exit contains a read of the variable which is not preceded by a definition of the variable i.e the current value of the variable is being used later and therefore its important to preserve the value. Since the value is used later, the variable is considered live.
- For each node k, we store the genk and killk set.
- gen stores the set of variables that become live as a consequence of the execution of statements within the basic block.
- kill stores the set of variables which seem to be live because of assignments within the basic block.

### Local Data Flow Properties
- Gen n = {v | variable v is used in a basic block n and is not preceded by a definition of v. Here, used refers to an rvalue occurence ( variable is only read). rvalue occurences can also occur on the left hand side, in case of object or array access. Definition refers to an lvalue occurence. Preceding means within the basic block, we don't care what's happening outside the basic block.}

- kill n = {v | basic block n contains a definition of v: anywhere in n}
- In set stores the variables satisfying the property at the entry of the basic block.
- Out : at exit of basic block
- In k and Out k are also known as data-flow variables.
- In order to find variables that are live at the exit of a basic block, we only need to find the variables that are live at the entry of the successor basic block and perform their union
- Variables that are live at the exit of a basic block is the union of all the sets of variables that are live at the entry of successor basic blocks.
- End block in a program doesn't have any successors and therefore we have to define the boundary information. BI is the empty set for local variables.
- For liveness analysis, we need to traverse the CFG from the exit to the entry (backward flow).

- Live variables are candidates for register allocation
- Live var analysis is used for dead code elimination. If variable `x` is not live after an assignment x = `something`, then the assignment is redundant and can be deleted as dead code. 

- We can repeat liveness analysis on the code and optimize it further. This can continue as long as code continues to change. A better approach would be to perform strong liveness analysis, where the code needs to be optimized only once.
- Data-flow analysis involves defining the analysis, formulating the analysis, and performing the analysis.
- Defining the analysis: define the properties of execution paths
- Formulating the analysis: Define data flow equations, linear equations on sets rather than numbers
- Perform the analysis: solve data flow equations for the given program flow graph.
- Termination is guaranteed because sets are finite and can only grow
- since initial value is phi, values converge on empty set

## Available Expression Analysis
- An expression e is available at a program point p, if every path from program entry to p contains an evaluation of e which is not followed by a definition of any operand of e.

Gen n = {e | expression e is evaluated in basic block n and this evaluation is not followed by the definition of any of the operand of e}

kill n = {e | basic block n contains a definition of an operand of e}
---
title: Learning LLVM (Part-3) - Compiler Optimization - 1
readtime: true
date: 2024-08-31
tags: [llvm,low-level]
---

## Introduction
In the earlier posts in this series on learning about compilers and LLVM, we've looked into analysis passes. Now, we're moving on to transform passes. These passes modify the LLVM IR to either boost performance, shrink code size, or setup the code for additional optimizations. Optimization passes are a common type of transform pass. Using builtin transform passes ain't fun, isn't it? Writing custom optimization passes is an excellent way to learn more about compilers and deepen our understanding of how compilers use `program analysis` for optimization.

## Program Analysis
Program analysis is the process of analyzing the behavior of computer programs regarding different characteristics such as liveliness, correctness, security, etc. This analysis can be either static or dynamic. Most code optimization techniques are based on data-flow analysis, which is used to gather information about a program.

## Intro to Data-Flow Analysis
Data flow analysis involves methods that gather insights into how data moves across different execution paths in a program. It typically operates over a Control-Flow Graph. Based on the direction of data-flow, there are different types of analyses available. In this post, we'll be covering live variable analysis.

## Live Variable Analysis
A variable is said to be live at a point if there exists a path from the point to the program exit containing a use of the variable which is not preceded by any redefinition i.e an rvalue occurence of the variable not preceded by an lvalue occurence. Even if one path with an rvalue occurence of the variable exists, it will be considered live. Liveness is a point property.

<div style="display: flex; align-items: center; justify-content: space-between;">
    <img src="/images/llvm_learning/blog3_1.jpg" alt="Image 1" style="max-width: 48%; height: auto;">
    <div style="width: 4%;"></div> <!-- This div creates a gap -->
    <img src="/images/llvm_learning/blog3_2.jpg" alt="Image 2" style="max-width: 48%; height: auto;">
</div>

Consider the two images shown above. Each image presents a simple control-flow graph with two possible paths from the program point `p` to the end. A program point is nothing but specific location within a program's control flow. The first diagram includes a path from `p` to the end where the variable `x` is used without any redefinition (i.e `a = x + 2`). In contrast, both paths in the second diagram redefine `x`. Therefore, we can conclude that the variable `x` is live at the program point `p` in the first diagram, but it is not live at `p` in the second diagram.


<div style="display: flex; align-items: flex-start;">

<div style="flex: 1;">
Let's consider another example. Here, there's only one path from the program point p to the program exit. There's a statement x = x+2, which contains both lvalue and rvalue occurrences of x. However, the expression x+2 is evaluated first, and then the result is stored. According to the definition of liveness, an rvalue occurrence must not be preceded by an lvalue occurrence of the same variable, which satisfies this case. Hence, the variable x is live at the program point p.
</div>

<div style="flex: 1; text-align: right;">
<img src="/images/llvm_learning/blog3_3.jpg" alt="Image 1" style="max-width: 60%; height: auto;">
</div>

</div>

Consider a basic block `b`. The successors of `b` are the basic blocks to which control can flow directly after the execution of `b`. In contrast, the basic blocks that transfer control to the current block are known as predecessors. Let us define four sets for the basic block `b`.

use<sub>b</sub> : the set of all variables which are used in the basic block and not preceded by a definition within the block. We don't care about what's happening outside the block at the moment.

def<sub>b</sub> : the set of variables which are defined in the basic block (assignments).

In<sub>b</sub>: the set of variables that are live at the entry of the block.

Out<sub>b</sub>: the set of variables that are live at the exit of the block.

Having computed `use`<sub>b</sub> and `set`<sub>b</sub>, we can write the dataflow equations for computing the `In` and `Out` sets. 

{% mathjax %}
\Large \text{In}_b = \text{use}_b \cup (\text{Out}_b - \text{def}_b)
{% endmathjax %}

<br>
{% mathjax %}
\Large \text{Out}_b = \bigcup_{\text{s is a successor of } b} \text{In}_s
{% endmathjax %}

The liveness information is propagated backwards to a block from its successor blocks which is then used for computing the set of live variables at the entry of the block using `use` and `def` sets.

Note: In general terms, the term `gen-kill` is used. However, for live variable analysis, we're using the terms `use-def`.

Let's try out an example for getting a better understanding of liveness analysis. The following image shows a simple control flow graph with six basic blocks containing some statements. Let's assume there exist two imaginary basic blocks namely `entry` and `exit` block such that the set of live variables going out of the entry block and the set of variables going into the exit block are empty.

<img src="/images/llvm_learning/blog3_4.jpg" alt="Image 1" style="max-width: 60%; height: auto;">

Let's build the use and def sets for each basic block and compute the in and out sets. We'll initialize all the in sets as {%mathjax%}\phi{%endmathjax%}.


References:

https://www.cs.cornell.edu/courses/cs6120/2019fa/blog/llvm-function-inlining/#:~:text=It%20is%20a%20common%20convention,having%20to%20repeat%20the%20code.

https://www.amazon.in/Advanced-Compiler-Design-Implementation-Muchnick/dp/1558603204


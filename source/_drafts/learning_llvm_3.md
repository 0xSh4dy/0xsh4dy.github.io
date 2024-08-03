## Writing Transform Passes

### Constant Propagation
- If the value of a variable is known to be a constant, replace the use of
the variable by that constant.
- Value of the variable must be propagated forward from the point of
assignment. 

```cpp
PreservedAnalyses run(Module &M, ModuleAnalysisManager &MPM)
        {
            std::unordered_map<Value *, Constant *> constantMap;
            for(Function &F:M){
                outs()<<"Function "<<F.getName()<<" before constant propagation :\n";
                F.print(outs());
                outs()<<"\n";
                for(BasicBlock &BB:F){
                    for(Instruction &Instr:BB){
                        StoreInst *storeInst = dyn_cast<StoreInst>(&Instr);
                        LoadInst *loadInst = dyn_cast<LoadInst>(&Instr);
                        if(storeInst){
                            Value *ptrOperand = storeInst->getPointerOperand();
                            Value *valueOperand = storeInst->getValueOperand();
                            Constant *constVal = dyn_cast<Constant>(valueOperand);
                            
                            if(constVal){
                                constantMap[ptrOperand] = constVal;
                            }
                        }
                        else if(loadInst){
                            Value *ptrOperand = loadInst->getPointerOperand();
                            if(constantMap.find(ptrOperand)!=constantMap.end()){
                                loadInst->replaceAllUsesWith(constantMap[ptrOperand]);
                            }
                        }
                    }
                }
                outs()<<"After constant propagation:\n";
                F.print(outs());
                outs()<<"\n";
            }
            return PreservedAnalyses::none();
        }
```
```
define dso_local void @testFunction() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 10, ptr %1, align 4
  %4 = load i32, ptr %1, align 4
  %5 = add nsw i32 %4, 20
  store i32 %5, ptr %2, align 4
  %6 = load i32, ptr %1, align 4
  %7 = load i32, ptr %2, align 4
  %8 = add nsw i32 %6, %7
  %9 = add nsw i32 %8, 40
  store i32 %9, ptr %3, align 4
  ret void
}

After constant propagation:
define dso_local void @testFunction() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 10, ptr %1, align 4
  %4 = load i32, ptr %1, align 4
  %5 = add nsw i32 10, 20
  store i32 %5, ptr %2, align 4
  %6 = load i32, ptr %1, align 4
  %7 = load i32, ptr %2, align 4
  %8 = add nsw i32 10, %7
  %9 = add nsw i32 %8, 40
  store i32 %9, ptr %3, align 4
  ret void
}

```
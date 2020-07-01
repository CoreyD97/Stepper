package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

public abstract class PreExecutionStepVariable extends StepVariable {

    PreExecutionStepVariable(String identifier){
        super(identifier);
    }

    public abstract void updateVariableBeforeExecution();
}

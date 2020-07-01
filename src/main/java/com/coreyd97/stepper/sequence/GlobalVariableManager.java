package com.coreyd97.stepper.sequence;

import com.coreyd97.stepper.variable.VariableManager;

public class GlobalVariableManager extends VariableManager {

    private final StepSequence sequence;

    public GlobalVariableManager(StepSequence sequence){
        this.sequence = sequence;
    }
}

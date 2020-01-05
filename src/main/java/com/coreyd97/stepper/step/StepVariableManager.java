package com.coreyd97.stepper.step;

import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.VariableManager;

public class StepVariableManager extends VariableManager {

    private final Step step;

    StepVariableManager(Step step){
        super();
        this.step = step;
    }

    public void updateVariablesBeforeExecution(){
        for (StepVariable variable : this.variables) {
            variable.updateVariableBeforeExecution();
        }
    }

    public void updateVariablesAfterExecution(StepExecutionInfo executionInfo){
        for (StepVariable variable : this.variables) {
            variable.updateVariableAfterExecution(executionInfo);
        }
    }

    public void refreshVariableFromPreviousExecution(StepVariable variable){
        variable.updateVariableAfterExecution(this.step.getLastExecutionResult());
    }
}

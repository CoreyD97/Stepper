package com.coreyd97.stepper;

public interface IStepVariableListener {
    void onVariableAdded(StepVariable variable);
    void onVariableRemoved(StepVariable variable);
    void onVariableChange(StepVariable variable, StepVariable.ChangeType origin);
}

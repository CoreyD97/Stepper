package com.coreyd97.stepper.variable.listener;

import com.coreyd97.stepper.variable.StepVariable;

public interface IStepVariableListener {
    void onVariableAdded(StepVariable variable);
    void onVariableRemoved(StepVariable variable);
    void onVariableChange(StepVariable variable, StepVariable.ChangeType origin);
}

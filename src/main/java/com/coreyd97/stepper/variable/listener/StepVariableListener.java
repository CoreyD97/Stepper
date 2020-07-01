package com.coreyd97.stepper.variable.listener;

import com.coreyd97.stepper.variable.StepVariable;

public interface StepVariableListener {
    void onVariableAdded(StepVariable variable);
    void onVariableRemoved(StepVariable variable);
    void onVariableChange(StepVariable variable);
}

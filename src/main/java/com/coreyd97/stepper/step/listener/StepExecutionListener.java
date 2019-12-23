package com.coreyd97.stepper.step.listener;

import com.coreyd97.stepper.step.StepExecutionInfo;

public interface StepExecutionListener {
    void beforeStepExecution();
    void stepExecuted(StepExecutionInfo stepExecutionInfo);
}

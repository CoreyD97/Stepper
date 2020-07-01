package com.coreyd97.stepper.step.listener;

import com.coreyd97.stepper.step.Step;

public interface StepListener {
    void onStepAdded(Step step);
    void onStepUpdated(Step step);
    void onStepRemoved(Step step);
}

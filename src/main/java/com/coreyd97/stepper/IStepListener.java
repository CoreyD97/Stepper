package com.coreyd97.stepper;

public interface IStepListener {
    void onStepAdded(Step step);
    void onStepUpdated(Step step);
    void onStepRemoved(Step step);
}

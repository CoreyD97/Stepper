package com.coreyd97.stepper;

public interface IStepSequenceListener {
    void onStepSequenceAdded(StepSequence sequence);
    void onStepSequenceRemoved(StepSequence sequence);
}

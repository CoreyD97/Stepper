package com.coreyd97.stepper.sequencemanager.listener;

import com.coreyd97.stepper.sequence.StepSequence;

public interface StepSequenceListener {
    void onStepSequenceAdded(StepSequence sequence);
    void onStepSequenceRemoved(StepSequence sequence);
}

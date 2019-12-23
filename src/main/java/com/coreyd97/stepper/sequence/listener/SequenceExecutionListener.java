package com.coreyd97.stepper.sequence.listener;

import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import java.util.List;

public interface SequenceExecutionListener {
    void beforeSequenceStart(List<Step> steps);
    void sequenceStepExecuted(StepExecutionInfo executionInfo);
    void afterSequenceEnd(boolean success);
}

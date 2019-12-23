package com.coreyd97.stepper.sequence.listener;

import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import java.util.List;

public abstract class SequenceExecutionAdapter implements SequenceExecutionListener {

    @Override
    public void beforeSequenceStart(List<Step> steps) {

    }

    @Override
    public void sequenceStepExecuted(StepExecutionInfo executionInfo) {

    }

    @Override
    public void afterSequenceEnd(boolean success) {

    }
}

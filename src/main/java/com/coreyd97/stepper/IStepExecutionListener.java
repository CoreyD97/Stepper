package com.coreyd97.stepper;

public interface IStepExecutionListener {
    void beforeFirstStep(int totalSteps);
    void afterLastStep();
    void stepExecuted(Step step);
}

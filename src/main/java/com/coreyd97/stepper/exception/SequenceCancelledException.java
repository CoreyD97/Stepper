package com.coreyd97.stepper.exception;

public class SequenceCancelledException extends SequenceExecutionException {
    public SequenceCancelledException(String cause){
        super(cause);
    }
}

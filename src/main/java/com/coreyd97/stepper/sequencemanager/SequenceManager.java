package com.coreyd97.stepper.sequencemanager;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.listener.StepSequenceListener;
import com.coreyd97.stepper.variable.StepVariable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class SequenceManager {

    private final List<StepSequence> sequences;
    private final List<StepSequenceListener> sequenceListeners;

    public SequenceManager(){
        this.sequences = new ArrayList<>();
        this.sequenceListeners = new ArrayList<>();
    }

    public void addStepSequence(StepSequence sequence){
        this.sequences.add(sequence);
        for (StepSequenceListener stepSequenceListener : this.sequenceListeners) {
            try {
                stepSequenceListener.onStepSequenceAdded(sequence);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void removeStepSequence(StepSequence sequence){
        this.sequences.remove(sequence);
        for (StepSequenceListener stepSequenceListener : sequenceListeners) {
            try {
                stepSequenceListener.onStepSequenceRemoved(sequence);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void addStepSequenceListener(StepSequenceListener listener){
        this.sequenceListeners.add(listener);
    }

    public void removeStepSequenceListener(StepSequenceListener listener){
        this.sequenceListeners.remove(listener);
    }

    public List<StepSequence> getSequences() {
        return this.sequences;
    }

    /**
     * Map of the latest variables from each sequence.
     * E.g. If a variable is defined in step 1 and step n, the variable from step n will be used.
     * @return
     */
    public HashMap<StepSequence, List<StepVariable>> getRollingVariablesFromAllSequences(){
        try {
            HashMap<StepSequence, List<StepVariable>> allVariables = new HashMap<>();
            for (StepSequence stepSequence : this.sequences) {
                allVariables.put(stepSequence, stepSequence.getRollingVariablesForWholeSequence());
            }
            return allVariables;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}

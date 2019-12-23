package com.coreyd97.stepper;

import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.listener.StepSequenceListener;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.listener.StepListener;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.IStepVariableListener;

import java.util.ArrayList;

public class StateManager implements StepSequenceListener, StepListener, IStepVariableListener, IExtensionStateListener {

    private SequenceManager sequenceManager;
    private Preferences preferences;

    public StateManager(SequenceManager sequenceManager, Preferences preferences){
        this.sequenceManager = sequenceManager;
        this.preferences = preferences;
    }

    public void saveCurrentSequences(){
        this.preferences.setSetting(Globals.PREF_STEP_SEQUENCES, this.sequenceManager.getSequences());
    }

    public void loadSavedSequences(){
        ArrayList<StepSequence> stepSequences = this.preferences.getSetting(Globals.PREF_STEP_SEQUENCES);
        if(stepSequences != null) {
            for (StepSequence stepSequence : stepSequences) {
                this.sequenceManager.addStepSequence(stepSequence);
            }
        }
    }

    @Override
    public void onStepSequenceAdded(StepSequence sequence) {
        sequence.addStepListener(this);
        sequence.getSequenceGlobals().addVariableListener(this);
        saveCurrentSequences();
    }

    @Override
    public void onStepUpdated(Step step) {
        saveCurrentSequences();
    }

    @Override
    public void onStepSequenceRemoved(StepSequence sequence) {
        sequence.removeStepListener(this);
        sequence.getSequenceGlobals().removeVariableListener(this);
        saveCurrentSequences();
    }

    @Override
    public void onStepAdded(Step step) {
        step.addVariableListener(this);
        saveCurrentSequences();
    }

    @Override
    public void onStepRemoved(Step step) {
        step.removeVariableListener(this);
        saveCurrentSequences();
    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        saveCurrentSequences();
    }

    @Override
    public void onVariableRemoved(StepVariable variable) {
        saveCurrentSequences();
        variable.removeVariableListener(this);
    }

    @Override
    public void onVariableChange(StepVariable variable, StepVariable.ChangeType origin) {
        saveCurrentSequences();
    }

    @Override
    public void extensionUnloaded() {
        saveCurrentSequences();
    }
}

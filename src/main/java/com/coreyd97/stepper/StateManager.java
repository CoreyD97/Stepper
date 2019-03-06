package com.coreyd97.stepper;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.util.ArrayList;

public class StateManager implements IStepSequenceListener, IStepListener, IStepVariableListener {

    private Stepper stepper;
    private Preferences preferences;

    public StateManager(Stepper stepper, Preferences preferences){
        this.stepper = stepper;
        this.preferences = preferences;
    }

    public void saveCurrentSequences(){
        this.preferences.setSetting(Globals.PREF_STEP_SEQUENCES, this.stepper.getSequences());
        System.out.println(this.stepper.getGsonProvider().getGson().toJson(this.preferences.getSetting(Globals.PREF_STEP_SEQUENCES)));
    }

    public void loadSavedSequences(){
        ArrayList<StepSequence> stepSequences = (ArrayList<StepSequence>) this.preferences.getSetting(Globals.PREF_STEP_SEQUENCES);
        if(stepSequences != null) {
            for (StepSequence stepSequence : stepSequences) {
                this.stepper.addStepSequence(stepSequence);
            }
        }
    }

    @Override
    public void onStepSequenceAdded(StepSequence sequence) {
        sequence.addStepListener(this, false);
        sequence.getSequenceGlobals().addVariableListener(this);
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
}

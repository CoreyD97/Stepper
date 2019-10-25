package com.coreyd97.stepper;

import burp.IHttpRequestResponse;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.ui.StepContainer;
import com.coreyd97.stepper.ui.StepPanel;
import com.coreyd97.stepper.ui.StepSequenceTab;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Vector;

public class StepSequence
{
    private Stepper stepper;
    private String title;
    private SequenceGlobals sequenceGlobals;
    private Vector<Step> steps;
    private final ArrayList<IStepListener> stepListeners;
    private final ArrayList<IStepExecutionListener> stepExecutionListeners;

    public StepSequence(Stepper stepper, boolean createFirstStep, String title){
        this(stepper, createFirstStep);
        this.title = title;
    }

    public StepSequence(Stepper stepper, boolean createFirstStep){
        this.stepper = stepper;
        this.sequenceGlobals = new SequenceGlobals();
        this.steps = new Vector<>();
        this.stepListeners = new ArrayList<>();
        this.stepExecutionListeners = new ArrayList<>();
        this.title = "Step Sequence";
        if(createFirstStep){
            this.addStep();
        }
    }

    public void executeSteps(){
        new Thread(() -> {
            synchronized (StepSequence.this) {
                StepSequenceTab tabUI = this.stepper.getUI().getTabForStepManager(this);
                StepContainer stepContainer = tabUI.getStepsContainer();

                for (IStepExecutionListener stepListener : this.stepExecutionListeners) {
                    stepListener.beforeFirstStep(this.steps.size());
                }
                for (Step step : this.steps) {
                    //Since we can't add a listener to the messageEditors, we must update
                    //Our request content before executing instead :(
                    StepPanel panel = stepContainer.getPanelForStep(step);
                    step.setRequestBody(panel.getRequestEditor().getMessage());

                    if(!step.isReadyToExecute()){
                        JOptionPane.showMessageDialog(null, "One or more steps are incomplete.");
                        for (IStepExecutionListener stepExecutionListener : this.stepExecutionListeners) {
                            stepExecutionListener.afterLastStep();
                        }
                        return;
                    }
                }


                try {
                    HashMap<String, StepVariable> rollingReplacements = new HashMap<>();
                    for (Step step : this.steps) {

                        //Set step panel as selected panel
                        StepPanel panel = stepContainer.getPanelForStep(step);
                        stepContainer.setActivePanel(panel);

                        //Execute the step
                        step.executeStep(rollingReplacements);
                        for (StepVariable variable : step.getVariables()) {
                            rollingReplacements.put(variable.getIdentifier(), variable);
                        }
                        this.stepExecutionListeners.forEach(listener -> listener.stepExecuted(step));
                    }
                }catch (SequenceCancelledException e){
                    //User cancelled. Ignore it.
                }catch (SequenceExecutionException e){
                    JOptionPane.showMessageDialog(this.stepper.getUI().getUiComponent(), e.getMessage(),
                            "Sequence Stopped", JOptionPane.ERROR_MESSAGE);
                }
                for (IStepExecutionListener stepLExecutionistener : stepExecutionListeners) {
                    stepLExecutionistener.afterLastStep();
                }
            }
        }).start();
    }

    public void addStep(Step step){
        this.steps.add(step);
        step.setSequence(this);
        for (IStepListener stepListener : this.stepListeners) {
            try {
                stepListener.onStepAdded(step);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void addStep(){
        this.addStep(new Step(this));
    }

    public Vector<Step> getSteps() {
        return this.steps;
    }

    public void addStepExecutionListener(IStepExecutionListener listener){
        this.stepExecutionListeners.add(listener);
    }

    public void removeStepExecutionListener(IStepExecutionListener listener){
        this.stepExecutionListeners.remove(listener);
    }

    public void addStepListener(IStepListener listener, boolean executeAddedForExisting){
        this.stepListeners.add(listener);
        if(executeAddedForExisting){
            for (Step step : this.getSteps()) {
                listener.onStepAdded(step);
            }
        }
    }

    public void removeStepListener(IStepListener listener){
        this.stepListeners.remove(listener);
    }

    public void removeStep(Step step) {
        if(!this.steps.remove(step)) return; //If step not removed, ignore.
        step.dispose(); //Remove listener references
        for (IStepListener stepListener : this.stepListeners) {
            stepListener.onStepRemoved(step);
        }
    }

    public HashMap<String, StepVariable> getRollingVariables(Step uptoStep){
        HashMap<String, StepVariable> rolling = new HashMap<>();
        for (StepVariable variable : this.sequenceGlobals.getVariables()) {
            rolling.put(variable.getIdentifier(), variable);
        }
        for (Step step : this.steps) {
            if(uptoStep == step) break;
            for (StepVariable variable : step.getVariables()) {
                rolling.put(variable.getIdentifier(), variable);
            }
        }
        return rolling;
    }

    public void addStep(IHttpRequestResponse requestResponse) {
        Step step = new Step(this);
        step.setRequestBody(requestResponse.getRequest());
        step.setResponseBody(requestResponse.getResponse());
        step.setHttpService(requestResponse.getHttpService());
        addStep(step);
    }

    public HashMap<String, StepVariable> getAllVariables() {
        HashMap<String, StepVariable> allVariables = new HashMap<>();
        for (StepVariable variable : this.sequenceGlobals.getVariables()) {
            allVariables.put(variable.getIdentifier(), variable);
        }
        for (Step step : this.steps) {
            for (StepVariable variable : step.getVariables()) {
                allVariables.put(variable.getIdentifier(), variable);
            }
        }

        return allVariables;
    }

    public Step getOriginatingStep(StepVariable variable){
        for (Step step : this.steps) {
            if(step.getVariables().contains(variable)) return step;
        }
        return null;
    }

    public ArrayList<IStepListener> getStepListeners() {
        return stepListeners;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public SequenceGlobals getSequenceGlobals() {
        return this.sequenceGlobals;
    }

    public void setSequenceGlobals(SequenceGlobals sequenceGlobals) {
        this.sequenceGlobals = sequenceGlobals;
    }
}

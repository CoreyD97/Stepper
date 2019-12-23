package com.coreyd97.stepper;

import burp.IHttpRequestResponse;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.ui.StepContainer;
import com.coreyd97.stepper.ui.StepPanel;
import com.coreyd97.stepper.ui.StepSequenceTab;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

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
                    for (Step step : this.steps) {

                        //Set step panel as selected panel
                        StepPanel panel = stepContainer.getPanelForStep(step);
                        stepContainer.setActivePanel(panel);
                        List<StepVariable> rollingReplacements = this.getRollingVariablesUpToStep(step);

                        //Execute the step
                        step.executeStep(rollingReplacements);
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

    public void moveStep(int from, int to){
        if(to > from){ //Moving to the right. Take 1 from to index since we'll remove this one first.
            to--;
        }
        Step movedStep = this.steps.remove(from);
        this.steps.add(to, movedStep);
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

    /**
     * Returns all variables up to and excluding the given step.
     * If a variable is overwritten in a later step, only includes the latest instance.
     * @return List of all variables
     */
    public List<StepVariable> getRollingVariablesUpToStep(Step uptoStep){
        LinkedHashMap<String, StepVariable> rolling = new LinkedHashMap<>();
        for (StepVariable variable : this.sequenceGlobals.getVariables()) {
            rolling.put(variable.getIdentifier(), variable);
        }

        for (Step step : this.steps) {
            if(uptoStep == step) break;
            for (StepVariable variable : step.getVariables()) {
                rolling.put(variable.getIdentifier(), variable);
            }
        }

        return new ArrayList<>(rolling.values());
    }

    public void addStep(IHttpRequestResponse requestResponse) {
        Step step = new Step(this);
        step.setRequestBody(requestResponse.getRequest());
        step.setResponseBody(requestResponse.getResponse());
        step.setHttpService(requestResponse.getHttpService());
        addStep(step);
    }

    /**
     * Returns all variables, if a variable is overwritten in a later step.
     * Only includes the latest instance
     * @return List of all variables
     */
    public List<StepVariable> getRollingVariablesForWholeSequence() {
        return getRollingVariablesUpToStep(null); //Null for whole sequence
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

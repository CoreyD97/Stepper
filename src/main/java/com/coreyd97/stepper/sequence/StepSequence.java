package com.coreyd97.stepper.sequence;

import burp.IHttpRequestResponse;
import com.coreyd97.stepper.*;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.sequence.globals.SequenceGlobals;
import com.coreyd97.stepper.sequence.listener.SequenceExecutionListener;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;
import com.coreyd97.stepper.sequence.view.StepContainer;
import com.coreyd97.stepper.step.listener.StepListener;
import com.coreyd97.stepper.step.view.StepPanel;
import com.coreyd97.stepper.sequence.view.StepSequenceTab;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.util.*;

public class StepSequence
{
    private String title;
    private SequenceGlobals sequenceGlobals;
    private Vector<Step> steps;
    private final ArrayList<StepListener> stepListeners;
    private final ArrayList<SequenceExecutionListener> sequenceExecutionListeners;

    public StepSequence(boolean createFirstStep, String title){
        this(createFirstStep);
        this.title = title;
    }

    public StepSequence(boolean createFirstStep){
        this.sequenceGlobals = new SequenceGlobals();
        this.steps = new Vector<>();
        this.stepListeners = new ArrayList<>();
        this.sequenceExecutionListeners = new ArrayList<>();
        this.title = "Step Sequence";
        if(createFirstStep){
            this.addStep();
        }
    }

    public void executeSteps(){
        new Thread(() -> {
            synchronized (StepSequence.this) {
                StepSequenceTab tabUI = Stepper.getUI().getTabForStepManager(this);
                StepContainer stepContainer = tabUI.getStepsContainer();

                for (SequenceExecutionListener stepListener : this.sequenceExecutionListeners) {
                    stepListener.beforeSequenceStart(this.steps);
                }
                for (Step step : this.steps) {
                    //Since we can't add a listener to the messageEditors, we must update
                    //Our request content before executing instead :(
                    StepPanel panel = stepContainer.getPanelForStep(step);
                    step.setRequestBody(panel.getRequestEditor().getMessage());

                    if(!step.isReadyToExecute()){
                        JOptionPane.showMessageDialog(null, "One or more steps are incomplete.");
                        for (SequenceExecutionListener stepExecutionListener : this.sequenceExecutionListeners) {
                            stepExecutionListener.afterSequenceEnd(false);
                        }
                        return;
                    }
                }

                boolean sequenceSuccess = false;
                try {
                    for (Step step : this.steps) {
                        //Set step panel as selected panel
                        StepPanel panel = stepContainer.getPanelForStep(step);
                        stepContainer.setActivePanel(panel);
                        List<StepVariable> rollingReplacements = this.getRollingVariablesUpToStep(step);

                        //Execute the step
                        StepExecutionInfo stepExecutionInfo = step.executeStep(rollingReplacements);
                        this.sequenceExecutionListeners.forEach(listener -> listener.sequenceStepExecuted(stepExecutionInfo));
                    }
                    sequenceSuccess = true;
                }catch (SequenceCancelledException e){
                    //User cancelled. Ignore it.
                }catch (SequenceExecutionException e){
                    JOptionPane.showMessageDialog(Stepper.getUI().getUiComponent(), e.getMessage(),
                            "Sequence Stopped", JOptionPane.ERROR_MESSAGE);
                }
                for (SequenceExecutionListener stepLExecutionistener : sequenceExecutionListeners) {
                    stepLExecutionistener.afterSequenceEnd(sequenceSuccess);
                }
            }
        }).start();
    }

    public void addStep(Step step){
        this.steps.add(step);
        step.setSequence(this);
        for (StepListener stepListener : this.stepListeners) {
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

    public void addSequenceExecutionListener(SequenceExecutionListener listener){
        this.sequenceExecutionListeners.add(listener);
    }

    public void removeSequenceExecutionListener(SequenceExecutionListener listener){
        this.sequenceExecutionListeners.remove(listener);
    }

    public void addStepListener(StepListener listener){
        this.stepListeners.add(listener);
    }

    public void removeStepListener(StepListener listener){
        this.stepListeners.remove(listener);
    }

    public void removeStep(Step step) {
        if(!this.steps.remove(step)) return; //If step not removed, ignore.
        step.dispose(); //Remove listener references
        for (StepListener stepListener : this.stepListeners) {
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

    public ArrayList<StepListener> getStepListeners() {
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

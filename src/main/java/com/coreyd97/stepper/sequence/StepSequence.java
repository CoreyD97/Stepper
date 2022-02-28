package com.coreyd97.stepper.sequence;

import burp.IHttpRequestResponse;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.sequence.listener.SequenceExecutionListener;
import com.coreyd97.stepper.sequence.view.SequenceContainer;
import com.coreyd97.stepper.sequence.view.StepSequenceTab;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;
import com.coreyd97.stepper.variable.PreExecutionStepVariable;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.step.listener.StepListener;
import com.coreyd97.stepper.step.view.StepPanel;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Vector;

public class StepSequence
{
    private String title;
    private boolean isExecuting; //Ew. Let's fix this later. Temp fix for shortcuts.
    private VariableManager globalVariablesManager;
    private Vector<Step> steps;
    private final ArrayList<StepListener> stepListeners;
    private final ArrayList<SequenceExecutionListener> sequenceExecutionListeners;

    public StepSequence(String title){
        this.steps = new Vector<>();
        this.stepListeners = new ArrayList<>();
        this.globalVariablesManager = new GlobalVariableManager(this);
        this.sequenceExecutionListeners = new ArrayList<>();
        this.title = title;
    }

    public StepSequence(){
        this("Step Sequence");
    }

    public void executeBlocking(){
        if(this.isExecuting) return; //Sequence already being executed.
        this.isExecuting = true;
        try {
            synchronized (StepSequence.this) {
                StepSequenceTab tabUI = Stepper.getUI().getTabForStepManager(this);
                SequenceContainer sequenceContainer = tabUI.getStepsContainer();

                for (SequenceExecutionListener stepListener : this.sequenceExecutionListeners) {
                    stepListener.beforeSequenceStart(this.steps);
                }
                for (Step step : this.steps) {
                    //Since we can't add a listener to the messageEditors, we must update
                    //Our request content before executing instead :(
                    StepPanel panel = sequenceContainer.getPanelForStep(step);
                    step.setRequestBody(panel.getRequestEditor().getMessage());

                    if (!step.isReadyToExecute()) {
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
                        StepPanel panel = sequenceContainer.getPanelForStep(step);
                        sequenceContainer.setActivePanel(panel);
                        List<StepVariable> rollingReplacements = this.getRollingVariablesUpToStep(step);

                        //Execute the step
                        StepExecutionInfo stepExecutionInfo = step.executeStep(rollingReplacements);
                        this.sequenceExecutionListeners.forEach(listener -> listener.sequenceStepExecuted(stepExecutionInfo));
                    }
                    sequenceSuccess = true;
                } catch (SequenceCancelledException e) {
                    //User cancelled. Ignore it.
                } catch (SequenceExecutionException e) {
                    JOptionPane.showMessageDialog(Stepper.getUI().getUiComponent(), e.getMessage(),
                            "Sequence Stopped", JOptionPane.ERROR_MESSAGE);
                }
                for (SequenceExecutionListener stepLExecutionistener : sequenceExecutionListeners) {
                    stepLExecutionistener.afterSequenceEnd(sequenceSuccess);
                }
            }
        }finally {
            this.isExecuting = false;
        }
    }

    public void executeAsync(){
        new Thread(() -> executeBlocking()).start();
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

    public void addStep(IHttpRequestResponse requestResponse) {
        Step step = new Step(this);
        step.setRequestBody(requestResponse.getRequest());
        step.setResponseBody(requestResponse.getResponse());
        step.setHttpService(requestResponse.getHttpService());
        addStep(step);
    }

    public void stepModified(Step step){
        for (StepListener stepListener : this.stepListeners) {
            stepListener.onStepUpdated(step);
        }
    }

    public void removeStep(Step step) {
        if(!this.steps.remove(step)) throw new IllegalArgumentException("Step not valid for sequence");
        for (StepListener stepListener : this.stepListeners) {
            stepListener.onStepRemoved(step);
        }
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

    /**
     * Returns all variables, if a variable is overwritten in a later step.
     * Only includes the latest instance
     * @return List of all variables
     */
    public List<StepVariable> getRollingVariablesForWholeSequence() {
        return getRollingVariablesUpToStep(null); //Null for whole sequence
    }

    /**
     * Returns all pre and post variables up to the given step, and the pre variables of the step.
     * If a variable is overwritten in a later step, only includes the latest instance.
     * @return List of all variables
     */
    public List<StepVariable> getRollingVariablesUpToStep(Step uptoStep){
        LinkedHashMap<String, StepVariable> rolling = new LinkedHashMap<>();
        for (StepVariable variable : this.globalVariablesManager.getVariables()) {
            rolling.put(variable.getIdentifier(), variable);
        }

        for (Step step : this.steps) {
            if(uptoStep == step){
                for (PreExecutionStepVariable preExecutionVariable : step.getVariableManager().getPreExecutionVariables()) {
                    rolling.put(preExecutionVariable.getIdentifier(), preExecutionVariable);
                }
                break;
            }
            for (StepVariable variable : step.getVariableManager().getVariables()) {
                rolling.put(variable.getIdentifier(), variable);
            }
        }

        return new ArrayList<>(rolling.values());
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

    public VariableManager getGlobalVariableManager() {
        return this.globalVariablesManager;
    }
}

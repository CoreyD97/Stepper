package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.variable.listener.StepVariableListener;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public abstract class VariableManager {
    protected final List<StepVariable> variables;
    protected final List<StepVariableListener> variableListeners;

    public VariableManager(){
        this.variables = new ArrayList<>();
        this.variableListeners = new ArrayList<>();
    }

    public List<StepVariable> getVariables() {
        return variables;
    }

    public List<PostExecutionStepVariable> getPostExecutionVariables(){
        return variables.stream()
            .filter(var -> var instanceof PostExecutionStepVariable)
            .map(stepVariable -> (PostExecutionStepVariable) stepVariable)
            .collect(Collectors.toList());
    }

    public List<PreExecutionStepVariable> getPreExecutionVariables(){
        return variables.stream()
                .filter(var -> var instanceof PreExecutionStepVariable)
                .map(stepVariable -> (PreExecutionStepVariable) stepVariable)
                .collect(Collectors.toList());
    }

    public void addVariableListener(StepVariableListener listener){
        this.variableListeners.add(listener);
    }

    public void removeVariableListener(StepVariableListener listener){
        this.variableListeners.remove(listener);
    }

    public void addVariable(StepVariable variable){
        this.variables.add(variable);
        variable.setVariableManager(this);
        for (StepVariableListener listener : this.variableListeners) {
            try {
                listener.onVariableAdded(variable);
            }catch (Exception ignored){}
        }
    }

    public void removeVariable(StepVariable variable){
        this.variables.remove(variable);
        variable.setVariableManager(null);
        for (StepVariableListener listener : this.variableListeners) {
            try {
                listener.onVariableRemoved(variable);
            }catch (Exception ignored){}
        }
    }

    public void onVariableChange(StepVariable variable){
        for (StepVariableListener listener : this.variableListeners) {
            try {
                listener.onVariableChange(variable);
            }catch(Exception ignored){}
        }
    }
}

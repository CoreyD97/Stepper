package com.coreyd97.stepper.sequence.globals;

import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.IStepVariableListener;

import java.util.ArrayList;
import java.util.UUID;
import java.util.Vector;

public class SequenceGlobals {
    private final Vector<StepVariable> variables;
    private final ArrayList<IStepVariableListener> variableListeners;

    public SequenceGlobals(){
        this.variables = new Vector<>();
        this.variableListeners = new ArrayList<>();
    }

    public Vector<StepVariable> getVariables() {
        return variables;
    }

    public void addVariable(){
        StepVariable var = new StepVariable();
        var.setIdentifier(UUID.randomUUID().toString());
        addVariable(var);
    }

    public void addVariable(StepVariable variable){
        this.variables.add(variable);
        for (IStepVariableListener variableListener : this.variableListeners) {
            variable.addVariableListener(variableListener);
            variableListener.onVariableAdded(variable);
        }
    }

    public void deleteVariable(int index){
        if(index == -1) return;
        StepVariable variable = this.variables.get(index);
        deleteVariable(variable);
    }

    public void deleteVariable(StepVariable variable){
        if(variable == null) return;
        this.variables.remove(variable);
        for (IStepVariableListener variableListener : this.variableListeners) {
            variableListener.onVariableRemoved(variable);
            variable.removeVariableListener(variableListener);
        }
    }

    public void addVariableListener(IStepVariableListener listener){
        this.variableListeners.add(listener);
        for (StepVariable variable : this.variables) {
            variable.addVariableListener(listener);
        }
    }

    public void removeVariableListener(IStepVariableListener listener){
        this.variableListeners.remove(listener);
        for (StepVariable variable : this.variables) {
            variable.removeVariableListener(listener);
        }
    }
}

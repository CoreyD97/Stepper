package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.util.dialog.VariableCreationDialog;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

public class PreExecVariablePanel extends VariablePanel {

    public PreExecVariablePanel(VariableManager variableManager){
        super("Pre-Execution Variables", variableManager);
    }

    @Override
    void createVariableTable() {
        this.variableTable = new PreExecutionVariableTable(this.variableManager);
    }

    @Override
    void handleAddVariableEvent() {
        VariableCreationDialog dialog = new VariableCreationDialog((Frame) SwingUtilities.getWindowAncestor(this),
                "New Variable", VariableCreationDialog.VariableType.PROMPT);
        StepVariable variable = dialog.run();
        if(variable != null) {
            this.variableManager.addVariable(variable);
        }
    }

    @Override
    void handleDeleteVariableEvent() {
        if(this.variableTable.getSelectedRow() >= 0) {
            StepVariable variable = this.variableManager.getPreExecutionVariables().get(this.variableTable.getSelectedRow());
            this.variableManager.removeVariable(variable);
        }
    }
}

package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.variable.RegexVariable;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.VariableManager;

import javax.swing.*;
import java.awt.*;

public class SequenceGlobalsControlPanel extends JPanel {

    private final VariableManager globalVariableManager;
    private final SequenceGlobalsTable variableTable;
    private JButton addVariableButton;
    private JButton deleteSelectedVariableButton;

    public SequenceGlobalsControlPanel(VariableManager globalVariableManager, SequenceGlobalsTable variableTable){
        super(new GridLayout(1, 0));
        this.globalVariableManager = globalVariableManager;
        this.variableTable = variableTable;
        this.addVariableButton = new JButton("Add Variable");
        this.addVariableButton.addActionListener(actionEvent -> {
            this.globalVariableManager.addVariable(new RegexVariable());
        });
        this.deleteSelectedVariableButton = new JButton("Delete Selected Variable");
        this.deleteSelectedVariableButton.setEnabled(false);
        this.deleteSelectedVariableButton.addActionListener(actionEvent -> {
            StepVariable variable = this.globalVariableManager.getVariables().get(this.variableTable.getSelectedRow());
            this.globalVariableManager.removeVariable(variable);
        });

        this.variableTable.getSelectionModel().addListSelectionListener(e -> {
            this.deleteSelectedVariableButton.setEnabled(this.variableTable.getSelectedRow() != -1);
        });

        this.add(this.addVariableButton);
        this.add(this.deleteSelectedVariableButton);
    }
}

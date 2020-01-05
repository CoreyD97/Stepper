package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.util.dialog.VariableCreationDialog;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

public class VariableControlPanel extends JPanel implements ListSelectionListener {

    private final VariableManager variableManager;
    private final VariableTable variableTable;
    private JButton addVariableButton;
    private JButton deleteSelectedVariableButton;

    public VariableControlPanel(VariableManager variableManager, VariableTable variableTable){
        super(new GridLayout(1, 0));
        this.variableManager = variableManager;
        this.variableTable = variableTable;
        this.addVariableButton = new JButton("Add Variable");
        this.addVariableButton.addActionListener(actionEvent -> {
            VariableCreationDialog dialog = new VariableCreationDialog((Frame) SwingUtilities.getWindowAncestor(this),
                    "New Variable");
            StepVariable variable = dialog.run();
            if(variable != null) {
                this.variableManager.addVariable(variable);
            }
        });
        this.deleteSelectedVariableButton = new JButton("Delete Selected Variable");
        this.deleteSelectedVariableButton.addActionListener(actionEvent -> {
            StepVariable variable = this.variableManager.getVariables().get(this.variableTable.getSelectedRow());
            this.variableManager.removeVariable(variable);
        });

        this.add(this.addVariableButton);
        this.add(this.deleteSelectedVariableButton);
    }


    @Override
    public void valueChanged(ListSelectionEvent listSelectionEvent) {
//        this.deleteSelectedVariableButton.setEnabled(!(listSelectionEvent.getFirstIndex() == -1
//                || listSelectionEvent.getLastIndex() == -1));
        this.deleteSelectedVariableButton.revalidate();
        this.deleteSelectedVariableButton.repaint();
    }
}

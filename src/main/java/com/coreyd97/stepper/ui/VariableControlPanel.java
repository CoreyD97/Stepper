package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.Step;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

public class VariableControlPanel extends JPanel implements ListSelectionListener {

    private final Step step;
    private final VariableTable variableTable;
    private JButton addVariableButton;
    private JButton deleteSelectedVariableButton;

    public VariableControlPanel(Step step, VariableTable variableTable){
        super(new GridLayout(1, 0));
        this.step = step;
        this.variableTable = variableTable;
        this.addVariableButton = new JButton("Add Variable");
        this.addVariableButton.addActionListener(actionEvent -> {
            this.step.addVariable();
        });
        this.deleteSelectedVariableButton = new JButton("Delete Selected Variable");
        this.deleteSelectedVariableButton.addActionListener(actionEvent -> {
            this.step.deleteVariable(this.variableTable.getSelectedRow());
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

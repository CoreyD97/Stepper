package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.SequenceGlobals;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

public class SequenceGlobalsControlPanel extends JPanel implements ListSelectionListener {

    private final SequenceGlobals sequenceGlobals;
    private final SequenceGlobalsTable variableTable;
    private JButton addVariableButton;
    private JButton deleteSelectedVariableButton;

    public SequenceGlobalsControlPanel(SequenceGlobals sequenceGlobals, SequenceGlobalsTable variableTable){
        super(new GridLayout(1, 0));
        this.sequenceGlobals = sequenceGlobals;
        this.variableTable = variableTable;
        this.addVariableButton = new JButton("Add Variable");
        this.addVariableButton.addActionListener(actionEvent -> {
            this.sequenceGlobals.addVariable();
        });
        this.deleteSelectedVariableButton = new JButton("Delete Selected Variable");
        this.deleteSelectedVariableButton.enable(false);
        this.deleteSelectedVariableButton.addActionListener(actionEvent -> {
            this.sequenceGlobals.deleteVariable(this.variableTable.getSelectedRow());
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

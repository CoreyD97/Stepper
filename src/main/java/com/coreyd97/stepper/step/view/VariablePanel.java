package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.variable.VariableManager;

import javax.swing.*;
import java.awt.*;

public abstract class VariablePanel extends JPanel {

    protected final VariableManager variableManager;
    protected JTable variableTable;

    VariablePanel(String title, VariableManager variableManager){
        this.setLayout(new BorderLayout());
        this.variableManager = variableManager;
        createVariableTable();

        JPanel controlPanel = new JPanel(new GridLayout(1, 0));
        JButton addVariableButton = new JButton("Add Variable");
        addVariableButton.addActionListener(actionEvent -> {
            handleAddVariableEvent();
        });
        JButton deleteSelectedVariableButton = new JButton("Delete Selected Variable");
        deleteSelectedVariableButton.addActionListener(actionEvent -> {
            handleDeleteVariableEvent();
        });

        controlPanel.add(addVariableButton);
        controlPanel.add(deleteSelectedVariableButton);

        if(title != null) {
            JLabel label = new JLabel(title);
            label.setFont(label.getFont().deriveFont(label.getFont().getSize()+4).deriveFont(Font.BOLD));
            label.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 0));
            this.add(label, BorderLayout.NORTH);
        }

        this.add(new JScrollPane(this.variableTable), BorderLayout.CENTER);
        this.add(controlPanel, BorderLayout.SOUTH);

        this.setPreferredSize(new Dimension(300,150));
    }

    abstract void createVariableTable();
    abstract void handleAddVariableEvent();
    abstract void handleDeleteVariableEvent();
}

package com.coreyd97.stepper.util.dialog;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.variable.PromptVariable;
import com.coreyd97.stepper.variable.RegexVariable;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.UUID;

public class VariableCreationDialog extends JDialog {

    public enum VariableType { PROMPT, REGEX }
    StepVariable variable;

    public VariableCreationDialog(Frame owner, String title, VariableType type){
        super(owner, title, true);
        this.setLocation(owner.getLocation());
        buildDialog(type);
        pack();
    }

    private void buildDialog(VariableType type){
        BorderLayout borderLayout = new BorderLayout();
        borderLayout.setHgap(10);
        borderLayout.setVgap(10);
        JPanel wrapper = new JPanel(borderLayout);
        wrapper.setBorder(BorderFactory.createEmptyBorder(7,7,7,7));
        JLabel variableNameLabel = new JLabel("Variable Name: ");
        JTextField variableNameInput = new JTextField("");
        JPanel namePanel = new JPanel(new BorderLayout());
        namePanel.add(variableNameLabel, BorderLayout.WEST);
        namePanel.add(variableNameInput, BorderLayout.CENTER);
        wrapper.add(namePanel, BorderLayout.NORTH);

//        JLabel typeLabel = new JLabel("Type: ");
//        JComboBox<VariableType> typeCombo = new JComboBox<>(VariableType.values());
//        JPanel typePanel = new JPanel(new BorderLayout());
//        typePanel.add(typeLabel, BorderLayout.WEST);
//        typePanel.add(typeCombo, BorderLayout.CENTER);
//        wrapper.add(typePanel, BorderLayout.CENTER);

        JButton okButton = new JButton("OK");
        okButton.addActionListener(actionEvent -> {
            //todo Nicer way of constructing variables with support for different types once implemented.
            String variableName = variableNameInput.getText();
            if(variableName.equalsIgnoreCase("")){
                variableName = UUID.randomUUID().toString();
            }
            switch (type) {
                case PROMPT:
                    variable = new PromptVariable(variableName);
                    break;
                case REGEX:
                    variable = new RegexVariable(variableName);
                    break;
            }
            this.setVisible(false);
        });

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(actionEvent -> {
            this.variable = null;
            this.setVisible(false);
        });

        okButton.setMinimumSize(new Dimension(100,35));
        okButton.setPreferredSize(new Dimension(100,35));
        cancelButton.setMinimumSize(new Dimension(100,35));
        cancelButton.setPreferredSize(new Dimension(100,35));

        JPanel controlPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.weightx = 100;
        controlPanel.add(new JPanel(), gbc);
        gbc.weightx = 0;
        controlPanel.add(okButton, gbc);
        controlPanel.add(cancelButton, gbc);
        wrapper.add(controlPanel, BorderLayout.SOUTH);
        this.add(wrapper);
    }

    public StepVariable run(){
        this.setVisible(true);
        return this.variable;
    }

}

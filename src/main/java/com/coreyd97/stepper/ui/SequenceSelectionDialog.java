package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.StepSequence;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class SequenceSelectionDialog extends JDialog {

    private final ArrayList<StepSequence> allSequences;
    private ArrayList<StepSequence> selectedSequences;
    private SequenceSelectionTable sequenceSelectionTable;

    public SequenceSelectionDialog(Frame owner, String title, ArrayList<StepSequence> sequences){
        super(owner, title, true);
        this.allSequences = sequences;

        buildDialog();
        pack();
    }

    private void buildDialog(){
        BorderLayout borderLayout = new BorderLayout();
        borderLayout.setHgap(10);
        borderLayout.setVgap(10);
        JPanel wrapper = new JPanel(borderLayout);
        wrapper.setBorder(BorderFactory.createEmptyBorder(7,7,7,7));
        wrapper.add(new JLabel("Select sequences to include: "), BorderLayout.NORTH);

        this.sequenceSelectionTable = new SequenceSelectionTable(this.allSequences);
        wrapper.add(new JScrollPane(this.sequenceSelectionTable), BorderLayout.CENTER);

        JButton okButton = new JButton("OK");
        okButton.addActionListener(actionEvent -> {
            selectedSequences = this.sequenceSelectionTable.getSelectedSequences();
            this.setVisible(false);
        });

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(actionEvent -> {
            selectedSequences = null;
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

    public ArrayList<StepSequence> run(){
        this.setVisible(true);
        return this.selectedSequences;
    }
}

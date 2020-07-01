package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.variable.VariableManager;

import javax.swing.*;
import java.awt.*;

public class SequenceGlobalsPanel extends JPanel {

    private final StepSequence sequence;
    private final VariableManager globalVariableManager;


    public SequenceGlobalsPanel(StepSequence stepSequence){
        this.sequence = stepSequence;
        this.globalVariableManager = this.sequence.getGlobalVariableManager();
        buildPanel();
    }

    private void buildPanel() {
        //Build panel here
        this.setLayout(new BorderLayout());
        SequenceGlobalsTable table = new SequenceGlobalsTable(this.globalVariableManager);
        this.add(new JScrollPane(table), BorderLayout.CENTER);
        this.add(new SequenceGlobalsControlPanel(this.globalVariableManager, table), BorderLayout.SOUTH);
    }


}

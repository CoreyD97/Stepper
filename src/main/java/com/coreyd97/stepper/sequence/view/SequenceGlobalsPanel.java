package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.sequence.globals.SequenceGlobals;
import com.coreyd97.stepper.sequence.StepSequence;

import javax.swing.*;
import java.awt.*;

public class SequenceGlobalsPanel extends JPanel {

    private final StepSequence sequence;
    private final SequenceGlobals globals;


    public SequenceGlobalsPanel(StepSequence stepSequence){
        this.sequence = stepSequence;
        this.globals = this.sequence.getSequenceGlobals();
        buildPanel();
    }

    private void buildPanel() {
        //Build panel here
        this.setLayout(new BorderLayout());
        SequenceGlobalsTable table = new SequenceGlobalsTable(this.globals);
        this.add(new JScrollPane(table), BorderLayout.CENTER);
        this.add(new SequenceGlobalsControlPanel(this.globals, table), BorderLayout.SOUTH);
    }


}

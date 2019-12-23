package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.view.StepPanel;

import javax.swing.*;
import java.awt.*;
import java.util.Vector;

public class StepSequenceTab extends JPanel {
    private final StepSequence stepSequence;

    private StepContainer stepsContainer;
    private ControlPanel controlPanel;

    public StepSequenceTab(StepSequence stepSequence){
        super(new BorderLayout());
        this.stepSequence = stepSequence;
        this.stepsContainer = new StepContainer(this.stepSequence);
        this.controlPanel = new ControlPanel(this.stepSequence);
        add(this.stepsContainer, BorderLayout.CENTER);
        add(this.controlPanel, BorderLayout.SOUTH);
    }

    public StepContainer getStepsContainer() {
        return stepsContainer;
    }

    public StepPanel getSelectedStepPanel(){
        return stepsContainer.getSelectedStepPanel();
    }

    public StepSequence getStepSequence() {
        return this.stepSequence;
    }
}

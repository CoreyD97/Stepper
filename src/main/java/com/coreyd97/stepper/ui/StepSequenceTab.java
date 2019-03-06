package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.StepSequence;

import javax.swing.*;
import java.awt.*;
import java.util.Vector;

public class StepSequenceTab extends JPanel {
    private final StepSequence stepSequence;

    private JSplitPane stepperPanel;
    private StepContainer stepsContainer;
    private ControlPanel controlPanel;

    public StepSequenceTab(StepSequence stepSequence){
        super(new BorderLayout());
        this.stepSequence = stepSequence;
        this.stepperPanel = buildMainTabPanel();
        add(this.stepperPanel, BorderLayout.CENTER);
    }

    private JSplitPane buildMainTabPanel(){
        this.stepsContainer = new StepContainer(this.stepSequence);
        this.controlPanel = new ControlPanel(this.stepSequence);
        JSplitPane stepperPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, this.stepsContainer, this.controlPanel);
        stepperPanel.setResizeWeight(0.99);
        return stepperPanel;
    }

    public StepContainer getStepsContainer() {
        return stepsContainer;
    }

    public StepPanel getSelectedStepPanel(){
        return stepsContainer.getSelectedStepPanel();
    }

    public Vector<StepPanel> getEntryPanels(){
        return this.stepsContainer.getStepPanels();
    }

    public StepSequence getStepSequence() {
        return this.stepSequence;
    }
}

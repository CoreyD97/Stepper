package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.IStepExecutionListener;
import com.coreyd97.stepper.Step;
import com.coreyd97.stepper.StepSequence;

import javax.swing.*;
import java.awt.*;

public class ControlPanel extends JPanel implements IStepExecutionListener {

    private final StepSequence stepSequence;
    private final JButton executeButton;
    private int stepsToExecute;
    private int stepsExecuted;

    public ControlPanel(StepSequence stepSequence){
        this.stepSequence = stepSequence;
        this.setLayout(new BorderLayout());

        this.executeButton = new JButton("Execute Sequence");
        this.executeButton.addActionListener(actionEvent -> {
            this.stepSequence.executeSteps();
        });

        add(executeButton, BorderLayout.CENTER);
        this.stepSequence.addStepExecutionListener(this);
    }

    @Override
    public void beforeFirstStep(int totalSteps) {
        this.stepsToExecute = totalSteps;
        this.stepsExecuted = 0;
        this.executeButton.setEnabled(false);
        this.executeButton.setText("Executing... (" + stepsExecuted + "/" + stepsToExecute + ")");
    }

    @Override
    public void stepExecuted(Step step) {
        this.stepsExecuted++;
        this.executeButton.setText("Executing... (" + stepsExecuted + "/" + stepsToExecute + ")");
    }

    @Override
    public void afterLastStep() {
        this.executeButton.setEnabled(true);
        this.executeButton.setText("Execute Sequence");
    }
}

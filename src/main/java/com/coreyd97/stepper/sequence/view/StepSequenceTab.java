package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.Globals;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.view.StepPanel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class StepSequenceTab extends JPanel {
    private final StepSequence stepSequence;

    private SequenceContainer stepsContainer;
    private ControlPanel controlPanel;

    public StepSequenceTab(StepSequence stepSequence){
        super(new BorderLayout());
        this.stepSequence = stepSequence;
        this.stepsContainer = new SequenceContainer(this.stepSequence);
        this.controlPanel = new ControlPanel(this.stepSequence);
        add(this.stepsContainer, BorderLayout.CENTER);
        add(this.controlPanel, BorderLayout.SOUTH);

        ActionMap actionMap = getActionMap();
        actionMap.put("ExecuteSequence", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                //Execute sequence
                if(Stepper.getPreferences().getSetting(Globals.PREF_ENABLE_SHORTCUT)){
                    SwingUtilities.invokeLater(stepSequence::executeAsync);
                }
            }
        });

        InputMap inputMap = getInputMap(WHEN_IN_FOCUSED_WINDOW);
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_G, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK), "ExecuteSequence");
    }

    public SequenceContainer getStepsContainer() {
        return stepsContainer;
    }

    public StepPanel getSelectedStepPanel(){
        return stepsContainer.getSelectedStepPanel();
    }

    public StepSequence getStepSequence() {
        return this.stepSequence;
    }
}

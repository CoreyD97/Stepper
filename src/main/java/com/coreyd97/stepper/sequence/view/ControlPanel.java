package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.sequence.listener.SequenceExecutionListener;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;
import com.coreyd97.stepper.sequence.StepSequence;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.List;
import java.util.concurrent.*;
import java.text.NumberFormat;
import javax.swing.text.NumberFormatter;
import javax.swing.JFormattedTextField;

public class ControlPanel extends JPanel implements SequenceExecutionListener {

    private final StepSequence stepSequence;
    private final JButton executeButton;
    private final JButton cancelButton;
    private final JFormattedTextField timer;
    private final JFormattedTextField delay;
    private int stepsToExecute;
    private int stepsExecuted;
    private int input;
    private int stepdelay;
    private String sequenceText = "Sequence Delay";
    private String stepText = "Step Delay";
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private ScheduledFuture<?> runHandle;
    private NumberFormat format = NumberFormat.getInstance();
    private NumberFormatter formatter = null;
    private JPanel inputs = new JPanel();
    
    public ControlPanel(StepSequence stepSequence){
        this.format.setGroupingUsed(false);
        this.formatter = new NumberFormatter(format);
        this.formatter.setValueClass(Integer.class);
        this.formatter.setMaximum(65535);
        this.formatter.setAllowsInvalid(true);
        this.stepSequence = stepSequence;
        //switched to BoxLayout so buttons and inputs can be resized
        this.setLayout(new GridLayout()); 
        this.delay = new JFormattedTextField(this.formatter);
        this.timer = new JFormattedTextField(this.formatter);
        
        this.inputs.setLayout(new BoxLayout(this.inputs, BoxLayout.X_AXIS));
        
        //there is probably a way to get rid of the code duplication here
        //not sure if that is desired as it is only repeated twice and these
        //inputs might head in seperate directions as far as this logic is concerned
        this.timer.setText(sequenceText);
        this.timer.setFocusLostBehavior(JFormattedTextField.PERSIST);
        this.timer.setForeground(new Color(150, 150, 150));

        timer.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent arg0) {
                try {
                    input = Integer.parseInt(timer.getText());
                    if(input <= 0){
                        timer.setText(sequenceText);
                        timer.setForeground(new Color(150, 150, 150));
                    }
                } catch (final NumberFormatException e) {
                    input = 0;
                    timer.setText("");
                    timer.setForeground(new Color(0, 0, 0));
                }
            }
            @Override
            public void focusLost(FocusEvent arg0) {
                if(timer.getText().length() == 0) {
                    timer.setText(sequenceText);
                    timer.setForeground(new Color(150, 150, 150));
                }
            }
        });

        this.delay.setText(stepText);
        this.delay.setFocusLostBehavior(JFormattedTextField.PERSIST);
        this.delay.setForeground(new Color(150, 150, 150));

        delay.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent arg0) {
                try {
                    input = Integer.parseInt(delay.getText());
                    if(input <= 0){
                        delay.setText(stepText);
                        delay.setForeground(new Color(150, 150, 150));
                    }
                } catch (final NumberFormatException e) {
                    input = 0;
                    delay.setText("");
                    delay.setForeground(new Color(0, 0, 0));
                }
            }
            @Override
            public void focusLost(FocusEvent arg0) {
                if(delay.getText().length() == 0) {
                    delay.setText(stepText);
                    delay.setForeground(new Color(150, 150, 150));
                }
            }
        });
        //end duplication zone

        this.executeButton = new JButton("Execute Sequence");
        this.cancelButton = new JButton("Cancel");

        this.input = 0;

        this.executeButton.addActionListener(actionEvent -> {
            //try to get inputs
            try {
                input = Integer.parseInt(timer.getText());
                if (input <= 0){
                    timer.setText(sequenceText);
                }
            } catch (final NumberFormatException e) {
                input = 0;
                timer.setText(sequenceText);
            }
            try {
                stepdelay = Integer.parseInt(delay.getText());
                if(stepdelay <= 0){
                    delay.setText(stepText);
                }
            } catch (final NumberFormatException e) {
                stepdelay = 0;
                delay.setText(stepText);
            } 
            //execute normally
            if (this.input < 1) {
                this.stepSequence.executeAsync();
            //execute delayed
            } else {
                this.runHandle = scheduler.scheduleAtFixedRate(
                    new Runnable() {
                        @Override
                        public void run() {
                            stepSequence.executeBlocking();
                        }
                    },
                    0,
                    Integer.parseInt(this.timer.getText()),
                    TimeUnit.SECONDS);
                    this.cancelButton.setEnabled(true);
                    this.executeButton.setEnabled(false);
            }
        });

        //TODO Implement sequence cancel
        this.cancelButton.setEnabled(false);
        this.cancelButton.addActionListener(actionEvent -> {
            this.runHandle.cancel(false);
            this.cancelButton.setEnabled(false);
            this.executeButton.setEnabled(true);
        });

        //set size of inputs
        this.stepSequence.addSequenceExecutionListener(this);
        //add buttons
        inputs.add(timer);
        inputs.add(delay);
        add(inputs);
        add(executeButton);
        add(cancelButton);
    }

    @Override
    public void beforeSequenceStart(List<Step> steps) {
        this.stepsToExecute = steps.size();
        this.stepsExecuted = 0;
        this.executeButton.setEnabled(false);
        this.executeButton.setText("Executing... (" + stepsExecuted + "/" + stepsToExecute + ")");
        this.cancelButton.setEnabled(true);
    }

    @Override
    public void sequenceStepExecuted(StepExecutionInfo stepExecutionInfo) {
        try {
            Thread.sleep(this.stepdelay * 1000);
        } catch(InterruptedException ex){
            Thread.currentThread().interrupt();
        }
        this.stepsExecuted++;
        this.executeButton.setText("Executing... (" + stepsExecuted + "/" + stepsToExecute + ")");
    }

    @Override
    public void afterSequenceEnd(boolean success) {
        if (this.input < 1){
            this.cancelButton.setEnabled(false);
            this.executeButton.setEnabled(true);
        }
        // without this check the alert given on a bad step causes too many alerts with short sequence times
        if (!success){
            this.runHandle.cancel(false);
            this.cancelButton.setEnabled(false);
            this.executeButton.setEnabled(true);
        }
        this.executeButton.setText("Execute Sequence");
    }
}

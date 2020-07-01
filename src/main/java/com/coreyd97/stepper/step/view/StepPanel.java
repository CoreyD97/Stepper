package com.coreyd97.stepper.step.view;

import burp.IMessageEditor;
import com.coreyd97.stepper.*;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.sequence.view.SequenceContainer;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;
import com.coreyd97.stepper.step.listener.StepExecutionAdapter;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.StepVariableListener;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

public class StepPanel extends JPanel implements StepVariableListener {

    private final SequenceContainer sequenceContainer;
    private final Step step;

    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private JPanel topPanel;
    private JSplitPane reqRespSplitPane;
    private JLabel responseLengthLabel;
    private JLabel responseTimeLabel;

    private JTextField httpAddressField;
    private JSpinner httpPortSpinner;
    private JCheckBox httpIsSecure;

    public StepPanel(SequenceContainer sequenceContainer, Step step){
        super(new BorderLayout());
        this.sequenceContainer = sequenceContainer;
        this.step = step;

        //During message editor creation, the VariableReplacementTab will be matched with the actual
        //IHttpController implementation, not the proxy class.
        this.requestEditor = Stepper.callbacks.createMessageEditor(step, true);
        this.requestEditor.setMessage(step.getRequest(), true);
        this.responseEditor = Stepper.callbacks.createMessageEditor(step, false);
        this.responseEditor.setMessage(step.getResponse(), false);
        this.step.registerRequestEditor(this.requestEditor);
        this.step.registerResponseEditor(this.responseEditor);

        JPanel responseWrapper = new JPanel(new BorderLayout());
        JPanel responseInfoWrapper = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        responseInfoWrapper.add(new JLabel("Response Length: "));
        responseLengthLabel = new JLabel("N/A");
        responseInfoWrapper.add(responseLengthLabel);
        responseInfoWrapper.add(new JLabel(" |  Response Time: "));
        responseTimeLabel = new JLabel("N/A");
        responseInfoWrapper.add(responseTimeLabel);

        this.step.addExecutionListener(new StepExecutionAdapter(){
            @Override
            public void stepExecuted(StepExecutionInfo executionInfo) {
                String lengthMsg = String.format("%d bytes",executionInfo.getIRequestResponse().getResponse().length);
                StepPanel.this.responseLengthLabel.setText(lengthMsg);
                String timeMsg = String.format("%d ms", executionInfo.getResponseTime());
                StepPanel.this.responseTimeLabel.setText(timeMsg);
            }
        });

        responseWrapper.add(responseEditor.getComponent(), BorderLayout.CENTER);
        responseWrapper.add(responseInfoWrapper, BorderLayout.SOUTH);

        VariablePanel preExecVariablePanel = new PreExecVariablePanel(step.getVariableManager());
        JSplitPane requestSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                requestEditor.getComponent(), preExecVariablePanel);
        requestSplitPane.setResizeWeight(0.8);

        VariablePanel postExecVariablePanel = new PostExecVariablePanel(step.getVariableManager());
        JSplitPane responseSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                responseWrapper, postExecVariablePanel);
        responseSplitPane.setResizeWeight(0.8);

        //Make resizing one split pane also resize the other
        requestSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                new PropertyChangeListener() {
                    @Override
                    public void propertyChange(PropertyChangeEvent pce) {
                        responseSplitPane.setDividerLocation(requestSplitPane.getDividerLocation());
                    }
                });
        //Same as above
        responseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
                new PropertyChangeListener() {
                    @Override
                    public void propertyChange(PropertyChangeEvent pce) {
                        requestSplitPane.setDividerLocation(responseSplitPane.getDividerLocation());
                    }
                });

        this.reqRespSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestSplitPane, responseSplitPane);
        this.reqRespSplitPane.setResizeWeight(0.5);

        this.topPanel = new JPanel(new BorderLayout());
        JButton executeStepButton = new JButton("Execute Step");
        executeStepButton.addActionListener(actionEvent -> {
            new Thread(() -> {
                executeStepButton.setEnabled(false);
                try {
                    step.executeStep();
                }catch (SequenceCancelledException ignored){
                }catch (SequenceExecutionException e) {
                    JOptionPane.showMessageDialog(this, e.getMessage(),
                            "Step Error", JOptionPane.ERROR_MESSAGE);
                }catch (Exception e){
                    JOptionPane.showMessageDialog(this, e.getMessage(),
                            "Step Error", JOptionPane.ERROR_MESSAGE);
                }finally {
                    executeStepButton.setEnabled(true);
                }
            }).start();
        });
        JPanel httpServicePanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 10.0;
        gbc.gridx = gbc.gridy = 1;
        httpAddressField = new JTextField();
        httpAddressField.setText(step.getHostname());
        httpAddressField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {
                step.setHostname(httpAddressField.getText());
            }

            @Override
            public void removeUpdate(DocumentEvent documentEvent) {
                step.setHostname(httpAddressField.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                step.setHostname(httpAddressField.getText());
            }
        });
        httpServicePanel.add(httpAddressField, gbc);
        gbc.gridx++;
        gbc.weightx = 0;
        httpPortSpinner = new JSpinner(new SpinnerNumberModel(step.getPort().intValue(),1,65535,1));
        httpPortSpinner.getModel().addChangeListener(changeEvent -> this.step.setPort((Integer) httpPortSpinner.getValue()));
        httpPortSpinner.setEditor(new JSpinner.NumberEditor(httpPortSpinner,"#"));
        httpServicePanel.add(httpPortSpinner, gbc);
        gbc.gridx++;
        httpServicePanel.add(Box.createHorizontalStrut(25), gbc);
        gbc.gridx++;
        httpServicePanel.add(new JLabel("Is HTTPS"), gbc);
        gbc.gridx++;
        httpIsSecure = new JCheckBox();
        httpIsSecure.setSelected(step.isSSL());
        httpIsSecure.addChangeListener(changeEvent -> this.step.setSSL(httpIsSecure.isSelected()));
        httpServicePanel.add(httpIsSecure, gbc);
        gbc.gridx++;
        httpServicePanel.add(Box.createHorizontalStrut(25), gbc);

        this.topPanel.add(executeStepButton, BorderLayout.EAST);
        this.topPanel.add(httpServicePanel, BorderLayout.CENTER);

        this.add(topPanel, BorderLayout.NORTH);
        this.add(reqRespSplitPane, BorderLayout.CENTER);
        this.setPreferredSize(new Dimension(450, 0));
        this.setMaximumSize(new Dimension(450, 0));
        this.setMinimumSize(new Dimension(450, 0));
        this.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLoweredBevelBorder(), BorderFactory.createRaisedBevelBorder()));

        this.revalidate();
        this.repaint();
    }

    public IMessageEditor getRequestEditor() {
        return requestEditor;
    }

    public IMessageEditor getResponseEditor() {
        return responseEditor;
    }

    public void refreshRequestPanel() {
        //Reload the request viewer content. (Updates the With Replacements Tab!)
        this.requestEditor.setMessage(this.step.getRequest(), true);
    }

    public Step getStep() {
        return step;
    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        this.sequenceContainer.updateSubsequentPanels(this);
    }

    @Override
    public void onVariableRemoved(StepVariable variable) {
        this.sequenceContainer.updateSubsequentPanels(this);
    }

    @Override
    public void onVariableChange(StepVariable variable) {
        this.sequenceContainer.updateSubsequentPanels(this);
    }
}

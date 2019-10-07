package com.coreyd97.stepper;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import com.coreyd97.stepper.ui.StepPanel;
import com.coreyd97.stepper.ui.StepSequenceTab;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {

    private final Stepper stepper;

    public ContextMenuFactory(Stepper stepper){
        this.stepper = stepper;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if(messages.length != 1) return null;

        ArrayList<JMenuItem> menuItems = new ArrayList<>();
        JMenu addStepMenu = new JMenu("Add to Stepper");

        this.stepper.getUI().getAllStepSetTabs().forEach((title, stepSequenceTab) -> {
            JMenuItem item = new JMenuItem(title);
            item.addActionListener(actionEvent -> {
                stepSequenceTab.getStepSequence().addStep(messages[0]);
            });
            addStepMenu.add(item);
        });

        JMenuItem newSequence = new JMenuItem("New Sequence");
        newSequence.addActionListener(actionEvent -> {
            String name = JOptionPane.showInputDialog(Stepper.getInstance().getUI().getUiComponent(), "Enter a name to identify the sequence: ", "", JOptionPane.PLAIN_MESSAGE);
            if(name != null) {
                StepSequence stepSequence = new StepSequence(this.stepper, false, name);
                stepSequence.addStep(messages[0]);
                this.stepper.addStepSequence(stepSequence);
            }
        });

        addStepMenu.add(new JPopupMenu.Separator());
        addStepMenu.add(newSequence);

        menuItems.add(addStepMenu);

        if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            HashMap<String, StepVariable> usableVariables = null;

            StepSequenceTab selectedStepSet = stepper.getUI().getSelectedStepSet();
            if(selectedStepSet != null){
                StepPanel selectedStepPanel = selectedStepSet.getSelectedStepPanel();
                if(selectedStepPanel != null){
                    Step step = selectedStepPanel.getStep();
                    usableVariables = selectedStepSet.getStepSequence().getRollingVariables(step);
                }
            }else{
                //Message editor of another tool. Show all variables!
                usableVariables = new HashMap<>();
                for (StepSequence sequence : stepper.getSequences()) {
                    usableVariables.putAll(sequence.getAllVariables());
                }
            }

            if(usableVariables != null && usableVariables.size() > 0) {
                JMenu addStepVariableMenu = new JMenu("Add Stepper Variable To Clipboard");
                JMenu insertVariable = new JMenu("Insert Stepper Variable At Cursor (NOT IMPLEMENTED)");
                usableVariables.forEach((identifier, variable) -> {
                    JMenuItem variableEntry = new JMenuItem(identifier);
                    variableEntry.addActionListener(actionEvent -> {
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                                new StringSelection(variable.createVariableString()), null);
                    });
                    addStepVariableMenu.add(variableEntry);

                    variableEntry = new JMenuItem(identifier);
                    variableEntry.addActionListener(actionEvent -> {
                        Object source = invocation.getInputEvent().getSource();
                        if(source instanceof JComponent){
                            System.out.println(((JTextComponent) source).getText());
                        }
                    });
                    insertVariable.add(variableEntry);
                });
                menuItems.add(addStepVariableMenu);
                //Not implemented yet.
                //menuItems.add(insertVariable);
            }
        }
        return menuItems;
    }
}

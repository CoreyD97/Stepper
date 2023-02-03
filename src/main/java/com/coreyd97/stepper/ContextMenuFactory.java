package com.coreyd97.stepper;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.view.StepPanel;
import com.coreyd97.stepper.sequence.view.StepSequenceTab;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

public class ContextMenuFactory implements IContextMenuFactory {

    private final SequenceManager sequenceManager;

    public ContextMenuFactory(SequenceManager sequenceManager){
        this.sequenceManager = sequenceManager;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if(messages.length == 0) return null;
        ArrayList<JMenuItem> menuItems = new ArrayList<>();

        //Add x items to Stepper menu
        String addMenuTitle = String.format("Add %d %s to Stepper", messages.length, messages.length == 1 ? "item":"items");
        JMenu addStepMenu = new JMenu(addMenuTitle);

        for (StepSequence sequence : this.sequenceManager.getSequences()) {
            JMenuItem item = new JMenuItem(sequence.getTitle());
            item.addActionListener(actionEvent -> {
                for (IHttpRequestResponse message : messages) {
                    sequence.addStep(message);
                }
            });
            addStepMenu.add(item);
        }

        JMenuItem newSequence = new JMenuItem("New Sequence");
        newSequence.addActionListener(actionEvent -> {
            String name = JOptionPane.showInputDialog(Stepper.getUI().getUiComponent(), "Enter a name to identify the sequence: ", "", JOptionPane.PLAIN_MESSAGE);
            if(name != null) {
                StepSequence stepSequence = new StepSequence(name);
                for (IHttpRequestResponse message : messages) {
                    stepSequence.addStep(message);
                }
                this.sequenceManager.addStepSequence(stepSequence);
            }
        });

        addStepMenu.add(new JPopupMenu.Separator());
        addStepMenu.add(newSequence);

        menuItems.add(addStepMenu);

        if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            menuItems.addAll(buildCopyHeaderMenuItems(invocation));
            menuItems.addAll(buildVariableMenuItems(invocation));
        }
        return menuItems;
    }

    private List<JMenuItem> buildCopyHeaderMenuItems(IContextMenuInvocation invocation){
        List<JMenuItem> menuItems = new ArrayList<>();

        JMenu addStepHeaderToClipboardMenu = new JMenu("Copy Header To Clipboard");

        for (StepSequence stepSequence : sequenceManager.getSequences()) {
            JMenu sequenceItem = new JMenu(stepSequence.getTitle());

            JMenuItem execBeforeMenuItem = new JMenuItem("Execute-Before Header");
            execBeforeMenuItem.addActionListener(actionEvent -> {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(MessageProcessor.EXECUTE_BEFORE_HEADER+": " + stepSequence.getTitle()), null);
            });
            sequenceItem.add(execBeforeMenuItem);

            JMenuItem execAfterMenuItem = new JMenuItem("Execute-After Header");
            execAfterMenuItem.addActionListener(actionEvent -> {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(MessageProcessor.EXECUTE_AFTER_HEADER+": " + stepSequence.getTitle()), null);
            });
            sequenceItem.add(execAfterMenuItem);

            addStepHeaderToClipboardMenu.add(sequenceItem);
        }

        menuItems.add(addStepHeaderToClipboardMenu);

        return menuItems;
    }

    private List<JMenuItem> buildVariableMenuItems(IContextMenuInvocation invocation){
        List<JMenuItem> menuItems = new ArrayList<>();

        HashMap<StepSequence, List<StepVariable>> sequenceVariableMap = new HashMap<>();

        StepSequenceTab selectedStepSet = Stepper.getUI().getSelectedStepSet();
        boolean isViewingSequenceStep = false;
        if(selectedStepSet != null){
            StepPanel selectedStepPanel = selectedStepSet.getSelectedStepPanel();
            if(selectedStepPanel != null){
                isViewingSequenceStep = true;
                Step step = selectedStepPanel.getStep();
                List<StepVariable> stepVariables = selectedStepSet.getStepSequence().getRollingVariablesUpToStep(step);
                sequenceVariableMap.put(step.getSequence(), stepVariables);
            }
        }else{
            //Message editor of another tool. Show all variables!
            sequenceVariableMap = sequenceManager.getRollingVariablesFromAllSequences();
        }

        long varCount = sequenceVariableMap.values().stream().mapToInt(List::size).sum();

        if(varCount > 0) {
            JMenu addStepVariableToClipboardMenu = new JMenu("Copy Variable To Clipboard");
            //JMenuItem insertVariable = new JMenuItem("Insert Stepper Variable At Cursor (NOT POSSIBLE TO IMPLEMENT)");

            if(isViewingSequenceStep){ //Only variables from a single sequence step
                Collection<StepVariable> variables = sequenceVariableMap.values().stream()
                        .flatMap(Collection::stream).collect(Collectors.toList());

                List<JMenuItem> variableToClipboardMenuItems = buildAddVariableToClipboardMenuItems(null, variables);

                for (JMenuItem item : variableToClipboardMenuItems) {
                    addStepVariableToClipboardMenu.add(item);
                }
            }else{
                for (Map.Entry<StepSequence, List<StepVariable>> entry : sequenceVariableMap.entrySet()) {
                    StepSequence stepSequence = entry.getKey();
                    List<StepVariable> stringStepVariableHashMap = entry.getValue();
                    if (stringStepVariableHashMap.size() > 0) {
                        JMenu sequenceItem = new JMenu(stepSequence.getTitle());
                        List<JMenuItem> sequenceVariableToClipboardItems =
                                ContextMenuFactory.this.buildAddVariableToClipboardMenuItems(stepSequence, stringStepVariableHashMap);
                        for (JMenuItem item : sequenceVariableToClipboardItems) {
                            sequenceItem.add(item);
                        }
                        addStepVariableToClipboardMenu.add(sequenceItem);
                    }
                }
            }

            menuItems.add(addStepVariableToClipboardMenu);
        }
        return menuItems;
    }

    private List<JMenuItem> buildAddVariableToClipboardMenuItems(StepSequence sequence, Collection<StepVariable> variables){
        List<JMenuItem> menuItems = new ArrayList<>();
        for (StepVariable variable : variables) {
            JMenuItem item = new JMenuItem(variable.getIdentifier());
            item.addActionListener(actionEvent -> {
                String variableString;
                if(sequence == null){ //Not sequence specific
                    variableString = StepVariable.createVariableString(variable.getIdentifier());
                }else{
                    variableString = StepVariable.createVariableString(sequence.getTitle(), variable.getIdentifier());
                }
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(variableString), null);
            });
            menuItems.add(item);
        }
        return menuItems;
    }
}

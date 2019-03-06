package com.coreyd97.stepper.ui;

import com.coreyd97.BurpExtenderUtilities.CustomTabComponent;
import com.coreyd97.stepper.*;
import com.coreyd97.stepper.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.HashMap;
import java.util.Vector;
import java.util.function.Consumer;

public class StepContainer extends JPanel implements IStepListener, IStepVariableListener {

    private final StepSequence stepSequence;
    private SequenceGlobalsPanel sequenceGlobalsPanel;
    private Vector<StepPanel> stepPanels;
    private HashMap<Step, StepPanel> stepToPanelMap;
    private JTabbedPane tabbedContainer;

    private JPanel addTabOnShownPanel;

    public StepContainer(StepSequence stepSequence){
        this.setLayout(new BorderLayout());
        this.stepSequence = stepSequence;
        this.stepPanels = new Vector<>();
        this.stepToPanelMap = new HashMap<>();
        this.tabbedContainer = buildTabbedContainer();
        setupPanel();

        //Add existing panels and listen to step changes
        this.stepSequence.getSequenceGlobals().addVariableListener(this);
        this.stepSequence.addStepListener(this, true);
    }

    private void setupPanel(){
        this.removeAll();

        this.add(tabbedContainer, BorderLayout.CENTER);
    }

    private JTabbedPane buildTabbedContainer(){
        JTabbedPane tabbedPanel = new JTabbedPane();

        addTabOnShownPanel = new JPanel();
        addTabOnShownPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent componentEvent) {
                stepSequence.addStep();
            }
        });

        sequenceGlobalsPanel = new SequenceGlobalsPanel(this.stepSequence);

        tabbedPanel.addTab("Globals", sequenceGlobalsPanel);
        tabbedPanel.setSelectedIndex(0);
        tabbedPanel.addTab("Add Step", addTabOnShownPanel);

        return tabbedPanel;
    }

    private void addTabbedEntry(StepPanel stepPanel){
        int tabNumber = tabbedContainer.getTabCount(); //Do not subtract from zero. "Add tab" makes up for that.
        tabbedContainer.setSelectedIndex(0);
        int newTabLocation = tabNumber-1;
        tabbedContainer.insertTab(String.valueOf(tabNumber), null, stepPanel, null, newTabLocation);

        Step step = stepPanel.getStep();

        Consumer<String> onTitleChanged = title -> {
            step.setTitle(title);
        };

        Consumer<Void> onRemoveClicked = (nothing) -> {
            this.stepSequence.removeStep(step);
            for (int i = 1; i < tabbedContainer.getTabCount()-1; i++) {
                CustomTabComponent tab = (CustomTabComponent) tabbedContainer.getTabComponentAt(i);
                tab.setIndex(i); //Since 0 is globals tab
            }
        };

        CustomTabComponent tabComponent = new CustomTabComponent(tabbedContainer, newTabLocation,
                stepPanel.getStep().getTitle(), true,
                true, onTitleChanged,true, onRemoveClicked);
        tabbedContainer.setTabComponentAt(newTabLocation, tabComponent);

        tabbedContainer.setSelectedIndex(newTabLocation);
    }

    private void removeTabbedEntry(StepPanel stepPanel){
        tabbedContainer.setSelectedIndex(0);
        tabbedContainer.remove(stepPanel);
        for (int i = 1; i < tabbedContainer.getTabCount(); i++) {
            if(!tabbedContainer.getComponentAt(i).equals(addTabOnShownPanel)) {
                tabbedContainer.setTitleAt(i, String.valueOf(i+1));
            }
        }
    }

    private void addStepPanel(StepPanel stepPanel){
        this.stepPanels.add(stepPanel);
        addTabbedEntry(stepPanel);
        this.revalidate();
        this.repaint();
    }

    private void removeStepPanel(StepPanel stepPanel){
        if(!this.stepPanels.contains(stepPanel)) return;
        this.stepPanels.remove(stepPanel);
        removeTabbedEntry(stepPanel);
        this.revalidate();
        this.repaint();
    }

    public Vector<StepPanel> getStepPanels() {
        return stepPanels;
    }

    public StepPanel getPanelForStep(Step step){
        return this.stepToPanelMap.get(step);
    }

    @Override
    public void onStepAdded(Step step) {
        //Build and add panel for step
        StepPanel panel = new StepPanel(stepSequence, step);
        this.stepToPanelMap.put(step, panel);
        addStepPanel(panel);
        step.addVariableListener(this);
    }

    @Override
    public void onStepRemoved(Step step) {
        //Get panel for step and dispose panel
        StepPanel panel = this.stepToPanelMap.remove(step);
        if(panel != null){
            removeStepPanel(panel);
        }
        step.removeVariableListener(this);
        updateSubsequentPanels(panel);
    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        updateSubsequentPanels(this.stepToPanelMap.get(stepSequence.getOriginatingStep(variable)));
    }

    @Override
    public void onVariableRemoved(StepVariable variable) {
        updateSubsequentPanels(this.stepToPanelMap.get(stepSequence.getOriginatingStep(variable)));
    }

    @Override
    public void onVariableChange(StepVariable variable, StepVariable.ChangeType origin) {
        Step originatingStep = stepSequence.getOriginatingStep(variable);
        if(originatingStep != null)
            updateSubsequentPanels(this.stepToPanelMap.get(stepSequence.getOriginatingStep(variable)));
        else
            updateAllPanels();
    }

    private void updateSubsequentPanels(StepPanel panel){
        int fromPanel = this.stepPanels.indexOf(panel);
        if(fromPanel == -1) return;
        for (fromPanel+=1; fromPanel < this.stepPanels.size(); fromPanel++) {
            //Loop over panels after the variables origin and update.
            this.stepPanels.get(fromPanel).refreshRequestPanel();
        }
    }

    private void updateAllPanels(){
        for (StepPanel stepPanel : this.stepPanels) {
            stepPanel.refreshRequestPanel();
        }
    }

    public StepPanel getSelectedStepPanel() {
        Component selectedTab = this.tabbedContainer.getSelectedComponent();
        if(selectedTab instanceof StepPanel){
            return (StepPanel) selectedTab;
        }
        return null;
    }
}

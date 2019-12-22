package com.coreyd97.stepper.ui;

import com.coreyd97.BurpExtenderUtilities.CustomTabComponent;
import com.coreyd97.stepper.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Vector;
import java.util.function.Consumer;

public class StepContainer extends JPanel implements IStepListener, IStepVariableListener {

    private final StepSequence stepSequence;
    private SequenceGlobalsPanel sequenceGlobalsPanel;
    private Vector<StepPanel> stepPanels;
    private HashMap<Step, StepPanel> stepToPanelMap;
    private JTabbedPane tabbedContainer;

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

        sequenceGlobalsPanel = new SequenceGlobalsPanel(this.stepSequence);
        tabbedPanel.addTab("Globals", sequenceGlobalsPanel);
        tabbedPanel.addTab("Add Step", null);
        tabbedPanel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(SwingUtilities.isLeftMouseButton(e)){
                    stepSequence.addStep();
                }
            }
        });

        return tabbedPanel;
    }

    private void addTabForStep(Step step, StepPanel panel){
        int tabNumber = tabbedContainer.getTabCount()-1;
        tabbedContainer.insertTab(null, null, panel, null, tabNumber);

        Consumer<String> onTitleChanged = step::setTitle;

        Consumer<Void> onRemoveClicked = (nothing) -> {
            this.stepSequence.removeStep(step);
            //Update indices for other tabs
            updateTabIndices();
        };

        CustomTabComponent tabComponent = new CustomTabComponent(tabNumber,
                panel.getStep().getTitle(), true,
                true, onTitleChanged,true, onRemoveClicked);
        tabComponent.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)){
                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenu moveStep = new JMenu("Move Step");

                    int fromIndex = tabbedContainer.indexOfTabComponent(tabComponent);
                    Component tabBody = tabbedContainer.getComponentAt(fromIndex);
                    for(int i=1; i<tabbedContainer.getTabCount()-1; i++){ //Start at 1, globals is 0. Stop -1 for "add step" tab
                        final int toIndex = i;
                        if(i != fromIndex){
                            JMenuItem moveTo = new JMenuItem("Index: " + i);
                            moveTo.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent actionEvent) {
                                    tabbedContainer.insertTab(null, null, tabBody, null, toIndex);
                                    tabbedContainer.setTabComponentAt(toIndex, tabComponent);
                                    tabbedContainer.setSelectedIndex(toIndex);
                                    stepSequence.moveStep(fromIndex - 1, toIndex-1); //Take 1, since globals tab is first
                                    updateTabIndices();
                                }
                            });
                            moveStep.add(moveTo);
                        }
                    }

                    popupMenu.add(moveStep);
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        tabbedContainer.setTabComponentAt(tabNumber, tabComponent);
        tabbedContainer.setSelectedIndex(tabNumber);
    }

    private void updateTabIndices(){
        for (int i = 1; i < tabbedContainer.getTabCount()-1; i++) {
            CustomTabComponent tab = (CustomTabComponent) tabbedContainer.getTabComponentAt(i);
            tab.setIndex(i); //Since 0 is globals tab
        }
    }

    private void removeTabbedEntry(StepPanel stepPanel){
        tabbedContainer.remove(stepPanel);
        if(tabbedContainer.getSelectedIndex() == tabbedContainer.getTabCount()-1){
            //If we're now viewing the "Add Step" tab, view the previous tab instead
            tabbedContainer.setSelectedIndex(tabbedContainer.getSelectedIndex()-1);
        }
        updateTabIndices();
    }

    private void addPanelForStep(Step step, StepPanel panel){
        this.stepPanels.add(panel);
        addTabForStep(step, panel);
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

    public void setActivePanel(StepPanel stepPanel){
        this.tabbedContainer.setSelectedComponent(stepPanel);
    }

    @Override
    public void onStepAdded(Step step) {
        //Build and add panel for step
        StepPanel panel = new StepPanel(stepSequence, step);
        this.stepToPanelMap.put(step, panel);
        addPanelForStep(step, panel);
        step.addVariableListener(this);
    }

    @Override
    public void onStepUpdated(Step step) {
        //Do nothing
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
        int startIndex = this.stepPanels.indexOf(panel);
        if(startIndex == -1) return;

        for (startIndex+=1; startIndex < this.stepPanels.size(); startIndex++) {
            //Loop over panels after the variables origin and update.
            this.stepPanels.get(startIndex).refreshRequestPanel();
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

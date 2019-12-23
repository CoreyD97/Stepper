package com.coreyd97.stepper.sequence.view;

import com.coreyd97.BurpExtenderUtilities.CustomTabComponent;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.listener.StepAdapter;
import com.coreyd97.stepper.step.listener.StepListener;
import com.coreyd97.stepper.step.view.StepPanel;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.IStepVariableListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Vector;
import java.util.function.Consumer;

public class StepContainer extends JPanel implements IStepVariableListener {

    private final StepSequence stepSequence;
    private HashMap<Step, StepPanel> stepToPanelMap;
    private JTabbedPane tabbedContainer;

    public StepContainer(StepSequence stepSequence){
        super(new BorderLayout());
        this.stepSequence = stepSequence;
        this.stepToPanelMap = new HashMap<>();
        this.tabbedContainer = buildTabbedContainer();
        this.add(tabbedContainer, BorderLayout.CENTER);

        //Add panels for existing steps
        for (Step step : this.stepSequence.getSteps()) {
            addPanelForStep(step);
        }

        //Listen for new steps and changes to the sequence globals
        this.stepSequence.getSequenceGlobals().addVariableListener(this);
        this.stepSequence.addStepListener(new StepAdapter(){
            @Override
            public void onStepAdded(Step step) {
                addPanelForStep(step);
            }

            @Override
            public void onStepRemoved(Step step) {
                removePanelForStep(step);
            }
        });
    }

    private JTabbedPane buildTabbedContainer(){
        JTabbedPane tabbedPanel = new JTabbedPane();

        tabbedPanel.addTab("Globals", new SequenceGlobalsPanel(this.stepSequence));
        tabbedPanel.addTab("Add Step", null);
        CustomTabComponent addStepTab = new CustomTabComponent("Add Step");
        tabbedPanel.setTabComponentAt(1, addStepTab);
        addStepTab.addMouseListener(new MouseAdapter() {
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

    private void addPanelForStep(Step step){
        StepPanel panel = new StepPanel(stepSequence, step);
        this.stepToPanelMap.put(step, panel);
        addTabForStep(step, panel);
        step.addVariableListener(this);

        this.revalidate();
        this.repaint();
    }

    private void removePanelForStep(Step step){
        step.removeVariableListener(this);
        StepPanel panel = this.stepToPanelMap.remove(step);
        updateSubsequentPanels(panel); //Update the panels before this one is removed...
        removeTabbedEntry(panel);
        this.revalidate();
        this.repaint();
    }

    public StepPanel getPanelForStep(Step step){
        return this.stepToPanelMap.get(step);
    }

    public void setActivePanel(StepPanel stepPanel){
        this.tabbedContainer.setSelectedComponent(stepPanel);
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
        int tabIndex = this.tabbedContainer.indexOfComponent(panel) + 1;

        //Loop over panels, not including the Add Step panel
        for (; tabIndex < this.tabbedContainer.getTabCount()-1; tabIndex++) {
            //Loop over panels after the variables origin and update.
            ((StepPanel) tabbedContainer.getComponentAt(tabIndex)).refreshRequestPanel();
        }
    }

    private void updateAllPanels(){
        for (Component component : this.tabbedContainer.getComponents()) {
            if(component instanceof StepPanel) {
                ((StepPanel) component).refreshRequestPanel();
            }
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

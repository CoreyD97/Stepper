package com.coreyd97.stepper.ui;

import burp.ITab;
import com.coreyd97.BurpExtenderUtilities.CustomTabComponent;
import com.coreyd97.BurpExtenderUtilities.PopOutPanel;
import com.coreyd97.stepper.IStepSequenceListener;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.StepSequence;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.HashMap;
import java.util.function.Consumer;

public class StepperUI implements ITab, IStepSequenceListener {
    private final Stepper extension;

    private final JPanel blankPanel;
    private final JTabbedPane tabbedPane;
    private final JPanel preferencesPanel;
    private final JPanel aboutPanel;
    private final PopOutPanel popOutPanel;
    private final HashMap<StepSequence, StepSequenceTab> managerTabMap;
    int currentCount = 0;

    public StepperUI(Stepper stepper){
        this.extension = stepper;
        this.extension.addStepSequenceListener(this);

        this.tabbedPane = new JTabbedPane();
        this.blankPanel = new JPanel();
        this.blankPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent componentEvent) {
                stepper.addStepSequence(new StepSequence(extension, false));
            }
        });

        //Begin hack: Add a temp tab to prevent triggering componentShown of add tab.
        this.tabbedPane.addTab("toRemove", null);
        this.tabbedPane.addTab("Add Sequence", blankPanel);
        this.tabbedPane.setSelectedIndex(-1);
        this.tabbedPane.remove(0);
        //End hack
        this.preferencesPanel = new OptionsPanel(this.extension, this.extension.getPreferences());
        AboutPanel aboutPanel = new AboutPanel();
        this.aboutPanel = buildAboutPanel();
        this.tabbedPane.addTab("Preferences", this.preferencesPanel);
        this.tabbedPane.addTab("About", aboutPanel);
        this.popOutPanel = new PopOutPanel(this.tabbedPane, "Stepper");
        this.managerTabMap = new HashMap<>();
    }

    @Override
    public void onStepSequenceAdded(StepSequence sequence) {
        StepSequenceTab tab = new StepSequenceTab(sequence);
        currentCount++;
        this.tabbedPane.setSelectedIndex(tabbedPane.getTabCount()-1);
        managerTabMap.put(sequence, tab);
        int newTabLocation = this.tabbedPane.getTabCount()-3;
        this.tabbedPane.insertTab("", null, tab, null, newTabLocation);

        Consumer<String> onTitleChange = sequence::setTitle;

        Consumer<Void> onRemoveClicked = aVoid -> {
            this.extension.removeStepSet(sequence);
        };

        CustomTabComponent tabComponent = new CustomTabComponent( newTabLocation-1,
                sequence.getTitle(), false,
                true, onTitleChange, true, onRemoveClicked);

        this.tabbedPane.setTabComponentAt(newTabLocation, tabComponent);
        this.tabbedPane.setSelectedIndex(newTabLocation);
    }

    @Override
    public void onStepSequenceRemoved(StepSequence sequence) {
        StepSequenceTab stepSequenceTab = this.getTabForStepManager(sequence);
        int prevTab = this.tabbedPane.indexOfComponent(stepSequenceTab) - 1;
        if(prevTab != -1)
            this.tabbedPane.setSelectedIndex(prevTab);
        this.tabbedPane.remove(stepSequenceTab);
    }

    public StepSequenceTab getTabForStepManager(StepSequence manager){
        return this.managerTabMap.get(manager);
    }

    public StepSequenceTab getSelectedStepSet(){
        if(!getUiComponent().isVisible()) return null;
        Component selectedStepSet = this.tabbedPane.getSelectedComponent();
        if(selectedStepSet instanceof StepSequenceTab)
            return (StepSequenceTab) selectedStepSet;
        else
            return null;
    }

    public HashMap<String, StepSequenceTab> getAllStepSetTabs(){
        HashMap<String, StepSequenceTab> stepSets = new HashMap<>();
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            Component c = tabbedPane.getComponentAt(i);
            if(c instanceof StepSequenceTab) {
                Component tabComponent = tabbedPane.getTabComponentAt(i);
                if(tabComponent instanceof CustomTabComponent)
                    stepSets.put(((CustomTabComponent) tabComponent).getTitle(), (StepSequenceTab) c);
            }
        }
        return stepSets;
    }

    private JPanel buildAboutPanel(){
        return new JPanel();
    }

    @Override
    public String getTabCaption() {
        return "Stepper";
    }

    @Override
    public Component getUiComponent() {
        return this.popOutPanel;
    }
}

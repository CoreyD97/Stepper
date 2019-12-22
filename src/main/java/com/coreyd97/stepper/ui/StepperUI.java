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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashMap;
import java.util.function.Consumer;

public class StepperUI implements ITab, IStepSequenceListener {

    private final Stepper extension;
    private final JTabbedPane tabbedPane;
    private final JPanel preferencesPanel;
    private final PopOutPanel popOutPanel;
    private final HashMap<StepSequence, StepSequenceTab> managerTabMap;

    public StepperUI(Stepper stepper){
        this.extension = stepper;
        this.extension.addStepSequenceListener(this);

        this.tabbedPane = new JTabbedPane();
        this.tabbedPane.addTab("Add Sequence", null);
        CustomTabComponent addSequenceTabComponent = new CustomTabComponent( "Add Sequence");
        //Add mouse listener to "Add Sequence" tab
        addSequenceTabComponent.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(SwingUtilities.isLeftMouseButton(e)) {
                    stepper.addStepSequence(new StepSequence(extension, false));
                }
            }
        });
        this.tabbedPane.setTabComponentAt(0, addSequenceTabComponent);

        this.preferencesPanel = new OptionsPanel(this.extension, this.extension.getPreferences());
        this.tabbedPane.addTab("Preferences", this.preferencesPanel);
        this.tabbedPane.addTab("About", new AboutPanel());
        this.popOutPanel = new PopOutPanel(this.tabbedPane, "Stepper");
        this.managerTabMap = new HashMap<>();
    }

    @Override
    public void onStepSequenceAdded(StepSequence sequence) {
        StepSequenceTab tab = new StepSequenceTab(sequence);
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

    @Override
    public String getTabCaption() {
        return "Stepper";
    }

    @Override
    public Component getUiComponent() {
        return this.popOutPanel;
    }
}

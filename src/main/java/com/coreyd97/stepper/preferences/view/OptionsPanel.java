package com.coreyd97.stepper.preferences.view;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.Globals;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class OptionsPanel extends JPanel {

    private final SequenceManager sequenceManager;
    private final Preferences preferences;

    public OptionsPanel(SequenceManager sequenceManager){
        this.sequenceManager = sequenceManager;
        this.preferences = Stepper.getPreferences();

        buildPanel();
    }

    private void buildPanel() {
        ComponentGroup configGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Config");
        configGroup.addPreferenceComponent(preferences, Globals.PREF_UPDATE_REQUEST_LENGTH, "Automatically update the Content-Length header");
        configGroup.addPreferenceComponent(preferences, Globals.PREF_ENABLE_SHORTCUT, "Enable Shortcut (Ctrl+Shift+G)");

        ComponentGroup toolEnabledGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Allow Variables Usage");
        JCheckBox allToolsCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_ALL_TOOLS, "All Tools");
        JCheckBox proxyCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_PROXY, "Proxy");
        JCheckBox repeaterCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_REPEATER, "Repeater");
        JCheckBox intruderCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_INTRUDER, "Intruder");
        JCheckBox spiderCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_SPIDER, "Spider");
        JCheckBox scannerCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_SCANNER, "Scanner");
        JCheckBox sequencerCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_SEQUENCER, "Sequencer");
        JCheckBox extenderCheckbox = toolEnabledGroup.addPreferenceComponent(preferences, Globals.PREF_VARS_IN_EXTENDER, "Extender");

        { //Set initial states
            boolean individualEnabled = !allToolsCheckbox.isSelected();
            proxyCheckbox.setEnabled(individualEnabled);
            repeaterCheckbox.setEnabled(individualEnabled);
            intruderCheckbox.setEnabled(individualEnabled);
            spiderCheckbox.setEnabled(individualEnabled);
            scannerCheckbox.setEnabled(individualEnabled);
            sequencerCheckbox.setEnabled(individualEnabled);
            extenderCheckbox.setEnabled(individualEnabled);
        }

        allToolsCheckbox.addChangeListener(changeEvent -> {
            boolean individualEnabled = !allToolsCheckbox.isSelected();
            proxyCheckbox.setEnabled(individualEnabled);
            repeaterCheckbox.setEnabled(individualEnabled);
            intruderCheckbox.setEnabled(individualEnabled);
            spiderCheckbox.setEnabled(individualEnabled);
            scannerCheckbox.setEnabled(individualEnabled);
            sequencerCheckbox.setEnabled(individualEnabled);
            extenderCheckbox.setEnabled(individualEnabled);
        });

        GridBagConstraints constraints = toolEnabledGroup.generateNextConstraints(true);
        toolEnabledGroup.add(Box.createHorizontalStrut(175), constraints);

        ComponentGroup importGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Import Sequences");
        importGroup.add(new JButton(new AbstractAction("Import Sequences From File") {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setMultiSelectionEnabled(false);
                int result = fileChooser.showOpenDialog(OptionsPanel.this);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File openingFile = fileChooser.getSelectedFile();
                    byte[] fileContent;
                    try {
                        fileContent = Files.readAllBytes(openingFile.toPath());
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(OptionsPanel.this, "Unable to open file for reading: " + ex.getMessage(),
                                "Unable to Open File", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    importSequencesFromString(new String(fileContent), true);
                }
            }
        }));

        importGroup.add(new JButton(new AbstractAction("Import Sequences As String") {
            @Override
            public void actionPerformed(ActionEvent e) {
                JTextArea inputArea = new JTextArea();
                inputArea.setWrapStyleWord(true);
                inputArea.setLineWrap(true);
                inputArea.setEditable(true);
                JScrollPane scrollPane = new JScrollPane(inputArea);
                scrollPane.setPreferredSize(new Dimension(500, 600));
                scrollPane.setMaximumSize(new Dimension(500, Integer.MAX_VALUE));
                scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                int result = JOptionPane.showConfirmDialog(OptionsPanel.this, scrollPane,
                        "Import Sequences", JOptionPane.OK_CANCEL_OPTION);
                if(result == JOptionPane.OK_OPTION){
                    importSequencesFromString(inputArea.getText(), true);
                }
            }
        }));

        ComponentGroup exportGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Export Sequences");
        exportGroup.add(new JButton(new AbstractAction("Export Sequences To File") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String sequencesJson = exportSequencesAsString(sequenceManager.getSequences(), true);
                if(sequencesJson == null || sequencesJson.length() == 0) return;

                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setMultiSelectionEnabled(false);
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                int result = fileChooser.showSaveDialog(OptionsPanel.this);
                if(result == JFileChooser.APPROVE_OPTION){
                    File saveFile = fileChooser.getSelectedFile();
                    try {
                        Files.write(saveFile.toPath(), sequencesJson.getBytes());
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(OptionsPanel.this, "Unable to write to file: " + ex.getMessage(),
                                "Unable to Save File", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }));

        exportGroup.add(new JButton(new AbstractAction("Export Sequences As String") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String sequencesJson = exportSequencesAsString(sequenceManager.getSequences(), true);
                if(sequencesJson == null || sequencesJson.length() == 0) return;
                JTextArea selectionArea = new JTextArea();
                selectionArea.setWrapStyleWord(true);
                selectionArea.setLineWrap(true);
                selectionArea.setEditable(false);
                selectionArea.setText(sequencesJson);
                JScrollPane scrollPane = new JScrollPane(selectionArea);
                scrollPane.setPreferredSize(new Dimension(500, 600));
                scrollPane.setMaximumSize(new Dimension(500, Integer.MAX_VALUE));
                scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                JOptionPane.showMessageDialog(OptionsPanel.this, scrollPane,
                        "Exported Sequences", JOptionPane.PLAIN_MESSAGE);
            }
        }));

        PanelBuilder panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new JComponent[][]{new JComponent[]{toolEnabledGroup, importGroup},
                                                                new JComponent[]{toolEnabledGroup, exportGroup},
                                                                new JComponent[]{configGroup, configGroup}});
        panelBuilder.setAlignment(Alignment.TOPMIDDLE);
        this.add(panelBuilder.build());
    }

    /**
     * Convert json into sequences and show selection dialog for which to import
     * @param sequencesJson
     */
    private void importSequencesFromString(String sequencesJson, boolean displaySelectionDialog){
        Gson gson = Stepper.getGsonProvider().getGson();
        ArrayList<StepSequence> allSequences = null;
        try{
            allSequences = gson.fromJson(sequencesJson, new TypeToken<ArrayList<StepSequence>>(){}.getType());
        }catch (Exception e){
            //TODO Error handling
            e.printStackTrace();
        }

        if(allSequences == null || allSequences.size() == 0){
            JOptionPane.showMessageDialog(this, "Could not import sequences. " +
                    "Either the JSON is malfored or no sequences could be found in the content.", "Import Failed", JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<StepSequence> selectedSequences;
        if(displaySelectionDialog){
            SequenceSelectionDialog dialog = new SequenceSelectionDialog(
                    (Frame) SwingUtilities.getWindowAncestor(this), "Import Sequences", allSequences);
            selectedSequences = dialog.run();
        }else{
            selectedSequences = allSequences;
        }

        for (StepSequence selectedSequence : selectedSequences) {
            this.sequenceManager.addStepSequence(selectedSequence);
        }

    }

    /**
     * Show selection dialog for which sequences to export and output results as string.
     * @return
     */
    private String exportSequencesAsString(List<StepSequence> sequences, boolean displaySelectionDialog){
        List<StepSequence> selectedSequences;
        if(displaySelectionDialog){
            SequenceSelectionDialog dialog = new SequenceSelectionDialog(
                    (Frame) SwingUtilities.getWindowAncestor(this), "Export Sequences", sequences);
            selectedSequences = dialog.run();
        }else{
            selectedSequences = sequences;
        }

        if(selectedSequences == null) return "";

        Gson gson = Stepper.getGsonProvider().getGson();
        return gson.toJson(selectedSequences, new TypeToken<ArrayList<StepSequence>>(){}.getType());
    }


}

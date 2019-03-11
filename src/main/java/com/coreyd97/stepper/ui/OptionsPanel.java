package com.coreyd97.stepper.ui;

import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.Globals;
import com.coreyd97.stepper.Stepper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.coreyd97.stepper.StepSequence;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;

public class OptionsPanel extends JPanel {

    private final Stepper stepper;
    private final Preferences preferences;

    public OptionsPanel(Stepper stepper, Preferences preferences){
        this.stepper = stepper;
        this.preferences = preferences;

        buildPanel();
    }

    private void buildPanel() {
        PanelBuilder panelBuilder = new PanelBuilder(preferences);

        PanelBuilder.ComponentGroup toolEnabledGroup = panelBuilder.createComponentGroup("Allow Variables Usage");
        JCheckBox allToolsCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_ALL_TOOLS, "All Tools");
        JCheckBox proxyCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_PROXY, "Proxy");
        JCheckBox repeaterCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_REPEATER, "Repeater");
        JCheckBox intruderCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_INTRUDER, "Intruder");
        JCheckBox spiderCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_SPIDER, "Spider");
        JCheckBox scannerCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_SCANNER, "Scanner");
        JCheckBox sequencerCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_SEQUENCER, "Sequencer");
        JCheckBox extenderCheckbox = (JCheckBox) toolEnabledGroup.addSetting(Globals.PREF_VARS_IN_EXTENDER, "Extender");

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

        GridBagConstraints constraints = toolEnabledGroup.generateNextConstraints();
        toolEnabledGroup.add(Box.createHorizontalStrut(175), constraints);

        PanelBuilder.ComponentGroup importGroup = panelBuilder.createComponentGroup("Import Sequences");
        importGroup.addButton("Import Sequences From File", actionEvent -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setMultiSelectionEnabled(false);
            int result = fileChooser.showOpenDialog(this);
            if(result == JFileChooser.APPROVE_OPTION){
                File openingFile = fileChooser.getSelectedFile();
                byte[] fileContent;
                try {
                    fileContent = Files.readAllBytes(openingFile.toPath());
                }catch (IOException e){
                    JOptionPane.showMessageDialog(this, "Unable to open file for reading: " + e.getMessage(),
                            "Unable to Open File", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                importSequencesFromString(new String(fileContent), true);
            }

        });

        importGroup.addButton("Import Sequences As String", actionEvent -> {
            JTextArea inputArea = new JTextArea();
            inputArea.setWrapStyleWord(true);
            inputArea.setLineWrap(true);
            inputArea.setEditable(true);
            JScrollPane scrollPane = new JScrollPane(inputArea);
            scrollPane.setPreferredSize(new Dimension(500, 600));
            scrollPane.setMaximumSize(new Dimension(500, Integer.MAX_VALUE));
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
            int result = JOptionPane.showConfirmDialog(this, scrollPane,
                    "Import Sequences", JOptionPane.OK_CANCEL_OPTION);
            if(result == JOptionPane.OK_OPTION){
                importSequencesFromString(inputArea.getText(), true);
            }
        });

        PanelBuilder.ComponentGroup exportGroup = panelBuilder.createComponentGroup("Export Sequences");
        exportGroup.addButton("Export Sequences To File", actionEvent -> {
            String sequencesJson = exportSequencesAsString(this.stepper.getSequences(), true);
            if(sequencesJson == null || sequencesJson.length() == 0) return;

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int result = fileChooser.showSaveDialog(this);
            if(result == JFileChooser.APPROVE_OPTION){
                File saveFile = fileChooser.getSelectedFile();
                try {
                    Files.write(saveFile.toPath(), sequencesJson.getBytes());
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(this, "Unable to write to file: " + e.getMessage(),
                            "Unable to Save File", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        exportGroup.addButton("Export Sequences As String", actionEvent -> {
            String sequencesJson = exportSequencesAsString(this.stepper.getSequences(), true);
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
            JOptionPane.showMessageDialog(this, scrollPane,
                    "Exported Sequences", JOptionPane.PLAIN_MESSAGE);
        });


        JPanel builtPanel = null;
        try {
            builtPanel = panelBuilder.build(new JComponent[][]{new JComponent[]{toolEnabledGroup, importGroup},
                                                                new JComponent[]{toolEnabledGroup, exportGroup}},
                                            PanelBuilder.Alignment.TOPMIDDLE);
        } catch (Exception e) {
            builtPanel = new JPanel();
            builtPanel.add(new JLabel("Could not build the preferences panel!"));
        }
        this.add(builtPanel);
    }

    /**
     * Convert json into sequences and show selection dialog for which to import
     * @param sequencesJson
     */
    private void importSequencesFromString(String sequencesJson, boolean displaySelectionDialog){
        Gson gson = this.stepper.getGsonProvider().getGson();
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

        ArrayList<StepSequence> selectedSequences;
        if(displaySelectionDialog){
            SequenceSelectionDialog dialog = new SequenceSelectionDialog(
                    (Frame) SwingUtilities.getWindowAncestor(this), "Import Sequences", allSequences);
            selectedSequences = dialog.run();
        }else{
            selectedSequences = allSequences;
        }

        for (StepSequence selectedSequence : selectedSequences) {
            this.stepper.addStepSequence(selectedSequence);
        }

    }

    /**
     * Show selection dialog for which sequences to export and output results as string.
     * @return
     */
    private String exportSequencesAsString(ArrayList<StepSequence> sequences, boolean displaySelectionDialog){
        ArrayList<StepSequence> selectedSequences;
        if(displaySelectionDialog){
            SequenceSelectionDialog dialog = new SequenceSelectionDialog(
                    (Frame) SwingUtilities.getWindowAncestor(this), "Export Sequences", sequences);
            selectedSequences = dialog.run();
        }else{
            selectedSequences = sequences;
        }

        if(selectedSequences == null) return "";

        Gson gson = this.stepper.getGsonProvider().getGson();
        String json = gson.toJson(selectedSequences, new TypeToken<ArrayList<StepSequence>>(){}.getType());
        return json;
    }


}

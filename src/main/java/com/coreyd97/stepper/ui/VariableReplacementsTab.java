package com.coreyd97.stepper.ui;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import com.coreyd97.stepper.Step;
import com.coreyd97.stepper.StepVariable;
import com.coreyd97.stepper.*;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VariableReplacementsTab implements IMessageEditorTab {//, IStepListener, IStepVariableListener {

    private final IMessageEditorController controller;
    private final JScrollPane scrollPane;
    private final JTextPane textArea;
    private final StyledDocument document;
    private final boolean isEditable;

    private Step actualController;
    private byte[] rawRequest;

    public VariableReplacementsTab(IMessageEditorController controller, boolean isEditable){
        super();
        this.controller = controller;
        this.isEditable = isEditable;

        //Setup text area
        this.textArea = new WrappedTextPane();
        this.document = this.textArea.getStyledDocument();
        this.scrollPane = new JScrollPane(this.textArea);
        this.scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        this.scrollPane.setBorder(null);
        this.textArea.setBorder(null);
        //Setup styles
        Style defaultStyle = document.getStyle(StyleContext.DEFAULT_STYLE);
        StyleConstants.setFontFamily(defaultStyle, "DejaVu Sans Mono");
        Style highlightedStyle = document.addStyle("highlighted", null);
        StyleConstants.setFontFamily(highlightedStyle, "DejaVu Sans Mono");
        StyleConstants.setBold(highlightedStyle, true);


        if(UIManager.getLookAndFeel().getName().equalsIgnoreCase("Darcula")){
            //Dark theme
            StyleConstants.setForeground(defaultStyle, Color.WHITE);
            StyleConstants.setForeground(highlightedStyle, new Color(165, 195, 91));
        }else {
            //Light theme
            StyleConstants.setForeground(defaultStyle, Color.BLACK);
            StyleConstants.setForeground(highlightedStyle, new Color(176, 0, 192));
        }

        textArea.setEditable(false);
        textArea.setText("Due to an unknown bug, the method to set the content of this tab does not update " +
                "when content is pasted into the raw tab with no other modifications made. " +
                "Simply click to another tab and back to display the correct content.");
    }

    void setActualController(Step controller){
        this.actualController = controller;
    }

    @Override
    public String getTabCaption() {
        return "Stepper Replacements";
    }

    @Override
    public  Component getUiComponent() {
        return this.scrollPane;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest && this.isEditable;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        rawRequest = content;
        updateMessageWithReplacements(content);
    }

    @Override
    public byte[] getMessage() {
        return this.rawRequest;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return this.textArea.getSelectedText().getBytes();
    }

    public void updateMessageWithReplacements(){
        this.updateMessageWithReplacements(this.rawRequest);
    }

    private void updateMessageWithReplacements(byte[] content){
        if(content == null){
            this.textArea.setText("");
            return;
        }
        HashMap<String, StepVariable> variables;
        if(this.actualController != null){
            variables = this.actualController.getRollingVariables();
        }else{
            variables = new HashMap<>();
            for (StepSequence sequence : Stepper.getInstance().getSequences()) {
                variables.putAll(sequence.getAllVariables());
            }
        }

        String contentString = new String(content);
        try {
            replaceAndHighlight(contentString, new ArrayList<>(variables.values()));
        } catch (BadLocationException e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            textArea.setText("Sorry, something went wrong!\n\n" + sw.toString());
        }
    }

    /**
     * Custom find and replace to identify and highlight regions where replaced.
     */
    private void replaceAndHighlight(String content, ArrayList<StepVariable> variables) throws BadLocationException {
        StringBuffer output;
        String contentToSearch = content;
        ArrayList<Integer[]> highlightRanges = new ArrayList<>(); // [ Offset , Length ]
        for (StepVariable stepVariable : variables) {
            output = new StringBuffer();
            Pattern pattern = stepVariable.createIdentifierPattern();
            String replacement = stepVariable.getLatestValue() != null ? stepVariable.getLatestValue() : "";
            Matcher m = pattern.matcher(contentToSearch);
            int replacementCount = 0;
            while(m.find()){
                m.appendReplacement(output, replacement);
                //Offset also takes into account previous found instances that had been replaced.
                int foundOffset = m.start() + (replacementCount * (replacement.length() - m.group().length()));
                //Below we use offset after appending to get the length of the unescaped
                //value appended to the output.
                int foundLength = Math.abs(output.length()-foundOffset);

                replacementCount++;

                //Shift the existing ranges to accomodate the replacement.
                for (Integer[] range : highlightRanges) {
                    if(range[0] >= foundOffset){
                        range[0] = range[0] - foundLength + replacement.length();
                    }
                }

                highlightRanges.add(new Integer[]{foundOffset, foundLength});
            }
            m.appendTail(output);
            contentToSearch = output.toString();
        }

        output = new StringBuffer();
        output.append(contentToSearch);

        Style highlighted = document.getStyle("highlighted");
        Style defaultStyle = document.getStyle(StyleContext.DEFAULT_STYLE);

        highlightRanges.sort((a,b) -> {
            return a[0] - b[0];
        });

        document.remove(0, document.getLength());
        int currentOffset = 0;
        for (Integer[] highlightRange : highlightRanges) {
            document.insertString(currentOffset, output.substring(currentOffset, highlightRange[0]), defaultStyle);
            currentOffset = highlightRange[0];
            document.insertString(currentOffset, output.substring(currentOffset, currentOffset+highlightRange[1]), highlighted);
            currentOffset = highlightRange[0]+highlightRange[1];
        }
        document.insertString(currentOffset, output.substring(currentOffset, output.length()), defaultStyle);
    }
}

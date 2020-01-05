package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;
import com.coreyd97.stepper.step.StepVariableManager;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class RegexVariable extends StepVariable {

    Pattern regex = null;
    String regexString = null;

    public RegexVariable(){
        this(UUID.randomUUID().toString(), null);
    }

    public RegexVariable(String identifier){
        this(identifier, null);
    }

    public RegexVariable(String identifier, String regex){
        super(identifier);
        this.regexString = regex;
        try {
            if(regex != null) {
                this.regex = Pattern.compile(regex);
            }
        } catch (PatternSyntaxException ignored) {
        }
    }

    @Override
    public void setCondition(String regex) {
        this.regexString = regex;
        try{
            this.regex = Pattern.compile(regex, Pattern.DOTALL);
        }catch (PatternSyntaxException e){
            this.regex = null;
        }
        if(this.variableManager != null) {
            ((StepVariableManager) this.variableManager).refreshVariableFromPreviousExecution(this);
        }
        notifyChanges();
    }

    @Override
    public String getConditionText() {
        return this.regexString;
    }

    @Override
    public boolean isValid() {
        return this.regex != null;
    }

    @Override
    public void updateVariableBeforeExecution() {

    }

    @Override
    public void updateValueFromStep(Step step) {
        //TODO
    }

    @Override
    public void updateVariableAfterExecution(StepExecutionInfo executionInfo) {
        if(executionInfo == null) //Not yet been executed
            return;

        String response = new String(executionInfo.getIRequestResponse().getResponse());
        Matcher m = this.regex.matcher(response);
        if(m.find()) this.value = m.group();
        else this.value = "";

        notifyChanges();
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        DefaultTableCellRenderer defaultRenderer = new DefaultTableCellRenderer();
        Component c = defaultRenderer.getTableCellRendererComponent(table, this.regexString, isSelected, hasFocus, row, column);
        styleComponentForRegexValidity(c);
        return c;
    }

//    @Override
//    public Component getTableCellEditorComponent(JTable jTable, Object value, boolean isSelected, int row, int column) {
//        DefaultCellEditor defaultCellEditor = new DefaultCellEditor(new JTextField());
//        Component c = defaultCellEditor.getTableCellEditorComponent(jTable, this.regex.pattern(), isSelected, row, column);
//        styleComponentForRegexValidity(c);
//        return c;
//    }

    private void styleComponentForRegexValidity(Component c){
        if(this.regex != null){
            c.setBackground(new Color(76,255, 155));
            c.setForeground(Color.BLACK);
        }else if(this.regexString != null){
            c.setBackground(new Color(221, 70, 57));
            c.setForeground(Color.WHITE);
        }
    }

    public Pattern getPattern() {
        return this.regex;
    }
}

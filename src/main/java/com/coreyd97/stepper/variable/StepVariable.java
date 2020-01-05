package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.regex.Pattern;

public abstract class StepVariable implements TableCellRenderer {

    private static String variablePrepend = "$VAR:";
    private static String variableAppend = "$";

    protected transient VariableManager variableManager;
    protected String identifier;
    protected String value;

    private StepVariable(){

    }

    StepVariable(String identifier){
        this.identifier = identifier;
        this.value = "";
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public abstract void setCondition(String condition);

    public abstract String getConditionText();

    public abstract void updateVariableBeforeExecution();

    public abstract void updateValueFromStep(Step step);

    public abstract void updateVariableAfterExecution(StepExecutionInfo executionInfo);

    public abstract boolean isValid();

    public void setValue(String value) {
        this.value = value;
    }

    protected void notifyChanges(){
        if(this.variableManager != null) variableManager.onVariableChange(this);
    }

    public void setVariableManager(VariableManager variableManager){
        this.variableManager = variableManager;
    }

    public String getValue() {
        return this.value;
    }

    public static Pattern createIdentifierPatternWithSequence(String sequence, String identifier){
        return Pattern.compile(Pattern.quote(createVariableString(sequence, identifier)), Pattern.CASE_INSENSITIVE);
    }

    public static Pattern createIdentifierPattern(String identifier){
        return Pattern.compile(Pattern.quote(createVariableString(identifier)), Pattern.CASE_INSENSITIVE);
    }

    public static Pattern createIdentifierPattern(StepVariable stepVariable){
        return createIdentifierPattern(stepVariable.getIdentifier());
    }

    public static Pattern createIdentifierPatternWithSequence(StepSequence sequence, StepVariable variable){
        return createIdentifierPatternWithSequence(sequence.getTitle(), variable.getIdentifier());
    }

    public static Pattern createIdentifierCaptureRegex(){
        return Pattern.compile(Pattern.quote(variablePrepend) + "(.*?)" + Pattern.quote(variableAppend));
    }

    public static String createVariableString(String sequence, String identifier){
        return variablePrepend + sequence + ":" + identifier + variableAppend;
    }

    public static String createVariableString(String identifier){
        return variablePrepend + identifier + variableAppend;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        DefaultTableCellRenderer defaultRenderer = new DefaultTableCellRenderer();
        return defaultRenderer.getTableCellRendererComponent(table, this.getConditionText(), isSelected, hasFocus, row, column);
    }

//    @Override
//    public Component getTableCellEditorComponent(JTable jTable, Object value, boolean isSelected, int row, int column) {
//        DefaultCellEditor defaultCellEditor = new DefaultCellEditor(new JTextField());
//        return defaultCellEditor.getTableCellEditorComponent(jTable, this.getConditionText(), isSelected, row, column);
//    }
}

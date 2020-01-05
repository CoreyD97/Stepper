package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.UUID;

public class PromptVariable extends StepVariable {

    public PromptVariable(){
        this(UUID.randomUUID().toString());
    }

    public PromptVariable(String identifier){
        super(identifier);
    }

    @Override
    public void setCondition(String regex) {
        //No condition.
    }

    @Override
    public String getConditionText() {
        return null;
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public void updateVariableBeforeExecution() {
        String newValue = JOptionPane.showInputDialog(Stepper.getUI().getUiComponent(), "Enter value for variable \"" + this.identifier + "\": ",
                "Variable Value", JOptionPane.INFORMATION_MESSAGE);
        this.value = newValue;
        notifyChanges();
    }

    @Override
    public void updateValueFromStep(Step step) {

    }

    @Override
    public void updateVariableAfterExecution(StepExecutionInfo executionInfo) {

    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        DefaultTableCellRenderer defaultRenderer = new DefaultTableCellRenderer();
        Component c = defaultRenderer.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
        return c;
    }
}

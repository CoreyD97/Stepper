package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.UUID;

public class PromptVariable extends PreExecutionStepVariable {

    public PromptVariable(){
        this(UUID.randomUUID().toString());
    }

    public PromptVariable(String identifier){
        super(identifier);
    }

    @Override
    public String getType() {
        return "Prompt";
    }

    @Override
    public String getValuePreview() {
        return String.format("$PROMPT_VALUE:%s$", getIdentifier());
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public void updateVariableBeforeExecution() {
        String newValue = JOptionPane.showInputDialog(Stepper.getUI().getUiComponent(), "Enter value for variable \"" + this.identifier + "\": ",
                "Variable Value", JOptionPane.INFORMATION_MESSAGE);
        this.value = newValue == null ? "" : newValue;
        notifyChanges();
    }
}

package com.coreyd97.stepper.variable;

import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.StepExecutionInfo;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.regex.Pattern;

public abstract class PostExecutionStepVariable extends StepVariable {

    PostExecutionStepVariable(String identifier){
        super(identifier);
    }

    public abstract void setCondition(String condition);

    public abstract String getConditionText();

    public abstract void updateVariableAfterExecution(StepExecutionInfo executionInfo);
}

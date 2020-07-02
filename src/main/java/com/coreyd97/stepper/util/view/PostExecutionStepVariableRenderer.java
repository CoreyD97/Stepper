package com.coreyd97.stepper.util.view;

import com.coreyd97.stepper.variable.PostExecutionStepVariable;
import com.coreyd97.stepper.variable.RegexVariable;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Created by corey on 22/08/17.
 */
public class PostExecutionStepVariableRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        if(value instanceof PostExecutionStepVariable) {
            Component c = super.getTableCellRendererComponent(table, ((PostExecutionStepVariable) value).getConditionText(), isSelected, hasFocus, row, column);
            if (value instanceof RegexVariable) {
                if(((RegexVariable) value).getPattern() != null){ //Pattern was valid
                    c.setBackground(new Color(76,255, 155));
                    c.setForeground(Color.BLACK);
                }else if(((RegexVariable) value).getConditionText() != null){ //Pattern was not null and invalid
                    c.setBackground(new Color(221, 70, 57));
                    c.setForeground(Color.WHITE);
                }
            }
            return c;
        }else{
            return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        }
    }
}


package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.StepVariable;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Created by corey on 22/08/17.
 */
public class PatternRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        if(!(value instanceof StepVariable)){
            return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        }

        StepVariable var = (StepVariable) value;
        Component c;
        if(var.getRegex() == null && var.getRegexString() != null){
            c = super.getTableCellRendererComponent(table, var.getRegexString(), isSelected, hasFocus, row, column);
            c.setBackground(new Color(221, 70, 57));
            c.setForeground(Color.WHITE);
            return c;
        }
        if(var.getRegex() != null){
            c = super.getTableCellRendererComponent(table, var.getRegex().pattern(), isSelected, hasFocus, row, column);
            c.setBackground(new Color(76,255, 155));
            c.setForeground(Color.BLACK);
            return c;
        }
        return super.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
    }
}


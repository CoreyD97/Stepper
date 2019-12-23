package com.coreyd97.stepper.util.view;

import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.awt.*;

public class PatternEditor extends DefaultCellEditor {

    public PatternEditor() {
        super(new JTextField());
        this.getComponent().setMinimumSize(new Dimension(100, 100));
    }

    @Override
    public Component getTableCellEditorComponent(JTable jTable, Object value, boolean isSelected, int row, int column) {
        if(!(value instanceof StepVariable)) return super.getTableCellEditorComponent(jTable, value, isSelected, row, column);

        StepVariable var = (StepVariable) value;
        Component c;
        if(var.isValidRegex()){
            c = super.getTableCellEditorComponent(jTable, var.getRegex().pattern(), isSelected, row, column);
            c.setBackground(new Color(76,255, 155));
            c.setForeground(Color.BLACK);
        }else if(var.getRegexString() != null){
            c = super.getTableCellEditorComponent(jTable, var.getRegexString(), isSelected, row, column);
            c.setBackground(new Color(221, 70, 57));
            c.setForeground(Color.WHITE);
        }else{
            c = super.getTableCellEditorComponent(jTable, "", isSelected, row, column);
        }
        return c;
    }
}

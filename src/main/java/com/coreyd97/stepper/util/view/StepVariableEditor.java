package com.coreyd97.stepper.util.view;

import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.awt.*;

public class StepVariableEditor extends DefaultCellEditor {

    public StepVariableEditor() {
        super(new JTextField());
        this.getComponent().setMinimumSize(new Dimension(100, 100));
    }
//
//    @Override
//    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
//        if(!(value instanceof StepVariable)) return super.getTableCellEditorComponent(table, value, isSelected, row, column);
//
//        Component c = null;
////        c = ((StepVariable) value).getTableCellEditorComponent(table, value, isSelected, row, column);
//        return c != null ? c : super.getTableCellEditorComponent(table, ((StepVariable) value).getConditionText(), isSelected, row, column);
//    }
}

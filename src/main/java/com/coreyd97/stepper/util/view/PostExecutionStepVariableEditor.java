package com.coreyd97.stepper.util.view;

import com.coreyd97.stepper.variable.PostExecutionStepVariable;
import com.coreyd97.stepper.variable.RegexVariable;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Created by corey on 22/08/17.
 */
public class PostExecutionStepVariableEditor extends DefaultCellEditor {

    public PostExecutionStepVariableEditor() {
        super(new JTextField());
        this.getComponent().setMinimumSize(new Dimension(100, 100));
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
        if(value instanceof PostExecutionStepVariable) {
            return super.getTableCellEditorComponent(table, ((PostExecutionStepVariable) value).getConditionText(), isSelected, row, column);
        }else{
            return super.getTableCellEditorComponent(table, value, isSelected, row, column);
        }
    }
}


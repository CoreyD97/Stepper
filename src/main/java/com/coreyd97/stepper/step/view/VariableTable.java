package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.StepVariableListener;
import com.coreyd97.stepper.util.view.StepVariableEditor;
import com.coreyd97.stepper.util.view.StepVariableRenderer;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;

public class VariableTable extends JTable {

    private Step step;

    public VariableTable(Step step){
        super();
        this.step = step;
        this.setModel(new VariableTableModel(this.step.getVariableManager()));
        this.getColumnModel().getColumn(1).setCellRenderer(new StepVariableRenderer());
        this.setDefaultEditor(StepVariable.class, new StepVariableEditor());
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 10 );

        this.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
    }

    private class VariableTableModel extends AbstractTableModel implements StepVariableListener {

        private final VariableManager variableManager;

        private VariableTableModel(VariableManager variableManager){
            this.variableManager = variableManager;
            this.variableManager.addVariableListener(this);
        }

        @Override
        public Class<?> getColumnClass(int i) {
            switch (i){
                case 0: return String.class;
                case 1: return StepVariable.class;
                case 2: return String.class;
                default: return String.class;
            }
        }

        @Override
        public String getColumnName(int i) {
            switch(i){
                case 0: return "Identifier";
                case 1: return "Condition";
                case 2: return "Value";
                default: return "N/A";
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            if(column == 2) return false;
            return true;
        }

        @Override
        public int getRowCount() {
            return variableManager.getVariables().size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Object getValueAt(int row, int col) {
            StepVariable variable = variableManager.getVariables().get(row);
            switch (col){
                case 0: return variable.getIdentifier();
                case 1: return variable;
                case 2: return variable.getValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            StepVariable var = this.variableManager.getVariables().get(row);
            switch (col){
                case 0: var.setIdentifier((String) value); break;
                case 1: var.setCondition((String) value); break;
            }
            this.fireTableDataChanged();
        }

        @Override
        public void onVariableAdded(StepVariable variable) {
            this.fireTableDataChanged();
        }

        @Override
        public void onVariableRemoved(StepVariable variable) {
            this.fireTableDataChanged();
        }

        @Override
        public void onVariableChange(StepVariable variable) {
            this.fireTableDataChanged();
        }
    }
}

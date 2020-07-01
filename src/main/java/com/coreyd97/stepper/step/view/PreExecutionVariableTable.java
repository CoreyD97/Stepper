package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.variable.PreExecutionStepVariable;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.listener.StepVariableListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;

public class PreExecutionVariableTable extends JTable {

    public PreExecutionVariableTable(VariableManager variableManager){
        super();
        this.setModel(new PreExecutionVariableTableModel(variableManager));
//        this.getColumnModel().getColumn(1).setCellRenderer(new StepVariableRenderer());
//        this.setDefaultEditor(StepVariable.class, new StepVariableEditor());
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 10 );

        this.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
    }

    private class PreExecutionVariableTableModel extends AbstractTableModel implements StepVariableListener {

        private final VariableManager variableManager;

        private PreExecutionVariableTableModel(VariableManager variableManager){
            this.variableManager = variableManager;
            this.variableManager.addVariableListener(this);
        }

        @Override
        public Class<?> getColumnClass(int i) {
            return String.class;
        }

        @Override
        public String getColumnName(int i) {
            switch(i){
                case 0: return "Type";
                case 1: return "Identifier";
                case 2: return "Last Value";
                default: return "N/A";
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 1;
        }

        @Override
        public int getRowCount() {
            return this.variableManager.getPreExecutionVariables().size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Object getValueAt(int row, int col) {
            PreExecutionStepVariable variable = this.variableManager.getPreExecutionVariables().get(row);
            switch (col){
                case 0: return variable.getType();
                case 1: return variable.getIdentifier();
                case 2: return variable.getValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            PreExecutionStepVariable var = this.variableManager.getPreExecutionVariables().get(row);
            switch (col){
                case 1: var.setIdentifier((String) value); break;
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

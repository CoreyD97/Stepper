package com.coreyd97.stepper.step.view;

import com.coreyd97.stepper.util.view.PostExecutionStepVariableEditor;
import com.coreyd97.stepper.util.view.PostExecutionStepVariableRenderer;
import com.coreyd97.stepper.variable.PostExecutionStepVariable;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.listener.StepVariableListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;

public class PostExecutionVariableTable extends JTable {


    public PostExecutionVariableTable(VariableManager variableManager){
        super();
        this.setModel(new PostExecutionVariableTableModel(variableManager));
        this.getColumnModel().getColumn(2).setCellRenderer(new PostExecutionStepVariableRenderer());
        this.getColumnModel().getColumn(2).setCellEditor(new PostExecutionStepVariableEditor());
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 10 );

        this.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
    }

    private class PostExecutionVariableTableModel extends AbstractTableModel implements StepVariableListener {

        private final VariableManager variableManager;

        private PostExecutionVariableTableModel(VariableManager variableManager){
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
                case 2: return "Condition";
                case 3: return "Value";
                default: return "N/A";
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 1 || column == 2;
        }

        @Override
        public int getRowCount() {
            return this.variableManager.getPostExecutionVariables().size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int row, int col) {
            PostExecutionStepVariable variable = this.variableManager.getPostExecutionVariables().get(row);
            switch (col){
                case 0: return variable.getType();
                case 1: return variable.getIdentifier();
                case 2: return variable;
                case 3: return variable.getValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            PostExecutionStepVariable var = this.variableManager.getPostExecutionVariables().get(row);
            switch (col){
                case 1: var.setIdentifier((String) value); break;
                case 2: var.setCondition((String) value); break;
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

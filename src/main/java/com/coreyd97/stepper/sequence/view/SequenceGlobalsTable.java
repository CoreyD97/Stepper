package com.coreyd97.stepper.sequence.view;

import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.VariableManager;
import com.coreyd97.stepper.variable.listener.StepVariableListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;

public class SequenceGlobalsTable extends JTable implements StepVariableListener {

    private VariableManager sequenceGlobals;

    public SequenceGlobalsTable(VariableManager globalVariableManager){
        super();
        this.sequenceGlobals = globalVariableManager;
        this.setModel(new VariableTableModel(globalVariableManager));
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 5 );

        this.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        this.sequenceGlobals.addVariableListener(this);
    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        ((VariableTableModel) this.getModel()).fireTableDataChanged();
    }

    @Override
    public void onVariableRemoved(StepVariable variable) {
        ((VariableTableModel) this.getModel()).fireTableDataChanged();
    }

    @Override
    public void onVariableChange(StepVariable variable) {
        ((VariableTableModel) this.getModel()).fireTableDataChanged();
    }

    private class VariableTableModel extends AbstractTableModel {

        private final VariableManager globalVariableManager;

        private VariableTableModel(VariableManager globalVariableManager){
            this.globalVariableManager = globalVariableManager;
        }

        @Override
        public Class<?> getColumnClass(int i) {
            return String.class;
        }

        @Override
        public String getColumnName(int i) {
            switch(i){
                case 0: return "Identifier";
                case 1: return "Value";
                default: return "N/A";
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return true;
        }

        @Override
        public int getRowCount() {
            return globalVariableManager.getVariables().size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public Object getValueAt(int row, int col) {
            StepVariable variable = globalVariableManager.getVariables().get(row);
            switch (col){
                case 0: return variable.getIdentifier();
                case 1: return variable.getValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            StepVariable var = globalVariableManager.getVariables().get(row);
            switch (col){
                case 0: var.setIdentifier((String) value); break;
                case 1: var.setValue((String) value); break;
            }
        }
    }
}

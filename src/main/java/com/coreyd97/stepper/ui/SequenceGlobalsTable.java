package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.SequenceGlobals;
import com.coreyd97.stepper.IStepVariableListener;
import com.coreyd97.stepper.StepVariable;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.Vector;

public class SequenceGlobalsTable extends JTable implements IStepVariableListener {

    private SequenceGlobals sequenceGlobals;

    public SequenceGlobalsTable(SequenceGlobals sequenceGlobals){
        super();
        this.sequenceGlobals = sequenceGlobals;
        this.setModel(new VariableTableModel(sequenceGlobals.getVariables()));
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 5 );

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
    public void onVariableChange(StepVariable variable, StepVariable.ChangeType origin) {
        ((VariableTableModel) this.getModel()).fireTableDataChanged();
    }

    private class VariableTableModel extends AbstractTableModel {

        private final Vector<StepVariable> variables;

        private VariableTableModel(Vector<StepVariable> variables){
            this.variables = variables;
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
            return variables.size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public Object getValueAt(int row, int col) {
            StepVariable variable = variables.get(row);
            switch (col){
                case 0: return variable.getIdentifier();
                case 1: return variable.getLatestValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            StepVariable var = this.variables.get(row);
            switch (col){
                case 0: var.setIdentifier((String) value); break;
                case 1: var.setLatestValue((String) value); break;
            }
        }
    }
}

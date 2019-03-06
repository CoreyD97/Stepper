package com.coreyd97.stepper.ui;

import com.coreyd97.stepper.Step;
import com.coreyd97.stepper.StepVariable;
import com.coreyd97.stepper.IStepVariableListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.Vector;

public class VariableTable extends JTable implements IStepVariableListener {

    private Step step;

    public VariableTable(Step step){
        super();
        this.step = step;
        this.setModel(new VariableTableModel(this.step.getVariables()));
        this.getColumnModel().getColumn(1).setCellRenderer(new PatternRenderer());
        this.setDefaultEditor(StepVariable.class, new PatternEditor());
        this.createDefaultTableHeader();

        FontMetrics metrics = this.getFontMetrics(this.getFont());
        int fontHeight = metrics.getHeight();
        this.setRowHeight( fontHeight + 10 );

        //Watch the step for any added/removed variables. Will also subscribe to existing.
        this.step.addVariableListener(this);

    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        ((VariableTableModel) this.getModel()).fireTableDataChanged();
        variable.addVariableListener(this); //Listen to any future changes
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
                case 1: return "Regex";
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
            return variables.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Object getValueAt(int row, int col) {
            StepVariable variable = variables.get(row);
            switch (col){
                case 0: return variable.getIdentifier();
                case 1: return variable;
                case 2: return variable.getLatestValue();
            }

            return "";
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            StepVariable var = this.variables.get(row);
            switch (col){
                case 0: var.setIdentifier((String) value); break;
                case 1: var.setRegexString((String) value); break;
            }
            this.fireTableDataChanged();
        }
    }
}

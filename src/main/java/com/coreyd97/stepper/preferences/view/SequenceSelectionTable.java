package com.coreyd97.stepper.preferences.view;

import com.coreyd97.stepper.sequence.StepSequence;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SequenceSelectionTable extends JTable {

    private final SequenceSelectionTableModel model;

    public SequenceSelectionTable(List<StepSequence> sequences){
        this.model = new SequenceSelectionTableModel(sequences);
        this.setModel(this.model);
    }

    public List<StepSequence> getSelectedSequences(){
        return this.model.getSelectedSequences();
    }

    private class SequenceSelectionTableModel extends DefaultTableModel {

        private final List<StepSequence> sequences;
        private final boolean[] sequenceIsSelected;
        private final String[] COLUMN_NAMES = new String[]{"", "Name", "Steps", "Variables"};

        SequenceSelectionTableModel(List<StepSequence> sequences){
            this.sequences = sequences;
            this.sequenceIsSelected = new boolean[sequences.size()];
            Arrays.fill(this.sequenceIsSelected, true);
        }

        @Override
        public int getRowCount() {
            if(sequences == null) return 0;
            return sequences.size();
        }

        @Override
        public Class<?> getColumnClass(int index) {
            if(index == 0) return Boolean.class;
            if(index == 2 || index == 3) return Integer.class;
                return String.class;
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int i) {
            return COLUMN_NAMES[i];
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return col == 0;
        }

        @Override
        public void setValueAt(Object val, int row, int col) {
            if(col == 0 && row >= 0 && row < sequenceIsSelected.length){
                sequenceIsSelected[row] = (boolean) val;
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            StepSequence sequence = sequences.get(row);
            switch (col){
                case 0: {
                    return sequenceIsSelected[row];
                }
                case 1: {
                    return sequence.getTitle();
                }
                case 2: {
                    return sequence.getSteps().size();
                }
                case 3: {
                    return sequence.getRollingVariablesUpToStep(null).size();
                }
            }
            return "";
        }

        private List<StepSequence> getSelectedSequences(){
            List<StepSequence> selected = new ArrayList<>();
            for (int i = 0; i < this.sequenceIsSelected.length; i++) {
                if(this.sequenceIsSelected[i]){
                    selected.add(this.sequences.get(i));
                }
            }
            return selected;
        }
    }
}

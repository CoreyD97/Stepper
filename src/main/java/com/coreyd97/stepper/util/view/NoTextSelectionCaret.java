package com.coreyd97.stepper.util.view;

import javax.swing.text.DefaultCaret;
import javax.swing.text.JTextComponent;

public class NoTextSelectionCaret extends DefaultCaret {
    public NoTextSelectionCaret(JTextComponent component){
        setBlinkRate(component.getCaret().getBlinkRate());
        component.setHighlighter(null);
    }
}

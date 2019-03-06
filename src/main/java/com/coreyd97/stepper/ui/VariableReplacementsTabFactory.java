package com.coreyd97.stepper.ui;

import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import com.coreyd97.stepper.Step;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.StepSequence;

import java.util.ArrayList;

public class VariableReplacementsTabFactory implements IMessageEditorTabFactory {

    private final Stepper stepper;

    public VariableReplacementsTabFactory(Stepper extension){
        this.stepper = extension;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        VariableReplacementsTab tab = new VariableReplacementsTab(controller, editable);
        IMessageEditorController actualController = findActualController(controller);
        if(actualController instanceof Step) {
            tab.setActualController((Step) actualController);
        }
        return tab;
    }

    private IMessageEditorController findActualController(IMessageEditorController controller){
        ArrayList<StepSequence> stepSequences = stepper.getSequences();
        IHttpService service;
        try {
            service = controller.getHttpService();
        }catch (IllegalArgumentException | NullPointerException e){ return null; }
        if(service == null) return null;

        for (StepSequence stepSequence : stepSequences) {
            for (Step step : stepSequence.getSteps()) {
                if(step.getHttpService().toString().equalsIgnoreCase(service.toString())){
                    step.matchHackDone();
                    return step;
                }
            }
        }
        return null;
    }
}

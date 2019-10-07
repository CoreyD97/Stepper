package com.coreyd97.stepper.ui;

import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import com.coreyd97.stepper.Step;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.StepSequence;

import java.util.ArrayList;
import java.util.Arrays;

public class VariableReplacementsTabFactory implements IMessageEditorTabFactory {

    private final Stepper stepper;

    public VariableReplacementsTabFactory(Stepper extension){
        this.stepper = extension;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controllerProxyInstance, boolean editable) {
        VariableReplacementsTab tab = new VariableReplacementsTab(controllerProxyInstance, editable);
        IMessageEditorController actualController = findActualController(controllerProxyInstance);
        if(actualController != null && actualController instanceof Step) {
            tab.setActualController((Step) actualController);
        }
        return tab;
    }

    private IMessageEditorController findActualController(IMessageEditorController controller){
        ArrayList<StepSequence> stepSequences = stepper.getSequences();
        byte[] requestMatchHack = controller.getRequest();

        for (StepSequence stepSequence : stepSequences) {
            for (Step step : stepSequence.getSteps()) {
                if(Arrays.equals(requestMatchHack, step.getRequest())){
                    return step;
                }
            }
        }
        return null;
    }
}

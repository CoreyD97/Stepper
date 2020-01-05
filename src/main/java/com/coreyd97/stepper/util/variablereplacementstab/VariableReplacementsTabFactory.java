package com.coreyd97.stepper.util.variablereplacementstab;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.sequence.StepSequence;

import java.util.Arrays;
import java.util.List;

public class VariableReplacementsTabFactory implements IMessageEditorTabFactory {

    private final SequenceManager sequenceManager;

    public VariableReplacementsTabFactory(SequenceManager sequenceManager){
        this.sequenceManager = sequenceManager;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controllerProxyInstance, boolean editable) {
        VariableReplacementsTab tab = new VariableReplacementsTab(sequenceManager, controllerProxyInstance, editable);
        IMessageEditorController actualController = findActualController(controllerProxyInstance);
        if(actualController instanceof Step) {
            tab.setStep((Step) actualController);
        }
        return tab;
    }

    private IMessageEditorController findActualController(IMessageEditorController controller){
        List<StepSequence> stepSequences = sequenceManager.getSequences();
        byte[] requestMatchHack;

        try{
             requestMatchHack = controller.getRequest();
        }catch (Exception e){
            //The controller threw and exception when trying to get the request.
            //This is caused by the class which implements the controller, not stepper!
            return null;
        }

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

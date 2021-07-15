package com.coreyd97.stepper.step;

import burp.*;
import com.coreyd97.stepper.Globals;
import com.coreyd97.stepper.MessageProcessor;
import com.coreyd97.stepper.Stepper;
import com.coreyd97.stepper.exception.SequenceCancelledException;
import com.coreyd97.stepper.exception.SequenceExecutionException;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.step.listener.StepExecutionListener;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.util.*;

public class Step implements IMessageEditorController {

    private final List<StepExecutionListener> executionListeners;
    private final StepVariableManager variableManager;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private StepSequence sequence;
    private StepExecutionInfo lastExecutionInfo;
    private IHttpService httpService;
    private String hostname;
    private Integer port;
    private Boolean isSSL;
    private String title;

    private final String matchHack = ("MATCHHACK." + Math.random() + ".coreyd97.com");

    private byte[] requestBody;
    private byte[] responseBody;

    public Step(){
        this.variableManager = new StepVariableManager(this);
        this.executionListeners = new ArrayList<>();
        this.requestBody = new byte[0];
        this.responseBody = new byte[0];
        this.hostname = "";
        this.port = 443;
        this.isSSL = true;
    }

    public Step(StepSequence sequence, String title){
        this();
        this.sequence = sequence;
        if(title != null) {
            this.title = title;
        }else{
            this.title = "Step " + (sequence.getSteps().size()+1);
        }

    }

    public Step(StepSequence sequence){
        this(sequence, null);
    }

    public void setSequence(StepSequence sequence) {
        this.sequence = sequence;
    }

    public void setRequestBody(byte[] requestBody){
        this.requestBody = requestBody;
        if(this.requestEditor != null)
            this.requestEditor.setMessage(requestBody, true);
    }

    public void setResponseBody(byte[] responseBody){
        if(this.responseEditor != null)
            this.responseEditor.setMessage(responseBody, false);

    }

    public StepVariableManager getVariableManager() {
        return variableManager;
    }

    public StepSequence getSequence() {
        return sequence;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public byte[] getRequest() {
        if(this.requestEditor == null) {
            return matchHack.getBytes();
        }
        return this.requestEditor.getMessage();
    }

    @Override
    public byte[] getResponse() {
        if(this.responseEditor == null) return responseBody;
        return this.responseEditor.getMessage();
    }

    public StepExecutionInfo executeStep() throws SequenceExecutionException {
        List<StepVariable> variables = this.sequence.getRollingVariablesUpToStep(this);
        return this.executeStep(variables);
    }

    public StepExecutionInfo executeStep(List<StepVariable> replacements) throws SequenceExecutionException {
        byte[] requestWithoutReplacements = getRequest();
        byte[] builtRequest;

        this.variableManager.updateVariablesBeforeExecution();

        for (StepExecutionListener executionListener : this.executionListeners) {
            executionListener.beforeStepExecution();
        }

        if(MessageProcessor.hasStepVariable(requestWithoutReplacements)) {
//            if(MessageProcessor.isUnprocessable(requestWithoutReplacements)){
//                //If there's unicode issues, we're likely acting on binary data. Warn the user.
//                //TODO STEP SEQUENCE HANDLE BINARY ERRORS.
//                int result = JOptionPane.showConfirmDialog(Stepper.getInstance().getUI().getUiComponent(),
//                        "The request contains non UTF characters.\nStepper is able to make the replacements, " +
//                                "but some of the binary data may be lost. Continue?",
//                        "Stepper Replacement Error", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
//                if(result == JOptionPane.NO_OPTION) throw new SequenceCancelledException("Binary data, user cancelled.");
//            }
            builtRequest = MessageProcessor.makeReplacementsForSingleSequence(requestWithoutReplacements, replacements);
        }else{
            builtRequest = Arrays.copyOf(requestWithoutReplacements, requestWithoutReplacements.length);
        }

        if(Stepper.getPreferences().getSetting(Globals.PREF_UPDATE_REQUEST_LENGTH)){
            builtRequest = MessageProcessor.updateContentLength(builtRequest);

            //TODO Find a way to reliably replace content-length of templated request.
            byte[] fixedContentLengthTemplate = MessageProcessor.updateContentLength(requestWithoutReplacements);
            //setRequestBody();
        }

        setResponseBody(new byte[0]);

        //Update the httpService
        //Part of hack to match VariableReplacementTab with actual IMessageEditorController
        this.httpService = Stepper.callbacks.getHelpers().buildHttpService(
                this.hostname, this.port, this.isSSL);

        //Add X-Stepper-Ignore header so its not picked up by messageProcessor
        builtRequest = MessageProcessor.addHeaderToRequest(builtRequest, MessageProcessor.STEPPER_IGNORE_HEADER);

        long start = new Date().getTime();
        //Update with response
        IHttpRequestResponse requestResponse = Stepper.callbacks.makeHttpRequest(this.getHttpService(), builtRequest);
        long end = new Date().getTime();
        if(requestResponse.getResponse() == null)
            throw new SequenceExecutionException("The request to the server timed out.");

        setResponseBody(requestResponse.getResponse());

        this.lastExecutionInfo = new StepExecutionInfo(this, requestResponse, end-start);

        //Pull variables from response
        this.variableManager.updateVariablesAfterExecution(lastExecutionInfo);

        for (StepExecutionListener executionListener : executionListeners) {
            executionListener.stepExecuted(lastExecutionInfo);
        }

        return lastExecutionInfo;
    }

    private void tryUpdateHttpService(){
        try {
            this.httpService = Stepper.callbacks.getHelpers().buildHttpService(
                    this.hostname, this.port, this.isSSL);
        }catch (IllegalArgumentException e){
            //
        }
    }

    public void addExecutionListener(StepExecutionListener listener){
        this.executionListeners.add(listener);
    }

    public void removeExecutionListener(StepExecutionListener listener){
        this.executionListeners.remove(listener);
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
        tryUpdateHttpService();
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
        tryUpdateHttpService();
    }

    public boolean isSSL() {
        return isSSL;
    }

    public void setSSL(boolean SSL) {
        tryUpdateHttpService();
        isSSL = SSL;
    }

    public String getTargetString(){
        if(hostname.isEmpty()) return "Not specified";
        return "http" + (isSSL ? "s" : "") + "://" + hostname + (port != 80 && port != 443 ? ":" + port : "");
    }

    public boolean isValidTarget(){
        if(this.hostname != null && this.port != null && this.isSSL != null){
            try{
                Stepper.callbacks.getHelpers().buildHttpService(hostname, port, isSSL);
                return true;
            } catch (Exception e){
                e.printStackTrace();
            }
        }
        return false;
    }

    public boolean isReadyToExecute(){
        return this.isValidTarget() && this.getRequest() != null && this.getRequest().length != 0;
    }


    public void setHttpService(IHttpService httpService) {
        this.hostname = httpService.getHost();
        this.port = httpService.getPort();
        this.isSSL = httpService.getProtocol().equalsIgnoreCase("https");
        tryUpdateHttpService();
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    public void registerRequestEditor(IMessageEditor requestEditor) {
        this.requestEditor = requestEditor;
        this.requestEditor.setMessage(requestBody, true);
    }

    public void registerResponseEditor(IMessageEditor responseEditor){
        this.responseEditor = responseEditor;
        this.responseEditor.setMessage(responseBody, false);
    }

    public StepExecutionInfo getLastExecutionResult() {
        return this.lastExecutionInfo;
    }
}

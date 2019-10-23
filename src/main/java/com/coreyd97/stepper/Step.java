package com.coreyd97.stepper;

import burp.*;

import javax.swing.*;
import java.util.*;
import java.util.regex.Matcher;

public class Step implements IMessageEditorController, IStepVariableListener {

    private final Vector<StepVariable> variables;
    private final ArrayList<IStepVariableListener> variableListeners;
    private final ArrayList<IHttpRequestResponseListener> requestResponseListeners;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private StepSequence sequence;
    private IHttpRequestResponse requestResponse;
    private IHttpService httpService;
    private String hostname;
    private Integer port;
    private Boolean isSSL;
    private String title;

    private byte[] requestBody;
    private byte[] responseBody;

    public Step(){
        this.variables = new Vector<>();
        this.variableListeners = new ArrayList<>();
        this.requestResponseListeners = new ArrayList<>();
        this.requestBody = new byte[0];
        this.responseBody = new byte[0];
    }

    public Step(StepSequence sequence, String title){
        this();
        this.sequence = sequence;
        if(title != null) {
            this.title = title;
        }else{
            this.title = "Step " + (sequence.getSteps().size()+1);
        }

        this.hostname = "HOSTNAME";
        this.port = 443;
        this.isSSL = true;
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
        for (IHttpRequestResponseListener requestResponseListener : requestResponseListeners) {
            requestResponseListener.onRequestSet(requestBody);
        }
    }

    public void setResponseBody(byte[] responseBody){
        if(this.responseEditor != null)
            this.responseEditor.setMessage(responseBody, false);
        for (IHttpRequestResponseListener requestResponseListener : requestResponseListeners) {
            requestResponseListener.onResponseSet(responseBody);
        }
    }

    public Vector<StepVariable> getVariables() {
        return variables;
    }

    public void addVariable(){
        StepVariable var = new StepVariable();
        var.setIdentifier(UUID.randomUUID().toString());
        addVariable(var);
    }

    public void addVariable(StepVariable var){
        this.variables.add(var);
        var.addVariableListener(this);
        for (IStepVariableListener variableListener : this.variableListeners) {
            var.addVariableListener(variableListener);
            variableListener.onVariableAdded(var);
        }
    }

    public void deleteVariable(int index){
        if(index == -1) return;
        StepVariable variable = this.variables.get(index);
        deleteVariable(variable);
    }

    public void deleteVariable(StepVariable variable){
        if(variable == null) return;
        this.variables.remove(variable);
        for (IStepVariableListener variableListener : this.variableListeners) {
            variableListener.onVariableRemoved(variable);
            variable.removeVariableListener(variableListener);
        }
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
        if(this.requestEditor == null) return ("MATCHHACK." + Math.random() + ".coreyd97.com").getBytes();
        return this.requestEditor.getMessage();
    }

    @Override
    public byte[] getResponse() {
        if(this.responseEditor == null) return responseBody;
        return this.responseEditor.getMessage();
    }

    public void executeStep(){
        HashMap<String, StepVariable> variables = this.sequence.getRollingVariables(this);
        this.executeStep(variables);
    }

    public boolean executeStep(HashMap<String, StepVariable> replacements) {
        byte[] requestWithoutReplacements = getRequest();
        byte[] builtRequest;

        if(MessageProcessor.hasStepVariable(requestWithoutReplacements)) {
            if(!MessageProcessor.isProcessable(requestWithoutReplacements)){
                //If there's unicode issues, we're likely acting on binary data. Warn the user.
                //TODO STEP SEQUENCE HANDLE BINARY ERRORS.
                int result = JOptionPane.showConfirmDialog(Stepper.getInstance().getUI().getUiComponent(),
                        "The request contains non UTF characters.\nStepper is able to make the replacements, " +
                                "but some of the binary data may be lost. Continue?",
                        "Stepper Replacement Error", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if(result == JOptionPane.NO_OPTION) return false;
            }
            builtRequest = MessageProcessor.makeReplacements(requestWithoutReplacements, replacements);
        }else{
            builtRequest = Arrays.copyOf(requestWithoutReplacements, requestWithoutReplacements.length);
        }

        //TODO Update the displayed request with the content-length header which was sent to the server.
        setResponseBody(new byte[0]);

        //Update the httpService
        //Part of hack to match VariableReplacementTab with actual IMessageEditorController
        this.httpService = Stepper.callbacks.getHelpers().buildHttpService(
                this.hostname, this.port, this.isSSL);

        //Update with response
        this.requestResponse = Stepper.callbacks.makeHttpRequest(this.getHttpService(), builtRequest);
        setResponseBody(this.requestResponse.getResponse());

        if(this.requestResponse.getResponse() == null){
            return false;
        }
        String responseString = new String(this.requestResponse.getResponse());

        //Pull variables from response
        for (StepVariable variable : this.variables) {
            updateVariable(variable, responseString);
        }

        return true;
    }

    private void updateHttpService(){
        this.httpService = Stepper.callbacks.getHelpers().buildHttpService(
                this.hostname, this.port, this.isSSL);
    }

    private void updateVariable(StepVariable variable, String response){
        if(variable.getRegex() == null) return;
        Matcher m = variable.getRegex().matcher(response);
        if(m.find()){
            if(m.groupCount() == 0)
                variable.setLatestValue(m.group(0));
            else
                variable.setLatestValue(m.group(1));
        }else{
            variable.setLatestValue("");
        }
    }

    public void dispose(){
        for (StepVariable variable : this.variables) {
            variable.clearVariableListeners();
        }
        this.variableListeners.clear();
    }

    @Override
    public void onVariableChange(StepVariable variable, StepVariable.ChangeType origin) {
        if(origin != StepVariable.ChangeType.REGEX) return;
        if (this.requestResponse != null && this.requestResponse.getResponse() != null)
            updateVariable(variable, new String(this.requestResponse.getResponse()));
        else
            updateVariable(variable, new String(""));
    }

    @Override
    public void onVariableAdded(StepVariable variable) {
        for (IStepVariableListener variableListener : this.variableListeners) {
            variable.addVariableListener(variableListener);
        }
    }

    @Override
    public void onVariableRemoved(StepVariable variable) {
        variable.clearVariableListeners();
    }

    public void addRequestResponseListener(IHttpRequestResponseListener listener) {
        this.requestResponseListeners.add(listener);
    }

    public void removeRequestResponseListener(IHttpRequestResponseListener listener) {
        this.requestResponseListeners.remove(listener);
    }

    public void addVariableListener(IStepVariableListener listener){
        this.variableListeners.add(listener);
        for (StepVariable variable : this.getVariables()) {
            variable.addVariableListener(listener);
        }
    }

    public void removeVariableListener(IStepVariableListener listener){
        this.variableListeners.remove(listener);
        for (StepVariable variable : this.getVariables()) {
            variable.removeVariableListener(listener);
        }
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
        updateHttpService();
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
        updateHttpService();
    }

    public boolean isSSL() {
        return isSSL;
    }

    public void setSSL(boolean SSL) {
        updateHttpService();
        isSSL = SSL;
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
        updateHttpService();
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    public HashMap<String, StepVariable> getRollingVariables() {
        if(this.sequence == null) return new HashMap<>();
        return this.sequence.getRollingVariables(this);
    }

    public void registerRequestEditor(IMessageEditor requestEditor) {
        this.requestEditor = requestEditor;
        this.requestEditor.setMessage(requestBody, true);
    }

    public void registerResponseEditor(IMessageEditor responseEditor){
        this.responseEditor = responseEditor;
        this.responseEditor.setMessage(responseBody, false);
    }

}

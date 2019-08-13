package com.coreyd97.stepper;

import burp.*;

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
        this.title = "Unnamed Step";
        this.variables = new Vector<>();
        this.variableListeners = new ArrayList<>();
        this.requestResponseListeners = new ArrayList<>();
        this.httpService = Stepper.callbacks.getHelpers().buildHttpService("MATCHHACK." + Math.random(), 1234, false);
        this.hostname = "HOSTNAME";
        this.port = 443;
        this.isSSL = true;
        this.requestBody = new byte[0];
        this.responseBody = new byte[0];
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
        if(this.requestEditor == null) return requestBody;
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

    public void executeStep(HashMap<String, StepVariable> replacements) {
        byte[] requestWithoutReplacements = getRequest();
        byte[] builtRequest = MessageProcessor.makeReplacements(requestWithoutReplacements, replacements);

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
            return;
        }
        String responseString = new String(this.requestResponse.getResponse());

        //Pull variables from response
        for (StepVariable variable : this.variables) {
            updateVariable(variable, responseString);
        }
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
    }

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public boolean isSSL() {
        return isSSL;
    }

    public void setSSL(boolean SSL) {
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
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    private int matchHackCompleteTimes = 0;
    public void matchHackDone() {
        //Run once request/response editors have been created.
        //Set the IHTTPRequestResponse to the actual values once both have been matched.
        matchHackCompleteTimes++;
        if(matchHackCompleteTimes == 2) {
            this.httpService = Stepper.callbacks.getHelpers().buildHttpService(
                    this.hostname, this.port, this.isSSL);
        }
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

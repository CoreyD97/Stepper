package com.coreyd97.stepper.step;

import burp.IHttpRequestResponse;

public class StepExecutionInfo {
    private Step step;
    private long responseTime;
    private IHttpRequestResponse requestResponse;

    public StepExecutionInfo(Step step, IHttpRequestResponse requestResponse, long responseTime){
        this.step = step;
        this.requestResponse = requestResponse;
        this.responseTime = responseTime;
    }

    public Step getStep() {
        return step;
    }

    public long getResponseTime() {
        return responseTime;
    }

    public IHttpRequestResponse getIRequestResponse() {
        return requestResponse;
    }
}

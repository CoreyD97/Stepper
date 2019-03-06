package com.coreyd97.stepper;

public interface IHttpRequestResponseListener {
    void onRequestSet(byte[] request);
    void onResponseSet(byte[] response);
}

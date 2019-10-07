package com.coreyd97.stepper;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.util.Arrays;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageProcessor implements IHttpListener {

    private final Stepper stepper;
    private final Preferences preferences;

    public MessageProcessor(Stepper stepper, Preferences preferences){
        this.stepper = stepper;
        this.preferences = preferences;
    }

    public static boolean hasStepVariable(byte[] content) {
        Pattern identifierFinder = StepVariable.createIdentifierCaptureRegex();
        Matcher m = identifierFinder.matcher(new String(content));
        return m.find();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(isValidTool(toolFlag) && messageIsRequest){
            HashMap<String, StepVariable> allVariables = new HashMap<>();
            for (StepSequence sequence : stepper.getSequences()) {
                allVariables.putAll(sequence.getAllVariables());
            }

            if(allVariables.size() > 0) {
                byte[] newRequest = makeReplacements(messageInfo.getRequest(), allVariables);
                try {
                    messageInfo.setRequest(newRequest);
                } catch (UnsupportedOperationException e) { /**Read-only message**/}
            }
        }
    }

    private boolean isValidTool(int toolFlag){
        if((boolean) preferences.getSetting(Globals.PREF_VARS_IN_ALL_TOOLS)) return true;
        switch (toolFlag){
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_PROXY);
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_REPEATER);
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_INTRUDER);
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_SCANNER);
            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_SEQUENCER);
            case IBurpExtenderCallbacks.TOOL_SPIDER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_SPIDER);
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return (boolean) preferences.getSetting(Globals.PREF_VARS_IN_EXTENDER);
            default:
                return false;
        }
    }

    public static byte[] makeReplacements(byte[] originalContent, HashMap<String, StepVariable> replacements){
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);
        if(request == null) return null;
        boolean hasReplaced = false;

        if(replacements != null) {
            //Apply replacements.
            String requestString = new String(request);
            for (StepVariable replacement : replacements.values()) {
                //Find identifier in requestBody and replace with latest value.
                Matcher m = StepVariable.createIdentifierPattern(replacement).matcher(requestString);
                if(m.find()){ hasReplaced = true; }
                String replacementValue = replacement.getLatestValue() != null ? replacement.getLatestValue() : "";
                requestString = m.replaceAll(replacementValue);
            }
            request = requestString.getBytes();
        }

        if(hasReplaced) {
            //Analyse the request with replacements to identify the headers and body
            IRequestInfo requestInfo = Stepper.callbacks.getHelpers().analyzeRequest(request);
            byte[] requestBody = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);

            //Built request
            return Stepper.callbacks.getHelpers().buildHttpMessage(requestInfo.getHeaders(), requestBody);
        }else{
            return originalContent;
        }
    }
}

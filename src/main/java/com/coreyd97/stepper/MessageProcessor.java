package com.coreyd97.stepper;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;

import javax.swing.*;
import java.nio.charset.Charset;
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

    public static boolean isProcessable(byte[] content){
        //Check for charset decoding errors
        return new String(content).indexOf('\uFFFD') == -1;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(isValidTool(toolFlag) && messageIsRequest){
            HashMap<String, StepVariable> allVariables = new HashMap<>();
            for (StepSequence sequence : stepper.getSequences()) {
                allVariables.putAll(sequence.getAllVariables());
            }

            if(allVariables.size() > 0 && hasStepVariable(messageInfo.getRequest())) {

                if(!isProcessable(messageInfo.getRequest())){
                    //If there's unicode issues, we're likely acting on binary data. Warn the user.
                    int result = JOptionPane.showConfirmDialog(this.stepper.getUI().getUiComponent(),
                            "The request contains non UTF characters.\nStepper is able to make the replacements, " +
                                    "but some of the binary data may be lost. Continue?",
                            "Stepper Replacement Error", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    if(result == JOptionPane.NO_OPTION) return;
                }

                try {
                    byte[] newRequest = makeReplacements(messageInfo.getRequest(), allVariables);
                    messageInfo.setRequest(newRequest);
                } catch (UnsupportedOperationException e) { /**Read-only message**/ }
            }
        }
    }

    private boolean isValidTool(int toolFlag){
        if(preferences.getSetting(Globals.PREF_VARS_IN_ALL_TOOLS)) return true;
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

    public static byte[] makeReplacements(byte[] originalContent,
                                          HashMap<String, StepVariable> replacements) {
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);
        boolean hasReplaced = false;

        String requestString = new String(request);

        for (StepVariable replacement : replacements.values()) {
            //Find identifier in requestBody and replace with latest value.
            Matcher m = StepVariable.createIdentifierPattern(replacement).matcher(requestString);
            hasReplaced |= m.find();

            String replacementValue = replacement.getLatestValue() == null ? "" : replacement.getLatestValue();
            requestString = m.replaceAll(replacementValue);
        }
        request = requestString.getBytes();

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

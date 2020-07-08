package com.coreyd97.stepper;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageProcessor implements IHttpListener {

    private final SequenceManager sequenceManager;
    private final Preferences preferences;
    public static final String EXECUTE_BEFORE_REGEX = "X-Stepper-Execute-Before:(.*)";
    public static final Pattern EXECUTE_BEFORE_PATTERN = Pattern.compile(EXECUTE_BEFORE_REGEX, Pattern.CASE_INSENSITIVE);
    public static final String STEPPER_IGNORE_HEADER = "X-Stepper-Ignore";
    public static final Pattern STEPPER_IGNORE_PATTERN = Pattern.compile(STEPPER_IGNORE_HEADER, Pattern.CASE_INSENSITIVE);

    public MessageProcessor(SequenceManager sequenceManager, Preferences preferences){
        this.sequenceManager = sequenceManager;
        this.preferences = preferences;
    }

    public static boolean hasStepVariable(byte[] content) {
        Pattern identifierFinder = StepVariable.createIdentifierCaptureRegex();
        Matcher m = identifierFinder.matcher(new String(content));
        return m.find();
    }

    public static boolean isUnprocessable(byte[] content){
        //Check for charset decoding errors
        return new String(content).indexOf('\uFFFD') != -1;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = Stepper.callbacks.getHelpers().analyzeRequest(messageInfo.getRequest());

        if(hasHeaderMatchingPattern(requestInfo, STEPPER_IGNORE_PATTERN)){
            byte[] request = removeHeaderMatchingPattern(messageInfo.getRequest(), STEPPER_IGNORE_PATTERN);
            messageInfo.setRequest(request);
            return;
        }

        if(isValidTool(toolFlag) && messageIsRequest){

            byte[] request = messageInfo.getRequest();
            List<StepSequence> postExecSequences = extractPostExecSequencesFromRequest(requestInfo);
            if(postExecSequences.size() > 0){
                //Remove the headers from the request
                request = removeHeaderMatchingPattern(request, EXECUTE_BEFORE_PATTERN);

                //Execute the sequences
                for (StepSequence sequence : postExecSequences) {
                    sequence.executeBlocking();
                }
            }


            HashMap<StepSequence, List<StepVariable>> allVariables = sequenceManager.getRollingVariablesFromAllSequences();

            if(allVariables.size() > 0 && hasStepVariable(request)) {

                if(isUnprocessable(messageInfo.getRequest())){
                    //If there's unicode issues, we're likely acting on binary data. Warn the user.
                    int result = JOptionPane.showConfirmDialog(Stepper.getUI().getUiComponent(),
                            "The request contains non UTF characters.\nStepper is able to make the replacements, " +
                                    "but some of the binary data may be lost. Continue?",
                            "Stepper Replacement Error", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    if(result == JOptionPane.NO_OPTION) return;
                }

                try {
                    byte[] newRequest = makeReplacementsForAllSequences(request, allVariables);

                    if(preferences.getSetting(Globals.PREF_UPDATE_REQUEST_LENGTH)){
                        newRequest = updateContentLength(newRequest);
                    }

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

    /**
     * Used to make replacements with variables from this sequence only.
     * Used for steps within a sequence.
     * @param originalContent
     * @param replacements
     * @return
     */
    public static byte[] makeReplacementsForSingleSequence(byte[] originalContent, List<StepVariable> replacements) {
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);
        boolean hasReplaced = false;

        String requestString = new String(request);

        for (StepVariable replacement : replacements) {
            //Find identifier in requestBody and replace with latest value.
            Matcher m = StepVariable.createIdentifierPattern(replacement).matcher(requestString);
            hasReplaced |= m.find();

            String replacementValue = replacement.getValue() == null ? "" : replacement.getValue();
            requestString = m.replaceAll(replacementValue);
        }

        request = requestString.getBytes();

        if(hasReplaced) {
            return request;
        }else{
            return originalContent;
        }
    }

    /**
     * Used to make replacements with variables from multiple sequences
     * Used when variables have been used in tools other than stepper.
     * @param originalContent
     * @param replacements
     * @return
     */
    public static byte[] makeReplacementsForAllSequences(byte[] originalContent,
                                                         HashMap<StepSequence, List<StepVariable>> replacements) {
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);
        boolean hasReplaced = false;

        String requestString = new String(request);

        for (Map.Entry<StepSequence, List<StepVariable>> sequenceEntry : replacements.entrySet()) {
            StepSequence sequence = sequenceEntry.getKey();
            List<StepVariable> variables = sequenceEntry.getValue();

            for (StepVariable replacement : variables) {
                //Find identifier in requestBody and replace with latest value.
                Matcher m = StepVariable.createIdentifierPatternWithSequence(sequence, replacement).matcher(requestString);
                hasReplaced |= m.find();

                String replacementValue = replacement.getValue() == null ? "" : replacement.getValue();
                requestString = m.replaceAll(replacementValue);
            }
        }

        request = requestString.getBytes();

        if(hasReplaced) {
            return request;
        }else{
            return originalContent;
        }
    }

    public static byte[] updateContentLength(byte[] request){
        IRequestInfo newRequestInfo = Stepper.callbacks.getHelpers().analyzeRequest(request);
        List<String> newRequestHeaders = newRequestInfo.getHeaders();
        int contentLength = request.length - newRequestInfo.getBodyOffset();
        newRequestHeaders.removeIf(header -> header.startsWith("Content-Length:"));
        newRequestHeaders.add("Content-Length: " + contentLength);

        byte[] newBody = Arrays.copyOfRange(request, newRequestInfo.getBodyOffset(), request.length);

        return Stepper.callbacks.getHelpers().buildHttpMessage(newRequestHeaders, newBody);
    }

    /**
     * Locates the X-Stepper-Execute-Before header and returns the matching sequence.
     * @param requestInfo
     * @return Optional value of step sequence to execute before the request.
     */
    public List<StepSequence> extractPostExecSequencesFromRequest(IRequestInfo requestInfo){
        //Check if headers ask us to execute a request before the request.
        List<String> requestHeaders = requestInfo.getHeaders();
        ArrayList<StepSequence> postExecSequences = new ArrayList<>();

        for (Iterator<String> iterator = requestHeaders.iterator(); iterator.hasNext(); ) {
            String header = iterator.next();
            Matcher m = MessageProcessor.EXECUTE_BEFORE_PATTERN.matcher(header);
            if (m.matches()) {
                Optional<StepSequence> postExecSequence = sequenceManager.getSequences().stream()
                        .filter(sequence -> sequence.getTitle().equalsIgnoreCase(m.group(1).trim()))
                        .findFirst();

                if(postExecSequence.isPresent())
                    postExecSequences.add(postExecSequence.get());
            }
        }
        return postExecSequences;
    }

    public static boolean hasHeaderMatchingPattern(IRequestInfo requestInfo, Pattern pattern){
        return requestInfo.getHeaders().stream().anyMatch(s -> pattern.asPredicate().test(s));
    }

    public static byte[] addHeaderToRequest(byte[] request, String header){
        IRequestInfo requestInfo = Stepper.callbacks.getHelpers().analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        headers.add(header);

        byte[] messageBody = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);

        return Stepper.callbacks.getHelpers().buildHttpMessage(headers, messageBody);
    }

    public static byte[] removeHeaderMatchingPattern(byte[] request, Pattern pattern){
        IRequestInfo newRequestInfo = Stepper.callbacks.getHelpers().analyzeRequest(request);
        List<String> newRequestHeaders = newRequestInfo.getHeaders();
        newRequestHeaders.removeIf(s -> {
            Matcher m = pattern.matcher(s);
            return m.matches();
        });

        byte[] messageBody = Arrays.copyOfRange(request, newRequestInfo.getBodyOffset(), request.length);

        return Stepper.callbacks.getHelpers().buildHttpMessage(newRequestHeaders, messageBody);
    }
}

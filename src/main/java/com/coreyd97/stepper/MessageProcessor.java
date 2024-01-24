package com.coreyd97.stepper;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.util.ReplacingInputStream;
import com.coreyd97.stepper.variable.StepVariable;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageProcessor implements IHttpListener {

    private final SequenceManager sequenceManager;
    private final Preferences preferences;
    public static final String EXECUTE_BEFORE_HEADER = "X-Stepper-Execute-Before";
    public static final String EXECUTE_AFTER_HEADER = "X-Stepper-Execute-After";
    public static final String EXECUTE_BEFORE_REGEX = EXECUTE_BEFORE_HEADER + ":(.*)";
    public static final String EXECUTE_AFTER_REGEX = EXECUTE_AFTER_HEADER+":(.*)";
    public static final String EXECUTE_AFTER_COMMENT_DELIMITER = "#%~%#";
    public static final Pattern EXECUTE_BEFORE_HEADER_PATTERN = Pattern.compile("^" + EXECUTE_BEFORE_REGEX + "$", Pattern.CASE_INSENSITIVE);
    public static final Pattern EXECUTE_AFTER_HEADER_PATTERN = Pattern.compile("^" + EXECUTE_AFTER_REGEX + "$", Pattern.CASE_INSENSITIVE);
    public static final String STEPPER_IGNORE_HEADER = "X-Stepper-Ignore";
    public static final Pattern STEPPER_IGNORE_PATTERN = Pattern.compile("^"+STEPPER_IGNORE_HEADER, Pattern.CASE_INSENSITIVE);

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

        if(isValidTool(toolFlag)){

            if(messageIsRequest){
                byte[] request = messageInfo.getRequest();
                System.out.println("Request: " + messageInfo.getRequest());
                List<StepSequence> preExecSequences = extractExecSequencesFromRequest(requestInfo, EXECUTE_BEFORE_HEADER_PATTERN);
                if(preExecSequences.size() > 0){
                    //Remove the headers from the request
                    request = removeHeaderMatchingPattern(request, EXECUTE_BEFORE_HEADER_PATTERN);

                    //Execute the sequences
                    for (StepSequence sequence : preExecSequences) {
                        sequence.executeBlocking();
                    }
                }

                List<StepSequence> postExecSequences = extractExecSequencesFromRequest(requestInfo, EXECUTE_AFTER_HEADER_PATTERN);

                if(postExecSequences.size() > 0){
                    //Remove the headers from the request
                    request = removeHeaderMatchingPattern(request, EXECUTE_AFTER_HEADER_PATTERN);

                    //Joining the sequences as string to set them as a comment to catch them in the response
                    String postExecSequencesJoined = EXECUTE_AFTER_HEADER + ":";
                    for (StepSequence sequence : postExecSequences) {
                        postExecSequencesJoined += sequence.getTitle() + EXECUTE_AFTER_COMMENT_DELIMITER;
                    }

                    if(!postExecSequencesJoined.isEmpty()){
                        messageInfo.setComment(messageInfo.getComment() + postExecSequencesJoined);
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
                        request = makeReplacementsForAllSequences(request, allVariables);

                        if(preferences.getSetting(Globals.PREF_UPDATE_REQUEST_LENGTH)){
                            request = updateContentLength(request);
                        }
                    } catch (UnsupportedOperationException e) { /**Read-only message**/ }
                }

                //Save any changes made to the request.
                messageInfo.setRequest(request);
            }else{
                // this is a response so we check for the comments
                List<StepSequence> postExecSequences = extractExecSequencesFromComment(messageInfo.getComment(), EXECUTE_AFTER_HEADER_PATTERN);
                if(postExecSequences.size() > 0){
                    //Execute the sequences
                    for (StepSequence sequence : postExecSequences) {
                        sequence.executeBlocking();
                    }
                    // remove the added comment from the request
                    messageInfo.setComment(messageInfo.getComment().replaceAll(EXECUTE_AFTER_REGEX+EXECUTE_AFTER_COMMENT_DELIMITER,""));
                }
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
     * @param variables
     * @return
     */
    public static byte[] makeReplacementsForSingleSequence(byte[] originalContent, List<StepVariable> variables) {
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);

        List<ReplacingInputStream.Replacement> replacements = new ArrayList<>();
        for (StepVariable variable : variables) {
            String match = StepVariable.createVariableString(variable.getIdentifier());
            String replace = variable.getValue();
            ReplacingInputStream.Replacement replacement = new ReplacingInputStream.Replacement(match.getBytes(StandardCharsets.UTF_8), replace.getBytes(StandardCharsets.UTF_8));
            replacements.add(replacement);
        }
        ReplacingInputStream inputStream = new ReplacingInputStream(new ByteArrayInputStream(request), replacements);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int b;
        try {
            while (-1 != (b = inputStream.read())) {
                bos.write(b);
            }
        }catch (IOException e){ /**TODO**/ }

        return bos.toByteArray();
    }

    /**
     * Used to make replacements with variables from multiple sequences
     * Used when variables have been used in tools other than stepper.
     * @param originalContent
     * @param sequenceVariableMap
     * @return
     */
    public static byte[] makeReplacementsForAllSequences(byte[] originalContent,
                                                         HashMap<StepSequence, List<StepVariable>> sequenceVariableMap) {
        byte[] request = Arrays.copyOf(originalContent, originalContent.length);

        List<ReplacingInputStream.Replacement> replacements = new ArrayList<>();
        for (Map.Entry<StepSequence, List<StepVariable>> sequenceEntry : sequenceVariableMap.entrySet()) {
            StepSequence sequence = sequenceEntry.getKey();
            List<StepVariable> variables = sequenceEntry.getValue();
            for (StepVariable variable : variables) {
                String match = StepVariable.createVariableString(sequence.getTitle(), variable.getIdentifier());
                String replace = variable.getValue();
                ReplacingInputStream.Replacement replacement = new ReplacingInputStream.Replacement(match.getBytes(StandardCharsets.UTF_8), replace.getBytes(StandardCharsets.UTF_8));
                replacements.add(replacement);
            }
        }
        ReplacingInputStream inputStream = new ReplacingInputStream(new ByteArrayInputStream(request), replacements);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int b;
        try {
            while (-1 != (b = inputStream.read())) {
                bos.write(b);
            }
        }catch (IOException e){ /**TODO**/ }

        return bos.toByteArray();
    }

    public static byte[] updateContentLength(byte[] request){
        IRequestInfo requestInfo = Stepper.callbacks.getHelpers().analyzeRequest(request);
        List<String> newRequestHeaders = requestInfo.getHeaders();
        byte[] newBody = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);

        //The method below automatically updates content-length.
        return Stepper.callbacks.getHelpers().buildHttpMessage(newRequestHeaders, newBody);
    }

    /**
     * Locates the X-Stepper-Execute-Before or X-Stepper-Execute-After headers and returns the matching sequences.
     * @param requestInfo
     * @param pattern
     * @return Optional value of step sequence to execute before or after the request.
     */
    public List<StepSequence> extractExecSequencesFromRequest(IRequestInfo requestInfo, Pattern pattern){
        //Check if headers ask us to execute a request before the request.
        List<String> requestHeaders = requestInfo.getHeaders();
        ArrayList<StepSequence> execSequences = new ArrayList<>();

        for (Iterator<String> iterator = requestHeaders.iterator(); iterator.hasNext(); ) {
            String header = iterator.next();
            Matcher m = pattern.matcher(header);
            if (m.matches()) {
                Optional<StepSequence> execSequence = sequenceManager.getSequences().stream()
                        .filter(sequence -> sequence.getTitle().equalsIgnoreCase(m.group(1).trim()))
                        .findFirst();

                if(execSequence.isPresent())
                    execSequences.add(execSequence.get());
                else
                    JOptionPane.showMessageDialog(Stepper.getUI().getUiComponent(), "Could not find execution sequence named: \"" + m.group(1).trim() + "\".");
            }
        }
        return execSequences;
    }

    /**
     * Locates the X-Stepper-Execute-After pattern in the comment and returns the matching sequences.
     * @param comment
     * @param pattern
     * @return Optional value of step sequence to execute after the request.
     */
    public List<StepSequence> extractExecSequencesFromComment(String comment, Pattern pattern){
        ArrayList<StepSequence> execSequences = new ArrayList<>();
        Matcher m = pattern.matcher(comment);
        if (m.find()) {
            String[] allSequences = m.group(1).split(EXECUTE_AFTER_COMMENT_DELIMITER);
            for(String sequenceName : allSequences){
                if(sequenceName != null && !sequenceName.isEmpty()){
                    Optional<StepSequence> execSequence = sequenceManager.getSequences().stream()
                            .filter(sequence -> sequence.getTitle().equalsIgnoreCase(sequenceName.trim()))
                            .findFirst();

                    if(execSequence.isPresent())
                        execSequences.add(execSequence.get());
                    else
                        JOptionPane.showMessageDialog(Stepper.getUI().getUiComponent(), "Could not find execution sequence named: \"" + m.group(1).trim() + "\".");
                }
            }
        }

        return execSequences;
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

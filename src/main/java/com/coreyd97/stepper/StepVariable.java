package com.coreyd97.stepper;

import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class StepVariable {

    public enum ChangeType {IDENTIFIER, REGEX, VALUE}

    String identifier = null;
    Pattern regex = null;
    String regexString = null;
    String latestValue;
    static String variablePrepend = "$VAR:";
    static String variableAppend = "$";

    private ArrayList<IStepVariableListener> listeners;

    public StepVariable(){
        this.listeners = new ArrayList<>();
    }

    public StepVariable(String identifier, Pattern regex){
        this();
        this.identifier = identifier;
        this.regex = regex;
        this.latestValue = "";
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
        for (IStepVariableListener listener : this.listeners) {
            try {
                listener.onVariableChange(this, ChangeType.IDENTIFIER);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public Pattern getRegex() {
        return regex;
    }

    public void setRegex(Pattern regex) {
        this.regex = regex;
        for (IStepVariableListener listener : listeners) {
            try{
                listener.onVariableChange(this, ChangeType.REGEX);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public String getRegexString() {
        return regexString;
    }

    public void setRegexString(String regexString) {
        try {
            setRegex(Pattern.compile(regexString, Pattern.DOTALL));
        }catch (PatternSyntaxException e){
            setRegex(null);
        }
        this.regexString = regexString;
    }

    public void setLatestValue(String latestValue) {
        this.latestValue = latestValue;
        for (IStepVariableListener listener : this.listeners) {
            try{
                listener.onVariableChange(this, ChangeType.VALUE);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public String getLatestValue() {
        return this.latestValue;
    }

    public boolean isValidRegex(){
        return this.regex != null;
    }

    public void addVariableListener(IStepVariableListener listener){
        this.listeners.add(listener);
    }

    public void removeVariableListener(IStepVariableListener listener){
        this.listeners.remove(listener);
    }

    public void clearVariableListeners(){
        this.listeners.clear();
    }

    public static Pattern createIdentifierPattern(String identifier){
        return Pattern.compile(Pattern.quote(createVariableString(identifier)), Pattern.CASE_INSENSITIVE);
    }

    public static Pattern createIdentifierPattern(StepVariable stepVariable){
        return createIdentifierPattern(stepVariable.getIdentifier());
    }

    public Pattern createIdentifierPattern(){
        return StepVariable.createIdentifierPattern(this);
    }

    public static Pattern createIdentifierCaptureRegex(){
        return Pattern.compile(Pattern.quote(variablePrepend) + "(.*?)" + Pattern.quote(variableAppend));
    }

    public static String createVariableString(String identifier){
        return variablePrepend + identifier + variableAppend;
    }

    public static String createVariableString(StepVariable stepVariable){
        return createVariableString(stepVariable.getIdentifier());
    }

    public String createVariableString(){
        return createVariableString(this.getIdentifier());
    }
}

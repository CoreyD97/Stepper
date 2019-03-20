package com.coreyd97.stepper;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.coreyd97.stepper.ui.StepperUI;
import com.coreyd97.stepper.ui.VariableReplacementsTabFactory;

import javax.swing.*;
import java.util.ArrayList;

public class Stepper implements IBurpExtender {

    public static IBurpExtenderCallbacks callbacks;
    public static Stepper instance;
    //Vars
    private final ArrayList<StepSequence> stepSequences;
    private final ArrayList<IStepSequenceListener> stepSequenceListeners;
    private final IGsonProvider gsonProvider;

    private StepperUI ui;
    private Preferences preferences;
    private StateManager stateManager;
    private MessageProcessor messageProcessor;

    public Stepper(){
        Stepper.instance = this;
        this.gsonProvider = new DefaultGsonProvider();
        this.gsonProvider.registerTypeAdapter(new TypeToken<StepSequence>(){}.getType(), new StepSequenceSerializer(this));
        this.gsonProvider.registerTypeAdapter(new TypeToken<SequenceGlobals>(){}.getType(), new SequenceGlobalsSerializer());
        this.gsonProvider.registerTypeAdapter(new TypeToken<Step>(){}.getType(), new StepSerializer());
        this.gsonProvider.registerTypeAdapter(new TypeToken<StepVariable>(){}.getType(), new StepVariableSerializer());

        this.stepSequences = new ArrayList<>();
        this.stepSequenceListeners = new ArrayList<>();

        //Fix Darcula's issue with JSpinner UI.
        try {
            Class spinnerUI = Class.forName("com.bulenkov.darcula.ui.DarculaSpinnerUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSpinnerUI", spinnerUI);
        } catch (ClassNotFoundException e) {
            //Darcula is not installed.
        }
    }

    public static Stepper getInstance() {
        return instance;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Stepper.callbacks = callbacks;
        this.preferences = new Preferences(this.gsonProvider, callbacks);
        configurePreferences();
        this.stateManager = new StateManager(this, this.preferences);
        this.addStepSequenceListener(this.stateManager);
        this.messageProcessor = new MessageProcessor(this, this.preferences);

        SwingUtilities.invokeLater(() -> {
            ui = new StepperUI(this);
            Stepper.callbacks.addSuiteTab(Stepper.this.ui);
            Stepper.callbacks.registerMessageEditorTabFactory(new VariableReplacementsTabFactory(this));
            Stepper.callbacks.registerContextMenuFactory(new ContextMenuFactory(Stepper.this));
            Stepper.callbacks.registerExtensionStateListener(Stepper.this.stateManager);
            Stepper.callbacks.registerHttpListener(Stepper.this.messageProcessor);

            this.stateManager.loadSavedSequences();

            if(this.stepSequences.size() == 0) {
                addStepSequence(new StepSequence(this, true));
            }
        });

    }

    private void configurePreferences(){
        preferences.addSetting(Globals.PREF_STEP_SEQUENCES, new TypeToken<ArrayList<StepSequence>>(){}.getType());
        preferences.addSetting(Globals.PREF_PREV_VERSION, Double.class, Globals.version);
        preferences.addSetting(Globals.PREF_VARS_IN_ALL_TOOLS, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_EXTENDER, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_SEQUENCER, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_REPEATER, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_PROXY, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_INTRUDER, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_SPIDER, Boolean.class, true);
        preferences.addSetting(Globals.PREF_VARS_IN_SCANNER, Boolean.class, true);
    }

    public Preferences getPreferences() {
        return preferences;
    }

    public StepperUI getUI() {
        return this.ui;
    }

    public void addStepSequence(StepSequence sequence){
        this.stepSequences.add(sequence);
        for (IStepSequenceListener stepSequenceListener : this.stepSequenceListeners) {
            try {
                stepSequenceListener.onStepSequenceAdded(sequence);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void removeStepSet(StepSequence sequence){
        this.stepSequences.remove(sequence);
        for (IStepSequenceListener stepSequenceListener : stepSequenceListeners) {
            try {
                stepSequenceListener.onStepSequenceRemoved(sequence);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void addStepSequenceListener(IStepSequenceListener listener){
        this.stepSequenceListeners.add(listener);
    }

    public void removeStepSequenceListener(IStepSequenceListener listener){
        this.stepSequenceListeners.remove(listener);
    }

    public ArrayList<StepSequence> getSequences() {
        return this.stepSequences;
    }

    public IGsonProvider getGsonProvider() {
        return gsonProvider;
    }
}

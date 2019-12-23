package com.coreyd97.stepper.preferences.view;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.PreferenceFactory;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.stepper.Globals;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequence.globals.SequenceGlobals;
import com.coreyd97.stepper.sequence.globals.SequenceGlobalsSerializer;
import com.coreyd97.stepper.sequence.serializer.StepSequenceSerializer;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.step.serializer.StepSerializer;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.serializer.StepVariableSerializer;
import com.google.gson.reflect.TypeToken;

import java.util.ArrayList;

public class StepperPreferenceFactory extends PreferenceFactory {

    public StepperPreferenceFactory(String extensionIdentifier, IGsonProvider gsonProvider, IBurpExtenderCallbacks callbacks) {
        super(extensionIdentifier, gsonProvider, callbacks);
    }

    @Override
    protected void createDefaults() {

    }

    @Override
    protected void registerTypeAdapters() {
        gsonProvider.registerTypeAdapter(new TypeToken<StepSequence>(){}.getType(), new StepSequenceSerializer());
        gsonProvider.registerTypeAdapter(new TypeToken<SequenceGlobals>(){}.getType(), new SequenceGlobalsSerializer());
        gsonProvider.registerTypeAdapter(new TypeToken<Step>(){}.getType(), new StepSerializer());
        gsonProvider.registerTypeAdapter(new TypeToken<StepVariable>(){}.getType(), new StepVariableSerializer());
    }

    @Override
    protected void registerSettings() {
        prefs.registerSetting(Globals.PREF_STEP_SEQUENCES, new TypeToken<ArrayList<StepSequence>>(){}.getType(), Preferences.Visibility.PROJECT);
        prefs.registerSetting(Globals.PREF_PREV_VERSION, Double.class, Globals.VERSION, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_ALL_TOOLS, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_EXTENDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_SEQUENCER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_REPEATER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_PROXY, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_INTRUDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_SPIDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(Globals.PREF_VARS_IN_SCANNER, Boolean.class, true, Preferences.Visibility.GLOBAL);
    }
}

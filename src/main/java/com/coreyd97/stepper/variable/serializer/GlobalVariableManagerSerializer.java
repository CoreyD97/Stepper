package com.coreyd97.stepper.variable.serializer;

import com.coreyd97.stepper.sequence.GlobalVariableManager;
import com.coreyd97.stepper.variable.StepVariable;
import com.coreyd97.stepper.variable.VariableManager;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Vector;

public class GlobalVariableManagerSerializer implements JsonSerializer<GlobalVariableManager>, JsonDeserializer<GlobalVariableManager> {

    @Override
    public GlobalVariableManager deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
//        GlobalVariableManager sequenceGlobals = new GlobalVariableManager();
//        JsonObject obj = json.getAsJsonObject();
//        Vector<StepVariable> variables = context.deserialize(
//                jsonObject.getAsJsonArray("variables"),
//                new TypeToken<List<StepVariable>>(){}.getType());
//        for (StepVariable variable : variables) {
//            sequenceGlobals.addVariable(variable);
//        }
//        return sequenceGlobals;
        return null;
    }

    @Override
    public JsonElement serialize(GlobalVariableManager src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject json = new JsonObject();
//        json.add("variables", context.serialize(src.getVariables(), new TypeToken<List<StepVariable>>(){}.getType()));
        return json;
    }
}

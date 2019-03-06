package com.coreyd97.stepper;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Vector;

public class SequenceGlobalsSerializer implements JsonSerializer<SequenceGlobals>, JsonDeserializer<SequenceGlobals> {


    @Override
    public SequenceGlobals deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        SequenceGlobals sequenceGlobals = new SequenceGlobals();
        JsonObject obj = json.getAsJsonObject();
        Vector<StepVariable> variables = context.deserialize(
                jsonObject.getAsJsonArray("variables"),
                new TypeToken<Vector<StepVariable>>(){}.getType());
        for (StepVariable variable : variables) {
            sequenceGlobals.addVariable(variable);
        }
        return sequenceGlobals;
    }

    @Override
    public JsonElement serialize(SequenceGlobals src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject json = new JsonObject();
        json.add("variables", context.serialize(src.getVariables(), new TypeToken<Vector<StepVariable>>(){}.getType()));
        return json;
    }
}

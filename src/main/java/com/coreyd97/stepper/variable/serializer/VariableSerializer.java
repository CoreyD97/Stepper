package com.coreyd97.stepper.variable.serializer;

import com.coreyd97.stepper.variable.PromptVariable;
import com.coreyd97.stepper.variable.RegexVariable;
import com.coreyd97.stepper.variable.StepVariable;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

public class VariableSerializer implements JsonDeserializer<StepVariable> {

    @Override
    public StepVariable deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = (JsonObject) json;
        if (jsonObject.has("type")) {
            switch (jsonObject.get("type").getAsString().toLowerCase()) {
                case "regex": {
                    return context.deserialize(json, new TypeToken<RegexVariable>() {}.getType());
                }
                case "prompt": {
                    return context.deserialize(json, new TypeToken<PromptVariable>() {}.getType());
                }
                default: throw new IllegalArgumentException("Unable to deserialize variable :(");
            }
        }

        //If no type, fall back to backwards compatibility and default to regex
        return context.deserialize(json, new TypeToken<RegexVariable>(){}.getType());
    }
}

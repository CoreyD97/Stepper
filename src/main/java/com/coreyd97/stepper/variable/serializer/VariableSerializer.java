package com.coreyd97.stepper.variable.serializer;

import com.coreyd97.stepper.variable.PromptVariable;
import com.coreyd97.stepper.variable.RegexVariable;
import com.coreyd97.stepper.variable.StepVariable;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

public class VariableSerializer implements JsonSerializer<StepVariable>, JsonDeserializer<StepVariable> {

    @Override
    public StepVariable deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = (JsonObject) json;
        if (jsonObject.has("type")) {
            Type deserializationType = null;
            switch (jsonObject.get("type").getAsString().toLowerCase()) {
                case "regex": {
                    deserializationType = new TypeToken<RegexVariable>() {}.getType();
                    break;
                }
                case "prompt": {
                    deserializationType = new TypeToken<PromptVariable>(){}.getType();
                    break;
                }
            }
            if(deserializationType != null){
                return context.deserialize(json, deserializationType);
            }
        }

        //If no type, fall back to backwards compatibility and default to regex
        return context.deserialize(json, new TypeToken<RegexVariable>(){}.getType());
    }

    @Override
    public JsonElement serialize(StepVariable src, Type typeOfSrc, JsonSerializationContext context) {
        if(src instanceof RegexVariable) return context.serialize(src, new TypeToken<RegexVariable>(){}.getType());
        if(src instanceof PromptVariable) return context.serialize(src, new TypeToken<PromptVariable>(){}.getType());

        throw new IllegalArgumentException("Unable to serialize variable of type: " + src.getClass().getName());
    }
}

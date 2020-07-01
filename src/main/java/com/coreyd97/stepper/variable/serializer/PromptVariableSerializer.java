package com.coreyd97.stepper.variable.serializer;

import com.coreyd97.stepper.variable.PromptVariable;
import com.coreyd97.stepper.variable.RegexVariable;
import com.google.gson.*;

import java.lang.reflect.Type;

public class PromptVariableSerializer implements JsonSerializer<PromptVariable>, JsonDeserializer<PromptVariable> {
    @Override
    public PromptVariable deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        PromptVariable stepVariable = new PromptVariable();
        stepVariable.setIdentifier(jsonObject.get("identifier") != null ? jsonObject.get("identifier").getAsString() : "" );
        if(jsonObject.has("value")) {
            stepVariable.setValue(jsonObject.get("value").getAsString());
        }
        return stepVariable;
    }

    @Override
    public JsonElement serialize(PromptVariable src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject obj = new JsonObject();
        obj.addProperty("type", src.getType());
        obj.addProperty("identifier", src.getIdentifier());
        obj.addProperty("value", src.getValue());
        return obj;
    }
}

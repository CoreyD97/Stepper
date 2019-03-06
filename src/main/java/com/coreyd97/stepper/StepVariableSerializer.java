package com.coreyd97.stepper;

import com.google.gson.*;

import java.lang.reflect.Type;

public class StepVariableSerializer implements JsonSerializer<StepVariable>, JsonDeserializer<StepVariable> {
    @Override
    public StepVariable deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        StepVariable stepVariable = new StepVariable();
        stepVariable.setIdentifier(jsonObject.get("identifier") != null ? jsonObject.get("identifier").getAsString() : "" );
        if(jsonObject.has("value")) {
            stepVariable.setLatestValue(jsonObject.get("value").getAsString());
        }
        stepVariable.setRegexString(jsonObject.get("pattern") != null ? jsonObject.get("pattern").getAsString() : "" );
        return stepVariable;
    }

    @Override
    public JsonElement serialize(StepVariable src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject obj = new JsonObject();
        obj.addProperty("identifier", src.getIdentifier());
        obj.addProperty("value", src.getLatestValue());
        obj.addProperty("pattern", src.getRegexString());
        return obj;
    }
}

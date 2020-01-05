package com.coreyd97.stepper.variable.serializer;

import com.coreyd97.stepper.variable.RegexVariable;
import com.google.gson.*;

import java.lang.reflect.Type;

public class RegexVariableSerializer implements JsonSerializer<RegexVariable>, JsonDeserializer<RegexVariable> {
    @Override
    public RegexVariable deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        RegexVariable stepVariable = new RegexVariable();
        stepVariable.setIdentifier(jsonObject.get("identifier") != null ? jsonObject.get("identifier").getAsString() : "" );
        if(jsonObject.has("value")) {
            stepVariable.setValue(jsonObject.get("value").getAsString());
        }
        stepVariable.setCondition(jsonObject.get("pattern") != null ? jsonObject.get("pattern").getAsString() : "" );
        return stepVariable;
    }

    @Override
    public JsonElement serialize(RegexVariable src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject obj = new JsonObject();
        obj.addProperty("identifier", src.getIdentifier());
        obj.addProperty("value", src.getValue());
        obj.addProperty("pattern", src.getConditionText());
        return obj;
    }
}

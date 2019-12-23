package com.coreyd97.stepper.sequence.serializer;

import com.coreyd97.stepper.sequence.globals.SequenceGlobals;
import com.coreyd97.stepper.sequence.StepSequence;
import com.coreyd97.stepper.sequencemanager.SequenceManager;
import com.coreyd97.stepper.step.Step;
import com.coreyd97.stepper.Stepper;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Vector;

public class StepSequenceSerializer implements JsonSerializer<StepSequence>, JsonDeserializer<StepSequence> {

    @Override
    public StepSequence deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        StepSequence stepSequence = new StepSequence( false);
        JsonObject obj = json.getAsJsonObject();
        stepSequence.setTitle(obj.get("title") != null ? obj.get("title").getAsString() : "" );
        if(obj.has("globals")) {
            SequenceGlobals sequenceGlobals = context.deserialize(obj.getAsJsonObject("globals"), new TypeToken<SequenceGlobals>() {
            }.getType());
            stepSequence.setSequenceGlobals(sequenceGlobals);
        }
        Vector<Step> steps = context.deserialize(obj.getAsJsonArray("steps"), new TypeToken<Vector<Step>>(){}.getType());
        for (Step step : steps) {
            stepSequence.addStep(step);
        }
        return stepSequence;
    }

    @Override
    public JsonElement serialize(StepSequence src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject json = new JsonObject();
        json.addProperty("title", src.getTitle());
        json.add("globals", context.serialize(src.getSequenceGlobals(), new TypeToken<SequenceGlobals>(){}.getType()));
        json.add("steps", context.serialize(src.getSteps(), new TypeToken<Vector<Step>>(){}.getType()));
        return json;
    }
}

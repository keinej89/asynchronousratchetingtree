package com.facebook.research.asynchronousratchetingtree.art.message;

import java.lang.reflect.Type;

import com.facebook.research.asynchronousratchetingtree.art.tree.Node;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class NodeTypeAdapter implements JsonSerializer<Node>, JsonDeserializer<Node> {

	private static final String CLASS_PROPERTY = "_class";

	@Override
	public JsonElement serialize(Node src, Type typeOfSrc, JsonSerializationContext context) {
		JsonObject jsonObj = (JsonObject) context.serialize(src);
		jsonObj.addProperty(CLASS_PROPERTY, src.getClass().getName());
		
		return jsonObj;
	}
	
	@Override
	public Node deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
			throws JsonParseException {
		JsonObject obj = json.getAsJsonObject();
		String clazz = obj.get(CLASS_PROPERTY).getAsString();
		
		try {
			return context.deserialize(json, Class.forName(clazz));
		} catch (ClassNotFoundException e) {
			throw new IllegalArgumentException("Class not found: "+clazz);
		}
	}

}

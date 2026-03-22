package eu.trustbeat.sdk;

import eu.trustbeat.sdk.internal.Json;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void parsesFlatObject() {
        String json = "{\"id\":\"track-1\",\"status\":\"pending\",\"overage\":false}";
        Map<String, Object> m = Json.parseObject(json);
        assertEquals("track-1", Json.str(m, "id"));
        assertEquals("pending", Json.str(m, "status"));
        assertFalse(Json.bool(m, "overage", true));
    }

    @Test
    void parsesNullField() {
        Map<String, Object> m = Json.parseObject("{\"client_ref\":null}");
        assertNull(Json.str(m, "client_ref"));
    }

    @Test
    void parsesNestedArray() {
        String json = "{\"accepted\":[{\"id\":\"t1\"},{\"id\":\"t2\"}]}";
        Map<String, Object> m = Json.parseObject(json);
        List<Map<String, Object>> items = Json.array(m, "accepted");
        assertEquals(2, items.size());
        assertEquals("t1", Json.str(items.get(0), "id"));
        assertEquals("t2", Json.str(items.get(1), "id"));
    }

    @Test
    void parsesIntField() {
        Map<String, Object> m = Json.parseObject("{\"leaf_index\":3}");
        assertEquals(3, Json.intVal(m, "leaf_index"));
    }

    @Test
    void parsesEscapedString() {
        Map<String, Object> m = Json.parseObject("{\"msg\":\"hello\\\"world\"}");
        assertEquals("hello\"world", Json.str(m, "msg"));
    }

    @Test
    void buildObjectOmitsNullValues() {
        String json = Json.buildObject("hash", "aabbcc", "client_ref", null);
        assertFalse(json.contains("client_ref"), "null values should be omitted");
        assertTrue(json.contains("\"hash\":\"aabbcc\""));
    }

    @Test
    void buildObjectProducesValidJson() {
        String json = Json.buildObject("hash", "abc", "flag", true, "count", 5L);
        Map<String, Object> m = Json.parseObject(json);
        assertEquals("abc", Json.str(m, "hash"));
        assertTrue(Json.bool(m, "flag", false));
        assertEquals(5, Json.intVal(m, "count"));
    }
}

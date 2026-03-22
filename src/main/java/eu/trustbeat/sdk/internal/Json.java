package eu.trustbeat.sdk.internal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal zero-dependency JSON parser.
 *
 * Supports the subset of JSON returned by the TrustBeat API:
 * objects, arrays of objects, strings, numbers, booleans, null.
 * Not a general-purpose parser — no Unicode escapes beyond \" \\ \n \r \t.
 */
public final class Json {

    private Json() {}

    // ── Public entry points ────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        return (Map<String, Object>) new Parser(json).parseValue();
    }

    // ── Parser ─────────────────────────────────────────────────────────────────

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s.trim(); }

        Object parseValue() {
            skipWs();
            if (pos >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON");
            char c = s.charAt(pos);
            if (c == '{')  return parseObject();
            if (c == '[')  return parseArray();
            if (c == '"')  return parseString();
            if (c == 't')  return parseLiteral("true",  Boolean.TRUE);
            if (c == 'f')  return parseLiteral("false", Boolean.FALSE);
            if (c == 'n')  return parseLiteral("null",  null);
            if (c == '-' || Character.isDigit(c)) return parseNumber();
            throw new IllegalArgumentException("Unexpected char '" + c + "' at pos " + pos);
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs(); expect(':');
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                char ch = s.charAt(pos);
                if (ch == '}') { pos++; break; }
                if (ch == ',') { pos++; continue; }
                throw new IllegalArgumentException("Expected ',' or '}' at pos " + pos);
            }
            return map;
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(parseValue());
                skipWs();
                char ch = s.charAt(pos);
                if (ch == ']') { pos++; break; }
                if (ch == ',') { pos++; continue; }
                throw new IllegalArgumentException("Expected ',' or ']' at pos " + pos);
            }
            return list;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"':  sb.append('"');  break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/');  break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        default:   sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private Object parseLiteral(String token, Object value) {
            if (s.startsWith(token, pos)) { pos += token.length(); return value; }
            throw new IllegalArgumentException("Expected '" + token + "' at pos " + pos);
        }

        private Number parseNumber() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') pos++;
            while (pos < s.length() && (Character.isDigit(s.charAt(pos)) ||
                   s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E' ||
                   s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
            String num = s.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E"))
                return Double.parseDouble(num);
            return Long.parseLong(num);
        }

        private void expect(char c) {
            if (pos >= s.length() || s.charAt(pos) != c)
                throw new IllegalArgumentException("Expected '" + c + "' at pos " + pos);
            pos++;
        }

        private char peek() {
            return pos < s.length() ? s.charAt(pos) : 0;
        }

        private void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }
    }

    // ── Convenience getters ────────────────────────────────────────────────────

    public static String str(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v == null ? null : v.toString();
    }

    public static boolean bool(Map<String, Object> m, String key, boolean def) {
        Object v = m.get(key);
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String)  return Boolean.parseBoolean((String) v);
        return def;
    }

    public static int intVal(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        return 0;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> array(Map<String, Object> m, String key) {
        Object v = m.get(key);
        if (v instanceof List) {
            List<?> raw = (List<?>) v;
            List<Map<String, Object>> result = new ArrayList<>(raw.size());
            for (Object item : raw) {
                if (item instanceof Map) {
                    result.add((Map<String, Object>) item);
                }
            }
            return result;
        }
        return new ArrayList<>();
    }

    // ── Minimal builder for request bodies ────────────────────────────────────

    /** Builds a JSON object string from key-value pairs. Values are auto-typed. */
    public static String buildObject(Object... pairs) {
        if (pairs.length % 2 != 0) throw new IllegalArgumentException("pairs must be even");
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (int i = 0; i < pairs.length; i += 2) {
            String key = (String) pairs[i];
            Object val = pairs[i + 1];
            if (val == null) continue;  // omit null values
            if (!first) sb.append(",");
            first = false;
            sb.append('"').append(escapeString(key)).append("\":");
            appendValue(sb, val);
        }
        sb.append("}");
        return sb.toString();
    }

    private static void appendValue(StringBuilder sb, Object val) {
        if (val == null)             { sb.append("null"); }
        else if (val instanceof Boolean) { sb.append(val); }
        else if (val instanceof Number)  { sb.append(val); }
        else if (val instanceof String)  { sb.append('"').append(escapeString((String) val)).append('"'); }
        else if (val instanceof List) {
            sb.append("[");
            boolean first = true;
            for (Object item : (List<?>) val) {
                if (!first) sb.append(",");
                first = false;
                appendValue(sb, item);
            }
            sb.append("]");
        } else {
            sb.append('"').append(escapeString(val.toString())).append('"');
        }
    }

    private static String escapeString(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}

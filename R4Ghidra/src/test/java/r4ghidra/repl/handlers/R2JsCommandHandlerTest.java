package r4ghidra.repl.handlers;

import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2Context;

/** Regression tests for JSON output from JavaScript values. */
public final class R2JsCommandHandlerTest {
  public static void run(R2Context context) throws Exception {
    int sandboxFlags = context.getSandboxFlags();
    context.setSandboxFlags(R2Context.R_SANDBOX_GRAIN_NONE);
    try {
      R2JsCommandHandler handler = new R2JsCommandHandler();
      for (String value :
          List.of("", "plain", "\"quoted\"", "C:\\new\\test\\", "\\n", "λ 😀", "\u2028\u2029")) {
        checkString(handler, context, JSONObject.quote(value), value);
      }
      for (int i = 0; i < 32; i++) {
        checkString(handler, context, "String.fromCharCode(" + i + ")", String.valueOf((char) i));
      }
      checkString(
          handler,
          context,
          "String.fromCharCode(92,34,44,34,105,110,106,101,99,116,101,100,34,58,116,114,117,101)",
          "\\\",\"injected\":true");

      check(json(handler, context, "42").equals("42\n"), "number output");
      check(json(handler, context, "true").equals("true\n"), "boolean output");
      String nested = json(handler, context, "({text: 'a\\nb\\tc\\\\d', values: [1, true, null]})");
      JSONObject object = new JSONObject(nested);
      check(object.getString("text").equals("a\nb\tc\\d"), "nested string");
      check(object.getJSONArray("values").similar(new JSONArray("[1,true,null]")), "nested array");

      check(
          new JSONArray(json(handler, context, "['a\\nb', 'c\\\\d']"))
              .toList()
              .equals(List.of("a\nb", "c\\d")),
          "array output");

      // Serializing an object must never evaluate its textual representation as source code.
      json(handler, context, "var serializedTextExecuted = false");
      json(handler, context, "new java.lang.StringBuilder('(serializedTextExecuted = true)')");
      check(
          json(handler, context, "serializedTextExecuted").equals("false\n"),
          "object text was evaluated");

      // Circular values retain the handler's string fallback.
      checkString(
          handler, context, "var cyclic = {}; cyclic.self = cyclic; cyclic", "[object Object]");

      // Force the fallback with a host value whose textual representation needs escaping.
      checkString(
          handler,
          context,
          "JSON.stringify = function() { throw new Error('forced'); };"
              + "new java.lang.StringBuilder('a\\nb\\tc\\\\d\\\"')",
          "a\nb\tc\\d\"");
      System.out.println("JavaScript JSON regression tests passed");
    } finally {
      context.setSandboxFlags(sandboxFlags);
    }
  }

  private static String json(R2JsCommandHandler handler, R2Context context, String script)
      throws Exception {
    return handler.execute(new R2Command("js", "j", List.of(script), null), context);
  }

  private static void checkString(
      R2JsCommandHandler handler, R2Context context, String script, String expected)
      throws Exception {
    String output = json(handler, context, script);
    check(output.endsWith("\n"), "missing output newline");
    for (int i = 0; i < output.length() - 1; i++) {
      check(output.charAt(i) >= 32, "unescaped control character in JSON output");
    }
    JSONTokener tokener = new JSONTokener(output);
    check(expected.equals(tokener.nextValue()), "JSON string did not round-trip: " + output);
    check(tokener.nextClean() == 0, "extra data after JSON string: " + output);
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}

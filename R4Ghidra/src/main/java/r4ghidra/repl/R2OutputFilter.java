package r4ghidra.repl;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Implements radare2 output filtering functionality
 *
 * <p>This class handles the various ~ filter modifiers for radare2 commands: - ~pattern - Grep
 * filter, only shows lines matching the pattern - ~pattern1,pattern2 - Grep filter with multiple
 * patterns (OR logic) - ~&pattern1,pattern2 - Grep filter with multiple patterns (AND logic) - ~{}
 * - Pretty-prints JSON output - ~? - Counts lines in output (like wc -l)
 */
public class R2OutputFilter {

  // Pattern for detecting filter expressions
  private static final Pattern FILTER_PATTERN =
      Pattern.compile(
          "(.*?)~(&?|!)(\\{\\}|\\?|([^\\s\\[]+)(\\[(\\d+(?:,\\d+)*)\\])?|\\[(\\d+(?:,\\d+)*)\\])");

  /**
   * Extract command and filter from a command string
   *
   * @param cmdStr The command string that may contain a filter
   * @return An array with [command, filter, andLogic, columns] or null if no filter is present
   *     Where columns is a comma-separated list of column indices or null if not specified
   */
  public static String[] extractCommandAndFilter(String cmdStr) {
    if (cmdStr == null || cmdStr.isEmpty()) {
      return null;
    }

    // Special case for help command
    if (cmdStr.equals("~?")) {
      return new String[] {"", "?", "false", null};
    } else if (cmdStr.equals("~&?")) {
      return new String[] {"", "?", "true", null};
    }

    // Check if the command contains a filter
    Matcher matcher = FILTER_PATTERN.matcher(cmdStr);
    if (matcher.matches()) {
      String command = matcher.group(1).trim();
      String operator = matcher.group(2); // "&", "!" or empty
      String filter = matcher.group(3);
      boolean isAndLogic = "&".equals(operator);
      boolean isNegationLogic = "!".equals(operator);

      // Extract column specification if present
      String columns = null;
      if (matcher.group(6) != null) { // Pattern with text and brackets: mov[0]
        columns = matcher.group(6);
        filter = matcher.group(4); // Just the pattern part without brackets
      } else if (matcher.group(7) != null) { // Pattern with only brackets: [0]
        columns = matcher.group(7);
        filter = ""; // No pattern, show all lines but filter columns
      }

      return new String[] {
        command, filter, String.valueOf(isAndLogic), columns, String.valueOf(isNegationLogic)
      };
    }

    return null;
  }

  /**
   * Apply a filter to command output
   *
   * @param output The command output to filter
   * @param filter The filter to apply
   * @param useAndLogic Whether to use AND logic for multiple patterns
   * @param columns Column specification (comma-separated list of column indices) or null
   * @return The filtered output
   */
  public static String applyFilter(
      String output, String filter, boolean useAndLogic, String columns, boolean useNegationLogic) {
    // Handle empty output
    if (output == null || output.isEmpty()) {
      return "";
    }

    // Handle empty filter with no columns
    if ((filter == null || filter.isEmpty()) && (columns == null || columns.isEmpty())) {
      return output;
    }

    // Handle line count filter (~? or ~&?)
    if (filter.equals("?")) {
      return countLines(output);
    }

    // Handle JSON pretty print filter (~{} or ~&{})
    if (filter.equals("{}")) {
      return prettyPrintJson(output);
    }

    // First apply grep filter if there is one
    String filteredOutput;
    if (filter != null && !filter.isEmpty()) {
      filteredOutput = grepLines(output, filter, useAndLogic, useNegationLogic);
    } else {
      filteredOutput = output;
    }

    // Then apply column filter if specified
    if (columns != null && !columns.isEmpty()) {
      return filterColumns(filteredOutput, columns);
    }

    return filteredOutput;
  }

  /**
   * Apply a filter to command output (backward compatibility)
   *
   * @param output The command output to filter
   * @param filter The filter to apply
   * @return The filtered output
   */
  public static String applyFilter(String output, String filter) {
    // Check if the filter includes the ! operator for negation
    boolean useNegation = filter != null && filter.startsWith("!");
    // Strip the ! prefix if present
    String actualFilter = useNegation && filter.length() > 1 ? filter.substring(1) : filter;

    return applyFilter(
        output,
        actualFilter,
        false,
        null,
        useNegation); // Default to OR logic, detected negation, no columns
  }

  /**
   * Apply a filter to command output (backward compatibility)
   *
   * @param output The command output to filter
   * @param filter The filter to apply
   * @param useAndLogic Whether to use AND logic for multiple patterns
   * @return The filtered output
   */
  public static String applyFilter(String output, String filter, boolean useAndLogic) {
    // Check if the filter includes the ! operator for negation
    boolean useNegation = filter != null && filter.startsWith("!");
    // Strip the ! prefix if present
    String actualFilter = useNegation && filter.length() > 1 ? filter.substring(1) : filter;

    return applyFilter(
        output, actualFilter, useAndLogic, null, useNegation); // No columns, detected negation
  }

  /**
   * Count lines in output
   *
   * @param output The output to count lines in
   * @return The number of lines as a string
   */
  private static String countLines(String output) {
    // Split by newlines and count non-empty lines
    String[] lines = output.split("\n");
    return String.valueOf(lines.length);
  }

  /**
   * Pretty print JSON output
   *
   * @param output The JSON output to pretty print
   * @return The pretty printed JSON
   */
  private static String prettyPrintJson(String output) {
    try {
      // Try to parse as JSON object
      try {
        JSONObject jsonObject = new JSONObject(output.trim());
        return jsonObject.toString(2);
      } catch (JSONException e) {
        // Try to parse as JSON array
        JSONArray jsonArray = new JSONArray(output.trim());
        return jsonArray.toString(2);
      }
    } catch (JSONException e) {
      // If not valid JSON, return the original output
      return "Error: Invalid JSON format\n" + output;
    }
  }

  /**
   * Grep lines matching one or more patterns
   *
   * @param output The output to grep
   * @param patternStr The pattern(s) to match, comma-separated for multiple patterns
   * @param useAndLogic Whether to use AND logic (all patterns must match) instead of OR logic
   * @param useNegationLogic Whether to use negation logic (exclude lines that match)
   * @return The filtered output
   */
  private static String grepLines(
      String output, String patternStr, boolean useAndLogic, boolean useNegationLogic) {
    String[] lines = output.split("\n");
    List<String> matchedLines = new ArrayList<>();

    // Check if we have multiple patterns (comma-separated)
    String[] patterns = patternStr.split(",");

    // Convert each pattern to a regex pattern
    List<Pattern> regexPatterns = new ArrayList<>();
    for (String pattern : patterns) {
      regexPatterns.add(Pattern.compile(convertGlobToRegex(pattern)));
    }

    // Check each line against all patterns with appropriate logic
    for (String line : lines) {
      boolean shouldAdd = false;

      if (useAndLogic) {
        // AND logic - all patterns must match
        boolean allMatch = true;
        for (Pattern pattern : regexPatterns) {
          Matcher matcher = pattern.matcher(line);
          if (!matcher.find()) {
            allMatch = false;
            break;
          }
        }
        shouldAdd = allMatch;
      } else {
        // OR logic - at least one pattern must match
        boolean anyMatch = false;
        for (Pattern pattern : regexPatterns) {
          Matcher matcher = pattern.matcher(line);
          if (matcher.find()) {
            anyMatch = true;
            break;
          }
        }
        shouldAdd = anyMatch;
      }

      // If using negation logic, invert the result
      if (useNegationLogic) {
        shouldAdd = !shouldAdd;
      }

      if (shouldAdd) {
        matchedLines.add(line);
      }
    }

    // Join matched lines
    return String.join("\n", matchedLines);
  }

  /**
   * Convert a glob pattern to a regex pattern
   *
   * @param glob The glob pattern
   * @return The regex pattern
   */
  private static String convertGlobToRegex(String glob) {
    StringBuilder regex = new StringBuilder();

    // Handle common glob patterns
    if (glob.startsWith("^")) {
      // Beginning of line anchor
      regex.append("^");
      glob = glob.substring(1);
    }

    if (glob.endsWith("$")) {
      // End of line anchor
      glob = glob.substring(0, glob.length() - 1);
      regex.append(Pattern.quote(glob)).append("$");
    } else {
      // Normal case - convert * to .*
      String quoted = Pattern.quote(glob);
      quoted = quoted.replace("*", "\\E.*\\Q");
      regex.append(quoted);
    }

    return regex.toString();
  }

  /** Get help information about filter syntax */
  /**
   * Filter specific columns from the output
   *
   * @param output The output text to filter
   * @param columnsSpec Comma-separated list of column indices (0-based)
   * @return The filtered output containing only the specified columns
   */
  private static String filterColumns(String output, String columnsSpec) {
    // Parse column indices
    String[] columnIndicesStr = columnsSpec.split(",");
    int[] columnIndices = new int[columnIndicesStr.length];

    for (int i = 0; i < columnIndicesStr.length; i++) {
      try {
        columnIndices[i] = Integer.parseInt(columnIndicesStr[i]);
      } catch (NumberFormatException e) {
        // Invalid column index, default to 0
        columnIndices[i] = 0;
      }
    }

    // Split output by lines and process each line
    String[] lines = output.split("\n");
    StringBuilder result = new StringBuilder();

    for (String line : lines) {
      if (line.trim().isEmpty()) {
        continue;
      }

      // Split the line by whitespace
      String[] columns = line.trim().split("\\s+");

      // Extract the specified columns
      StringBuilder filteredLine = new StringBuilder();
      boolean first = true;

      for (int colIndex : columnIndices) {
        if (colIndex >= 0 && colIndex < columns.length) {
          if (!first) {
            filteredLine.append(" ");
          }
          filteredLine.append(columns[colIndex]);
          first = false;
        }
      }

      // Add the filtered line to the result if it's not empty
      if (filteredLine.length() > 0) {
        result.append(filteredLine).append("\n");
      }
    }

    return result.toString();
  }

  public static String getFilterHelp() {
    StringBuilder sb = new StringBuilder();
    sb.append("Output Filter Syntax:\n");
    sb.append("  command~pattern                grep: filter lines matching pattern\n");
    sb.append("  command~pattern1,pattern2,...   grep: filter lines matching any pattern (OR)\n");
    sb.append("  command~&pattern1,pattern2,...  grep: filter lines matching all patterns (AND)\n");
    sb.append(
        "  command~!pattern               grep: filter lines NOT matching pattern (negation)\n");
    sb.append(
        "  command~!pattern1,pattern2,...  grep: filter lines NOT matching any pattern (negated"
            + " OR)\n");
    sb.append("  command~pattern[N]              column: filter lines and show only column N\n");
    sb.append("  command~[N]                    column: show only column N from all lines\n");
    sb.append(
        "  command~pattern[N,M,...]        column: show columns N, M, etc. from matching lines\n");
    sb.append("  command~{}                      json: pretty print JSON output\n");
    sb.append("  command~?                       count: count number of lines (wc -l)\n");
    sb.append("\nPattern modifiers:\n");
    sb.append("  ^pattern           match at start of line\n");
    sb.append("  pattern$           match at end of line\n");
    sb.append("  pat*tern           glob-style wildcard matching\n");
    sb.append("\nExamples:\n");
    sb.append("  pd~call,mov        show lines containing either 'call' OR 'mov'\n");
    sb.append("  pd~&mov,rax        show lines containing both 'mov' AND 'rax'\n");
    sb.append("  pd~!call           show lines NOT containing 'call'\n");
    sb.append("  pd~mov[0]          show first column of lines containing 'mov'\n");
    sb.append("  afl~[1]            show only the second column of function list\n");
    return sb.toString();
  }
}

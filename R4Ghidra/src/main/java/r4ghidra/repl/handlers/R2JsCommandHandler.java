package r4ghidra.repl.handlers;

import java.util.List;
import java.util.function.Function;
import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.R2REPLImpl;

/**
 * Handler for the 'js' command
 * 
 * <p>This command allows users to evaluate JavaScript expressions using the Nashorn engine.
 * It also provides an r2pipe-like interface via a global 'r2' object.
 */
public class R2JsCommandHandler implements R2CommandHandler {

  // The JavaScript engine
  private ScriptEngine engine;
  
  // Reference to the REPL for executing r2 commands
  private R2REPLImpl repl;
  
  /**
   * Create a new JavaScript command handler
   */
  public R2JsCommandHandler() {
    // Initialize the Nashorn engine
    NashornScriptEngineFactory factory = new NashornScriptEngineFactory();
    engine = factory.getScriptEngine();
    
    // Get the singleton instance of the REPL
    try {
      // Use reflection to access the static instance field
      java.lang.reflect.Field instanceField = R2REPLImpl.class.getDeclaredField("instance");
      instanceField.setAccessible(true);
      repl = (R2REPLImpl) instanceField.get(null);
    } catch (Exception e) {
      // If we can't get the instance, create a new one
      repl = new R2REPLImpl();
    }
  }

  @Override
  public String execute(R2Command command, R2Context context) throws R2CommandException {
    // Check if this is a 'js' command
    if (!command.hasPrefix("js")) {
      throw new R2CommandException("Not a JavaScript command");
    }
    
    String script;
    // Get the script from arguments or subcommand
    if (command.getArgumentCount() > 0) {
      // Join all arguments into one script
      script = String.join(" ", command.getArguments());
    } else if (!command.getSubcommand().isEmpty()) {
      script = command.getSubcommand();
    } else {
      throw new R2CommandException("No JavaScript expression provided");
    }
    
    try {
      // Set up the r2 object with cmd() function before evaluating the script
      setupR2Interface(context);
      
      // Evaluate the script
      Object result;
      if (command.hasSuffix('e')) {
        // Evaluate without printing the result
        engine.eval(script);
        return "";
      } else {
        // Evaluate and return the result
        result = engine.eval(script);
        
        if (result == null) {
          return "undefined\n";
        }
        
        // Format the result based on the suffix
        if (command.hasSuffix('j')) {
          // JSON output - try to convert the result to JSON
          try {
            String jsonResult = convertToJSON(result);
            return jsonResult + "\n";
          } catch (Exception e) {
            return "{\"error\":\"Cannot convert result to JSON\"}\n";
          }
        } else {
          // Regular output
          return result.toString() + "\n";
        }
      }
    } catch (ScriptException e) {
      // Return the JavaScript error
      return "JavaScript Error: " + e.getMessage() + "\n";
    }
  }

  /**
   * Set up the r2pipe-like interface in the JavaScript environment
   * 
   * @param context The R2Context to use for command execution
   * @throws ScriptException if the setup fails
   */
  private void setupR2Interface(R2Context context) throws ScriptException {
    // Create a bindings object for the engine
    Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
    
    // Create the r2 object
    String r2ObjectSetup = 
        "var r2 = {" +
        "  cmd: function(cmd) {" +
        "    return _cmd(cmd);" +
        "  }," +
        "  cmdj: function(cmd) {" +
        "    try {" +
        "      return JSON.parse(_cmd(cmd + 'j'));" +
        "    } catch(e) {" +
        "      return null;" +
        "    }" +
        "  }" +
        "};";
    
    // Define the _cmd function as a Java method reference
    bindings.put("_cmd", (Function<String, String>) (cmd) -> {
      try {
        return repl.executeCommand(cmd);
      } catch (Exception e) {
        return "Error: " + e.getMessage();
      }
    });
    
    // Evaluate the r2 object setup script
    engine.eval(r2ObjectSetup);
  }
  
  /**
   * Convert an object to JSON
   * 
   * @param obj The object to convert
   * @return A JSON string representation of the object
   */
  private String convertToJSON(Object obj) {
    if (obj == null) {
      return "null";
    } else if (obj instanceof Number || obj instanceof Boolean) {
      return obj.toString();
    } else if (obj instanceof String) {
      return "\"" + ((String) obj).replace("\"", "\\\"") + "\"";
    } else {
      // For other objects, try to use JavaScript's JSON.stringify
      try {
        return (String) engine.eval("JSON.stringify(" + obj.toString() + ")");
      } catch (Exception e) {
        return "\"" + obj.toString().replace("\"", "\\\"") + "\"";
      }
    }
  }

  @Override
  public String getHelp() {
    StringBuilder sb = new StringBuilder();
    sb.append("Usage: js[ej] <JavaScript expression>\n");
    sb.append(" js  <expr>       Evaluate JavaScript expression and print the result\n");
    sb.append(" jse <expr>       Evaluate JavaScript expression without printing the result\n");
    sb.append(" jsj <expr>       Evaluate and return result as JSON\n\n");
    sb.append("JavaScript Environment:\n");
    sb.append(" r2.cmd(str)      Run r4ghidra command and return output as string\n");
    sb.append(" r2.cmdj(str)     Run r4ghidra command with JSON output and parse as object\n\n");
    sb.append("Examples:\n");
    sb.append(" js 1+1                      # Print 2\n");
    sb.append(" js r2.cmd('pd 2')           # Run 'pd 2' command and print output\n");
    sb.append(" js r2.cmdj('e.j').configs   # Get eval vars as object and access configs property\n");
    sb.append(" js var x=1; x+1             # Local variables work as expected\n");
    sb.append(" js r2.cmd('s 0x100'); r2.cmd('pd 2')  # Multiple commands\n");
    return sb.toString();
  }
}
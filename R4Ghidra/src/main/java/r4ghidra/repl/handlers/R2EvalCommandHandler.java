package r4ghidra.repl.handlers;

import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONObject;

import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.config.R2EvalConfig;

/**
 * Handler for the 'e' (eval) command
 * 
 * This command allows users to view and set configuration variables.
 */
public class R2EvalCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if this is an 'e' command
        if (!command.hasPrefix("e")) {
            throw new R2CommandException("Not an eval command");
        }
        // Access the configuration manager
        R2EvalConfig config = context.getEvalConfig();
        
        // Determine expression: prefer the subcommand (without suffix), else first argument
        String rawSub = command.getSubcommandWithoutSuffix().trim();
        String expr;
        if (!rawSub.isEmpty()) {
            expr = rawSub;
        } else if (command.getArgumentCount() > 0) {
            expr = command.getFirstArgument("");
        } else {
            expr = "";
        }
        
        // List all variables when no expression provided
        if (expr.isEmpty()) {
            return formatEvalOutput(config.getAll(), command);
        }
        // Set variable when expression contains '='
        if (expr.contains("=")) {
            return handleSetVariable(expr, config, command);
        }
        // Query variables (specific or prefix)
        return handleQueryVariables(expr, config, command);
    }
    
    /**
     * Handle setting a variable
     */
    private String handleSetVariable(String subcommand, R2EvalConfig config, R2Command command) throws R2CommandException {
        // Parse key=value format
        int equalPos = subcommand.indexOf('=');
        String key = subcommand.substring(0, equalPos).trim();
        String value = subcommand.substring(equalPos + 1).trim();
        
        // Validate the key
        if (key.isEmpty()) {
            throw new R2CommandException("Invalid eval key");
        }
        
        // Special validation for certain keys
        if (key.equals("asm.bits")) {
            // Check if the value is one of the allowed bit widths
            if (!value.equals("8") && !value.equals("16") && 
                !value.equals("32") && !value.equals("64")) {
                throw new R2CommandException("Invalid value for asm.bits, must be 8, 16, 32, or 64");
            }
        } else if (key.equals("cfg.endian")) {
            // Check if the value is one of the allowed endian types
            if (!value.equalsIgnoreCase("big") && 
                !value.equalsIgnoreCase("little") && 
                !value.equalsIgnoreCase("middle")) {
                throw new R2CommandException("Invalid value for cfg.endian, must be big, little, or middle");
            }
        } else if (key.equals("scr.color")) {
            // Check if the value is a valid color level
            try {
                int colorLevel = Integer.parseInt(value);
                if (colorLevel < 0 || colorLevel > 3) {
                    throw new R2CommandException("Invalid value for scr.color, must be between 0 and 3");
                }
            } catch (NumberFormatException e) {
                throw new R2CommandException("Invalid value for scr.color, must be between 0 and 3");
            }
        }
        
        // Set the variable
        boolean changed = config.set(key, value);
        
        // Format the result based on the command suffix
        if (command.hasSuffix('q')) {
            // Quiet output - just return nothing
            return "";
        } else if (command.hasSuffix('j')) {
            // JSON output
            JSONObject json = new JSONObject();
            json.put("key", key);
            json.put("value", value);
            json.put("changed", changed);
            return json.toString() + "\n";
        } else {
            // Standard output
            return key + " = " + value + "\n";
        }
    }
    
    /**
     * Handle querying specific variable(s)
     */
    private String handleQueryVariables(String subcommand, R2EvalConfig config, R2Command command) throws R2CommandException {
        // If the subcommand ends with a dot, treat it as a prefix query
        if (subcommand.endsWith(".")) {
            String prefix = subcommand;
            Map<String, String> matches = config.getByPrefix(prefix);
            
            if (matches.isEmpty()) {
                return "No matching variables\n";
            }
            
            return formatEvalOutput(matches, command);
        } else {
            // Otherwise it's a specific variable query
            String key = subcommand;
            
            if (!config.contains(key)) {
                throw new R2CommandException("Unknown eval variable: " + key);
            }
            
            String value = config.get(key);
            
            // Format the result based on the command suffix
            if (command.hasSuffix('q')) {
                // Quiet output - just the value
                return value + "\n";
            } else if (command.hasSuffix('j')) {
                // JSON output
                JSONObject json = new JSONObject();
                json.put("key", key);
                json.put("value", value);
                return json.toString() + "\n";
            } else {
                // Standard output
                return key + " = " + value + "\n";
            }
        }
    }
    
    /**
     * Format the output of eval variables
     */
    private String formatEvalOutput(Map<String, String> vars, R2Command command) {
        if (command.hasSuffix('j')) {
            // JSON output
            JSONObject json = new JSONObject();
            JSONArray configs = new JSONArray();
            
            for (Map.Entry<String, String> entry : vars.entrySet()) {
                JSONObject configItem = new JSONObject();
                configItem.put("key", entry.getKey());
                configItem.put("value", entry.getValue());
                configs.put(configItem);
            }
            
            json.put("configs", configs);
            return json.toString() + "\n";
        } else if (command.hasSuffix('q')) {
            // Quiet output - just keys, one per line
            StringBuilder sb = new StringBuilder();
            for (String key : vars.keySet()) {
                sb.append(key).append("\n");
            }
            return sb.toString();
        } else if (command.hasSuffix('*')) {
            // R2 commands output
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : vars.entrySet()) {
                sb.append("e ").append(entry.getKey())
                  .append("=").append(entry.getValue()).append("\n");
            }
            return sb.toString();
        } else {
            // Standard output
            StringBuilder sb = new StringBuilder();
            int maxKeyLength = 0;
            
            // Find the longest key for nice alignment
            for (String key : vars.keySet()) {
                maxKeyLength = Math.max(maxKeyLength, key.length());
            }
            
            // Format the output
            for (Map.Entry<String, String> entry : vars.entrySet()) {
                sb.append(entry.getKey());
                
                // Pad to align the values
                int padding = maxKeyLength - entry.getKey().length() + 2;
                for (int i = 0; i < padding; i++) {
                    sb.append(' ');
                }
                
                sb.append("= ").append(entry.getValue()).append("\n");
            }
            
            return sb.toString();
        }
    }

    @Override
    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage: e[*jq] [key[=value]]\n");
        sb.append(" e                list all eval configuration variables\n");
        sb.append(" e key            get value of configuration variable\n");
        sb.append(" e key=value      set value of configuration variable\n");
        sb.append(" e.               list all eval vars matching a prefix\n");
        sb.append(" e*               list all eval vars as r2 commands\n");
        sb.append(" ej               list all eval vars in JSON format\n");
        sb.append(" eq               list only variable names, one per line\n\n");
        
        sb.append("Available variables:\n");
        sb.append(" asm.arch         set architecture (x86, arm, etc.)\n");
        sb.append(" asm.bits         set architecture bits (8, 16, 32, 64)\n");
        sb.append(" asm.cpu          set CPU variant (pentium, cortex, etc.)\n");
        sb.append(" asm.bytes        set bytes per instruction for display\n");
        sb.append(" cfg.bigendian    set big endian (true/false)\n");
        sb.append(" cfg.endian       set endian (big/little/middle)\n");
        sb.append(" cfg.sandbox      enable sandbox mode (true/false)\n");
        sb.append(" cfg.sandbox.grain list of sandboxed resources\n");
        sb.append(" scr.color        set color level (0-3)\n");
        sb.append(" scr.prompt       show prompt (true/false)\n");
        sb.append(" dir.tmp          set temporary directory\n");
        sb.append(" http.port        set HTTP server port\n");
        sb.append(" io.cache         enable I/O caching (true/false)\n");
        
        return sb.toString();
    }
}
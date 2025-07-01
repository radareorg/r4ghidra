package ghidrar2web.repl.handlers;

import java.util.Map;
import java.util.TreeMap;

import org.json.JSONObject;

import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;

/**
 * Handler for the '%' command - Manage environment variables
 * 
 * This handler provides a radare2-compatible interface for working with environment variables:
 * - % : List all environment variables
 * - %* : Show environment variables as r2 commands
 * - %j : Show environment variables in JSON format
 * - %SHELL : Print value of a specific environment variable
 * - %TMPDIR=/tmp : Set environment variable TMPDIR to "/tmp"
 */
public class R2EnvCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if this is a '%' command
        if (!command.hasPrefix("%")) {
            throw new R2CommandException("Not an environment command");
        }
        
        // Get the subcommand (the part after %)
        String subcommand = command.getSubcommand().trim();
        
        // Handle different subcommand types
        if (subcommand.isEmpty()) {
            // % - List all environment variables
            return listEnvironmentVariables();
        } else if (subcommand.equals("*")) {
            // %* - Show environment variables as r2 commands
            return listEnvironmentVariablesAsCommands();
        } else if (subcommand.equals("j")) {
            // %j - Show environment variables in JSON format
            return listEnvironmentVariablesAsJson();
        } else if (subcommand.contains("=")) {
            // %NAME=VALUE - Set environment variable
            return setEnvironmentVariable(subcommand);
        } else {
            // %NAME - Get specific environment variable
            return getEnvironmentVariable(subcommand);
        }
    }
    
    /**
     * List all environment variables
     * 
     * @return A string with all environment variables and their values
     */
    private String listEnvironmentVariables() {
        StringBuilder sb = new StringBuilder();
        
        // Get all environment variables and sort them alphabetically
        Map<String, String> sortedEnv = new TreeMap<>(System.getenv());
        
        // Format the output
        for (Map.Entry<String, String> entry : sortedEnv.entrySet()) {
            sb.append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * List all environment variables as r2 commands
     * 
     * @return A string with environment variables as r2 commands
     */
    private String listEnvironmentVariablesAsCommands() {
        StringBuilder sb = new StringBuilder();
        
        // Get all environment variables and sort them alphabetically
        Map<String, String> sortedEnv = new TreeMap<>(System.getenv());
        
        // Format the output as r2 commands
        for (Map.Entry<String, String> entry : sortedEnv.entrySet()) {
            sb.append("%").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * List all environment variables in JSON format
     * 
     * @return A JSON string with all environment variables
     */
    private String listEnvironmentVariablesAsJson() {
        JSONObject json = new JSONObject();
        
        // Get all environment variables
        Map<String, String> env = System.getenv();
        
        // Add all variables to JSON
        for (Map.Entry<String, String> entry : env.entrySet()) {
            json.put(entry.getKey(), entry.getValue());
        }
        
        return json.toString(2) + "\n";
    }
    
    /**
     * Set an environment variable
     * 
     * @param expr The expression in format NAME=VALUE
     * @return A confirmation message
     */
    private String setEnvironmentVariable(String expr) throws R2CommandException {
        // Parse the NAME=VALUE expression
        int equalIndex = expr.indexOf('=');
        String name = expr.substring(0, equalIndex).trim();
        String value = expr.substring(equalIndex + 1).trim();
        
        if (name.isEmpty()) {
            throw new R2CommandException("Empty variable name");
        }
        
        try {
            // Using reflection to set environment variable (as System.setenv is not available in Java)
            // This is a hack that works on most JVMs but is not guaranteed by the JVM specification
            Map<String, String> env = System.getenv();
            
            java.lang.reflect.Field field = env.getClass().getDeclaredField("m");
            field.setAccessible(true);
            
            @SuppressWarnings("unchecked")
            Map<String, String> writableEnv = (Map<String, String>) field.get(env);
            writableEnv.put(name, value);
            
            return "Environment variable set: " + name + "=" + value + "\n";
        } catch (Exception e) {
            throw new R2CommandException("Cannot set environment variable: " + e.getMessage() +
                    "\nNote: Some JVMs may not allow modifying environment variables at runtime");
        }
    }
    
    /**
     * Get the value of a specific environment variable
     * 
     * @param name The name of the environment variable
     * @return The value of the environment variable or an error message
     */
    private String getEnvironmentVariable(String name) {
        String value = System.getenv(name);
        
        if (value != null) {
            return value + "\n";
        } else {
            return "Environment variable not found: " + name + "\n";
        }
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: %[name[=value]]  Set each NAME to VALUE in the environment\n");
        help.append("| %             list all environment variables\n");
        help.append("| %*            show env vars as r2 commands\n");
        help.append("| %j            show env vars in JSON format\n");
        help.append("| %SHELL        prints SHELL value\n");
        help.append("| %TMPDIR=/tmp  sets TMPDIR value to \"/tmp\"\n");
        return help.toString();
    }
}
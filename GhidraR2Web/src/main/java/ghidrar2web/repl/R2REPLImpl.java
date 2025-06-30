package ghidrar2web.repl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;

/**
 * Radare2 REPL Implementation
 * 
 * This class provides a complete implementation of the radare2 REPL (Read-Eval-Print Loop)
 * with support for command parsing, execution, and special syntax handling.
 */
public class R2REPLImpl {
    
    // Root command registry - maps command prefixes to handlers
    private Map<String, R2CommandHandler> commandRegistry;
    
    // Context that can be accessed by command handlers
    private R2Context context;
    
    /**
     * Create a new R2 REPL implementation
     */
    public R2REPLImpl() {
        commandRegistry = new HashMap<>();
        context = new R2Context();
    }
    
    /**
     * Register a new command handler
     * 
     * @param prefix The command prefix (e.g., "s" for seek)
     * @param handler The handler implementation
     */
    public void registerCommand(String prefix, R2CommandHandler handler) {
        commandRegistry.put(prefix, handler);
    }
    
    /**
     * Parse and execute a command string
     * 
     * @param cmdStr The command string to execute
     * @return The result of the command execution
     */
    public String executeCommand(String cmdStr) {
        if (cmdStr == null || cmdStr.trim().isEmpty()) {
            return "";
        }
        
        try {
            // Parse the command
            R2Command cmd = parseCommand(cmdStr);
            
            // Handle special @ syntax for temporary seek
            Address originalSeek = null;
            if (cmd.hasTemporaryAddress()) {
                originalSeek = context.getCurrentAddress();
                context.setCurrentAddress(cmd.getTemporaryAddress());
            }
            
            // Find and execute the handler
            String result = executeCommandWithHandler(cmd);
            
            // Restore original seek position if we had a temporary seek
            if (cmd.hasTemporaryAddress() && context.getCurrentAddress().equals(cmd.getTemporaryAddress())) {
                context.setCurrentAddress(originalSeek);
            }
            
            return result;
        } catch (R2CommandException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * Find and execute the appropriate handler for a parsed command
     */
    private String executeCommandWithHandler(R2Command cmd) throws R2CommandException {
        String prefix = cmd.getPrefix();
        R2CommandHandler handler = commandRegistry.get(prefix);
        
        if (handler == null) {
            throw new R2CommandException("Unknown command: " + prefix);
        }
        
        return handler.execute(cmd, context);
    }
    
    /**
     * Parse a command string into an R2Command object
     */
    private R2Command parseCommand(String cmdStr) throws R2CommandException {
        // Extract any backtick command substitution
        cmdStr = processCommandSubstitution(cmdStr);
        
        // Split the command into the main part and any @ address part
        String[] atParts = cmdStr.split("@", 2);
        
        String mainCommand = atParts[0].trim();
        Address tempAddress = null;
        
        // If we have an @ part, parse the address
        if (atParts.length > 1) {
            String addrStr = atParts[1].trim();
            try {
                tempAddress = context.parseAddress(addrStr);
            } catch (Exception e) {
                throw new R2CommandException("Invalid address: " + addrStr);
            }
        }
        
        // Parse the main command into prefix, subcommands, and arguments
        if (mainCommand.isEmpty()) {
            throw new R2CommandException("Empty command");
        }
        
        String prefix = String.valueOf(mainCommand.charAt(0));
        String subcommand = mainCommand.length() > 1 ? mainCommand.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, but respect quoted strings
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Parse arguments with proper handling of quoted strings
            Pattern pattern = Pattern.compile("[^\\s\"']+|\"([^\"]*)\"|'([^']*)'");
            Matcher matcher = pattern.matcher(argsPart);
            
            while (matcher.find()) {
                if (matcher.group(1) != null) {
                    // Add double-quoted string without quotes
                    args.add(matcher.group(1));
                } else if (matcher.group(2) != null) {
                    // Add single-quoted string without quotes
                    args.add(matcher.group(2));
                } else {
                    // Add unquoted word
                    args.add(matcher.group());
                }
            }
        }
        
        return new R2Command(prefix, subcommand, args, tempAddress);
    }
    
    /**
     * Process any command substitution using backticks
     */
    private String processCommandSubstitution(String cmdStr) throws R2CommandException {
        // Find all backtick-enclosed content
        Pattern pattern = Pattern.compile("`([^`]*)`");
        Matcher matcher = pattern.matcher(cmdStr);
        StringBuffer result = new StringBuffer();
        
        while (matcher.find()) {
            String innerCommand = matcher.group(1);
            String innerResult = executeCommand(innerCommand).trim();
            matcher.appendReplacement(result, Matcher.quoteReplacement(innerResult));
        }
        
        matcher.appendTail(result);
        return result.toString();
    }
    
    /**
     * Get the current context
     */
    public R2Context getContext() {
        return context;
    }
}
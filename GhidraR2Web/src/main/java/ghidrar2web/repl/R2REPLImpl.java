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
            // Check for output filter (~)
            String[] cmdAndFilter = R2OutputFilter.extractCommandAndFilter(cmdStr);
            if (cmdAndFilter != null) {
                String cmd = cmdAndFilter[0];
                String filter = cmdAndFilter[1];
                
                // Special case for help command
                if (cmd.isEmpty() && filter.equals("?")) {
                    return R2OutputFilter.getFilterHelp();
                }
                
                // Execute the command and apply the filter
                String result = executeCommand(cmd);
                return R2OutputFilter.applyFilter(result, filter);
            }
            
            // Handle special case for dot commands (.)
            if (cmdStr.startsWith(".")) {
                return executeDotCommand(cmdStr);
            }
            
            // Handle special case for quoted commands (')
            if (cmdStr.startsWith("'")) {
                return executeQuotedCommand(cmdStr);
            }
            
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
     * Execute a dot command (.) that runs a command and then processes its output as r2 commands
     * 
     * @param dotCmdStr The dot command string
     * @return The combined result of executing all resulting commands
     */
    private String executeDotCommand(String dotCmdStr) throws R2CommandException {
        // Remove the leading dot
        String cmdStr = dotCmdStr.substring(1).trim();
        
        if (cmdStr.isEmpty()) {
            throw new R2CommandException("Empty dot command");
        }
        
        // Execute the command to get its output
        String cmdOutput = executeCommand(cmdStr);
        
        // Process the output as a series of r2 commands
        StringBuilder result = new StringBuilder();
        
        // Split by lines and execute each line as a separate command
        String[] lines = cmdOutput.split("\\n");
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                // Execute the command and append its output to the result
                try {
                    String lineResult = executeCommand(line);
                    if (lineResult != null && !lineResult.isEmpty()) {
                        result.append(lineResult);
                        // Add a newline if one isn't already present
                        if (!lineResult.endsWith("\n")) {
                            result.append("\n");
                        }
                    }
                } catch (Exception e) {
                    // Log the error but continue processing other lines
                    result.append("Error executing command '")
                          .append(line)
                          .append("': ")
                          .append(e.getMessage())
                          .append("\n");
                }
            }
        }
        
        return result.toString();
    }
    
    /**
     * Execute a command that starts with a single quote.
     * This will process the command as a literal string without interpreting special characters.
     * 
     * @param quotedStr The quoted command string
     * @return The result of the command execution
     */
    private String executeQuotedCommand(String quotedStr) throws R2CommandException {
        // Remove the leading single quote
        String cmdStr = quotedStr.substring(1);
        
        // Create a command object directly, no special character processing
        if (cmdStr.isEmpty()) {
            throw new R2CommandException("Empty quoted command");
        }
        
        String prefix = String.valueOf(cmdStr.charAt(0));
        String subcommand = cmdStr.length() > 1 ? cmdStr.substring(1) : "";
        
        List<String> args = new ArrayList<>();
        
        // Parse arguments based on spaces, without any special character processing
        if (subcommand.contains(" ")) {
            int spacePos = subcommand.indexOf(" ");
            String argsPart = subcommand.substring(spacePos).trim();
            subcommand = subcommand.substring(0, spacePos);
            
            // Simple space-separated args, no processing of quotes or other special chars
            String[] argArray = argsPart.split("\\s+");
            for (String arg : argArray) {
                if (!arg.trim().isEmpty()) {
                    args.add(arg.trim());
                }
            }
        }
        
        // No temporary address or command substitution for quoted commands
        R2Command cmd = new R2Command(prefix, subcommand, args, null);
        
        // Execute the command directly
        return executeCommandWithHandler(cmd);
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
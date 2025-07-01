package r4ghidra.repl.handlers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.num.R2NumUtil;
import r4ghidra.repl.num.R2NumException;

/**
 * Handler for the '?' (help) command
 */
public class R2HelpCommandHandler implements R2CommandHandler {
    // Registry of all available commands for help lookup
    private Map<String, R2CommandHandler> commandRegistry;

    /**
     * Create a new help command handler
     * 
     * @param commandRegistry Reference to the command registry for looking up command help
     */
    public R2HelpCommandHandler(Map<String, R2CommandHandler> commandRegistry) {
        this.commandRegistry = commandRegistry;
    }

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's a '?' command
        if (!command.hasPrefix("?")) {
            throw new R2CommandException("Not a help command");
        }

        // Check for recursive help suffix (?*)
        if (command.hasRecursiveHelpSuffix()) {
            return handleRecursiveHelp(command);
        }

        // Get the subcommand without any suffix
        String subcommand = command.getSubcommandWithoutSuffix();
        
        // '?' with no subcommand - general help
        if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
            return formatHelpOutput(getGeneralHelp(), command);
        }
        
        // '?' with an argument - help for specific command
        if (subcommand.isEmpty() && command.getArgumentCount() > 0) {
            String cmdName = command.getFirstArgument("");
            if (cmdName.isEmpty()) {
                return formatHelpOutput(getGeneralHelp(), command);
            }
            
            // Get the first character as the command prefix
            String prefix = cmdName.substring(0, 1);
            R2CommandHandler handler = commandRegistry.get(prefix);
            
            if (handler == null) {
                throw new R2CommandException("Unknown command: " + prefix);
            }
            
            return formatHelpOutput(handler.getHelp(), command);
        }
        
        // Handle help subcommands
        switch (subcommand) {
            // '?V' - version information
            case "V":
                return formatHelpOutput(getVersionInfo(), command);
            
            // '?v' - evaluate expression in hex
            case "v":
                if (command.getArgumentCount() == 0) {
                    throw new R2CommandException("Missing expression for ?v");
                }
                return evaluateExpressionInHex(command.getFirstArgument(""), context);
                
            // '?vi' - evaluate expression in decimal
            case "vi":
                if (command.getArgumentCount() == 0) {
                    throw new R2CommandException("Missing expression for ?vi");
                }
                return evaluateExpressionInDecimal(command.getFirstArgument(""), context);
                
            // Handle space after ? (e.g., '? 123') - multi-base display
            case "":
                if (command.getArgumentCount() > 0) {
                    return evaluateExpressionMultiBase(command.getFirstArgument(""), context);
                }
                // Fall through to default for regular help
                
            default:
                throw new R2CommandException("Unknown help subcommand: ?" + subcommand);
        }
    }

    /**
     * Format help output according to the command suffix
     */
    private String formatHelpOutput(String helpText, R2Command command) {
        if (command.hasSuffix('j')) {
            // JSON output
            String[] lines = helpText.split("\n");
            JSONObject json = new JSONObject();
            JSONArray commands = new JSONArray();
            
            // Special handling for recursive help
            if (command.hasRecursiveHelpSuffix()) {
                json.put("type", "recursive_help");
                JSONObject sections = new JSONObject();
                
                String currentSection = null;
                JSONArray currentSectionCommands = null;
                
                for (String line : lines) {
                    // Check for section markers === command ===
                    if (line.startsWith("===") && line.endsWith("===")) {
                        // Extract section name
                        String section = line.substring(3, line.length() - 3).trim();
                        currentSection = section;
                        currentSectionCommands = new JSONArray();
                        sections.put(section, currentSectionCommands);
                    } else if (currentSection != null && !line.trim().isEmpty()) {
                        // Add line to current section
                        JSONObject cmdHelp = new JSONObject();
                        int dashPos = line.indexOf(" - ");
                        if (dashPos > 0) {
                            String cmdName = line.substring(0, dashPos).trim();
                            String desc = line.substring(dashPos + 3).trim();
                            cmdHelp.put("command", cmdName);
                            cmdHelp.put("description", desc);
                        } else {
                            cmdHelp.put("text", line);
                        }
                        currentSectionCommands.put(cmdHelp);
                    }
                }
                
                json.put("sections", sections);
            } else {
                // Standard help output
                // First line is usually the usage line
                if (lines.length > 0) {
                    json.put("usage", lines[0]);
                }
                
                // Remaining lines are individual command descriptions
                for (int i = 1; i < lines.length; i++) {
                    String line = lines[i].trim();
                    if (!line.isEmpty()) {
                        JSONObject cmdHelp = new JSONObject();
                        // Try to extract command name and description
                        int dashPos = line.indexOf(" - ");
                        if (dashPos > 0) {
                            String cmdName = line.substring(0, dashPos).trim();
                            String desc = line.substring(dashPos + 3).trim();
                            cmdHelp.put("command", cmdName);
                            cmdHelp.put("description", desc);
                        } else {
                            cmdHelp.put("text", line);
                        }
                        commands.put(cmdHelp);
                    }
                }
                
                json.put("commands", commands);
            }
            
            return json.toString() + "\n";
        } else if (command.hasSuffix('q')) {
            // Quiet output - just command names, one per line
            StringBuilder sb = new StringBuilder();
            String[] lines = helpText.split("\n");
            
            for (int i = 1; i < lines.length; i++) { // Skip the usage line
                String line = lines[i].trim();
                if (!line.isEmpty()) {
                    int dashPos = line.indexOf(" - ");
                    if (dashPos > 0) {
                        String cmdName = line.substring(0, dashPos).trim();
                        sb.append(cmdName).append("\n");
                    }
                }
            }
            
            return sb.toString();
        } else {
            // Standard output
            return helpText;
        }
    }

    /**
     * Generate general help text by combining brief help from all registered commands
     */
    private String getGeneralHelp() {
        StringBuilder msg = new StringBuilder("Usage: [r4ghidra-command .. args]\n\n");
        
        // Sort commands alphabetically for consistent help display
        Map<String, R2CommandHandler> sortedCommands = new TreeMap<>(commandRegistry);
        
        // Extract first line of help from each command
        List<String> helpLines = new ArrayList<>();
        for (Map.Entry<String, R2CommandHandler> entry : sortedCommands.entrySet()) {
            // Skip including help for the help command itself
            if (entry.getKey().equals("?")) {
                helpLines.add("?             - show this help message");
                helpLines.add("?V            - show Ghidra Version information");
                helpLines.add("? [cmd]       - show help for the specified command");
                continue;
            }
            
            String commandHelp = entry.getValue().getHelp();
            if (commandHelp != null && !commandHelp.isEmpty()) {
                // Extract the brief description lines (skipping usage line)
                String[] lines = commandHelp.split("\n");
                for (int i = 1; i < lines.length; i++) {
                    if (!lines[i].trim().isEmpty()) {
                        helpLines.add(lines[i]);
                    }
                }
            }
        }
        
        // Add all help lines to the message
        for (String line : helpLines) {
            msg.append(line).append("\n");
        }
        
        // Add syntax information
        msg.append("\n");
        msg.append("Command syntax:\n");
        msg.append("  @[addr]     - Use temporary seek (address) for this command\n");
        msg.append("  `cmd`       - Command substitution - replace with output of cmd\n");
        msg.append("  *           - Output as r2 commands\n");
        msg.append("  j           - Output as JSON\n");
        msg.append("  q           - Quiet mode (minimal output)\n");
        msg.append("  ,           - Output as table/CSV\n");
        msg.append("  ?           - Command help\n");
        
        return msg.toString();
    }
    
    /**
     * Generate version information
     */
    private String getVersionInfo() {
        return "R4Ghidra 1.0\n";
    }

    /**
     * Evaluate a numeric expression and display the result in hexadecimal
     */
    private String evaluateExpressionInHex(String expr, R2Context context) throws R2CommandException {
        try {
            long value = R2NumUtil.evaluateExpression(context, expr);
            return "0x" + Long.toHexString(value) + "\n";
        } catch (R2NumException e) {
            throw new R2CommandException("Error evaluating expression: " + e.getMessage());
        }
    }
    
    /**
     * Evaluate a numeric expression and display the result in decimal
     */
    private String evaluateExpressionInDecimal(String expr, R2Context context) throws R2CommandException {
        try {
            long value = R2NumUtil.evaluateExpression(context, expr);
            return Long.toString(value) + "\n";
        } catch (R2NumException e) {
            throw new R2CommandException("Error evaluating expression: " + e.getMessage());
        }
    }
    
    /**
     * Evaluate a numeric expression and display the result in multiple bases
     */
    private String evaluateExpressionMultiBase(String expr, R2Context context) throws R2CommandException {
        try {
            long value = R2NumUtil.evaluateExpression(context, expr);
            StringBuilder sb = new StringBuilder();
            
            // Display the value in different formats
            sb.append("int32   ").append((int)value).append("\n");
            sb.append("uint32  ").append(Integer.toUnsignedLong((int)value)).append("\n");
            sb.append("hex     0x").append(Long.toHexString(value)).append("\n");
            sb.append("octal   0").append(Long.toOctalString(value)).append("\n");
            
            // Add string representation if value is in ASCII range
            if (value > 0 && value <= 127) {
                sb.append("string  \"").append((char)value).append("\"\n");
            }
            
            // Binary representation
            sb.append("binary  0b").append(Long.toBinaryString(value)).append("\n");
            
            return sb.toString();
        } catch (R2NumException e) {
            throw new R2CommandException("Error evaluating expression: " + e.getMessage());
        }
    }
    
    /**
     * Handle recursive help command (?*)
     * 
     * @param command The command with recursive help suffix
     * @return The recursive help output
     * @throws R2CommandException If there's an error getting recursive help
     */
    private String handleRecursiveHelp(R2Command command) throws R2CommandException {
        StringBuilder allHelp = new StringBuilder();
        
        // Check if there's an argument for filtering specific commands
        String filter = command.getArgumentCount() > 0 ? command.getFirstArgument("") : null;
        
        // Get recursive help for all commands
        if (filter != null && !filter.isEmpty()) {
            // If a filter is provided, only show help for matching commands
            allHelp.append("Recursive help for commands matching: " + filter + "\n\n");
        } else {
            allHelp.append("Recursive help for all commands\n\n");
        }
        
        // Generate recursive help for each command handler
        for (Map.Entry<String, R2CommandHandler> entry : commandRegistry.entrySet()) {
            String prefix = entry.getKey();
            R2CommandHandler handler = entry.getValue();
            
            // Skip if filtering and prefix doesn't match
            if (filter != null && !filter.isEmpty() && !prefix.contains(filter)) {
                // We'll still search within the help content later
                String help = handler.getHelp();
                if (!help.contains(filter)) {
                    continue;
                }
            }
            
            // Add root command help
            allHelp.append("=== ").append(prefix).append(" ===\n");
            allHelp.append(handler.getHelp()).append("\n\n");
            
            // Parse subcommands and add their help recursively
            List<String> subcommands = extractSubcommands(handler.getHelp(), prefix);
            
            // Process each subcommand
            for (String subcommand : subcommands) {
                // Skip if filtering and subcommand doesn't match
                if (filter != null && !filter.isEmpty() && !subcommand.contains(filter)) {
                    continue;
                }
                
                try {
                    // Try to get help for this subcommand by simulating a help command
                    // Create a dummy command to get help for this subcommand
                    List<String> args = new ArrayList<>();
                    args.add(prefix + subcommand);
                    R2Command helpCmd = new R2Command("?", "", args, null);
                    
                    // Execute the help command and add the output
                    String subHelp = formatHelpOutput(handler.getHelp(), helpCmd);
                    allHelp.append("=== ").append(prefix).append(subcommand).append(" ===\n");
                    allHelp.append(subHelp).append("\n\n");
                    
                    // Recursively process subcommands (to avoid infinite loops, limit the depth)
                    processSubcommandsRecursively(allHelp, handler, prefix + subcommand, 1, 3, filter);
                } catch (Exception e) {
                    // Ignore errors for subcommands
                }
            }
        }
        
        return formatHelpOutput(allHelp.toString(), command);
    }
    
    /**
     * Process subcommands recursively with depth limiting to avoid infinite loops
     * 
     * @param output The output buffer
     * @param handler The command handler
     * @param baseCommand The base command for which to find subcommands
     * @param currentDepth Current recursion depth
     * @param maxDepth Maximum recursion depth
     * @param filter Optional filter string
     */
    private void processSubcommandsRecursively(
            StringBuilder output, 
            R2CommandHandler handler, 
            String baseCommand, 
            int currentDepth, 
            int maxDepth, 
            String filter) {
        
        // Stop if we've reached the maximum depth
        if (currentDepth >= maxDepth) {
            return;
        }
        
        // Extract subcommands for this base command
        List<String> subcommands = extractSubcommands(handler.getHelp(), baseCommand);
        
        // Process each subcommand
        for (String subcommand : subcommands) {
            // Skip if filtering and subcommand doesn't match
            if (filter != null && !filter.isEmpty() && !subcommand.contains(filter)) {
                continue;
            }
            
            String fullCommand = baseCommand + subcommand;
            
            try {
                // Add subcommand help
                output.append("=== ").append(fullCommand).append(" ===\n");
                output.append(handler.getHelp()).append("\n\n");
                
                // Recursively process further subcommands
                processSubcommandsRecursively(output, handler, fullCommand, currentDepth + 1, maxDepth, filter);
            } catch (Exception e) {
                // Ignore errors for subcommands
            }
        }
    }
    
    /**
     * Extract subcommands from help text
     * 
     * @param helpText The help text to parse
     * @param prefix The command prefix to look for
     * @return A list of subcommands
     */
    private List<String> extractSubcommands(String helpText, String prefix) {
        List<String> subcommands = new ArrayList<>();
        
        // Parse help text line by line
        String[] lines = helpText.split("\n");
        
        for (String line : lines) {
            // Skip empty lines and the usage line
            if (line.trim().isEmpty() || line.startsWith("Usage:")) {
                continue;
            }
            
            // Look for lines with format: "prefix+subcommand - description"
            if (line.trim().startsWith(prefix)) {
                // Extract the command part
                String cmdPart = line.trim();
                int dashPos = cmdPart.indexOf(" - ");
                
                if (dashPos > 0) {
                    cmdPart = cmdPart.substring(0, dashPos).trim();
                    
                    // Extract the subcommand part (remove the prefix)
                    if (cmdPart.length() > prefix.length()) {
                        String subcommand = cmdPart.substring(prefix.length());
                        
                        // Skip if it contains brackets (optional parts) or spaces (arguments)
                        if (!subcommand.contains("[") && !subcommand.contains(" ")) {
                            subcommands.add(subcommand);
                        }
                    }
                }
            }
        }
        
        return subcommands;
    }

    @Override
    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage: ?[V|v|vi|*][jq] [command|expr]\n");
        sb.append(" ?             show general help\n");
        sb.append(" ? [cmd]       show help for specific command\n");
        sb.append(" ?V            show version information\n");
        sb.append(" ?v expr       evaluate expression and show result in hexadecimal\n");
        sb.append(" ?vi expr      evaluate expression and show result in decimal\n");
        sb.append(" ? expr        evaluate expression and show result in multiple formats\n");
        sb.append(" ?*            recursively show help for all commands\n");
        sb.append(" ?* [filter]   recursively show help for commands matching filter\n");
        sb.append(" ?*~pattern    recursively show help for all commands, then filter lines matching pattern\n");
        sb.append(" ?j            show help in JSON format\n");
        sb.append(" ?q            list only command names\n");
        return sb.toString();
    }
}

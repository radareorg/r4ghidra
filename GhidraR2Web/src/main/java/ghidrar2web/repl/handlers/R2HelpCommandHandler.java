package ghidrar2web.repl.handlers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;

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

        String subcommand = command.getSubcommand();
        
        // '?' with no subcommand - general help
        if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
            return getGeneralHelp();
        }
        
        // '?' with an argument - help for specific command
        if (subcommand.isEmpty() && command.getArgumentCount() > 0) {
            String cmdName = command.getFirstArgument("");
            if (cmdName.isEmpty()) {
                return getGeneralHelp();
            }
            
            // Get the first character as the command prefix
            String prefix = cmdName.substring(0, 1);
            R2CommandHandler handler = commandRegistry.get(prefix);
            
            if (handler == null) {
                throw new R2CommandException("Unknown command: " + prefix);
            }
            
            return handler.getHelp();
        }
        
        // Handle help subcommands
        switch (subcommand) {
            // '?V' - version information
            case "V":
                return getVersionInfo();
                
            default:
                throw new R2CommandException("Unknown help subcommand: ?" + subcommand);
        }
    }

    /**
     * Generate general help text by combining brief help from all registered commands
     */
    private String getGeneralHelp() {
        StringBuilder msg = new StringBuilder("Usage: [ghidra-r2web-command .. args]\n\n");
        
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
        
        return msg.toString();
    }
    
    /**
     * Generate version information
     */
    private String getVersionInfo() {
        return "GhidraR2Web 1.0\n";
    }

    @Override
    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage: ?[V] [command]\n");
        sb.append(" ?             show general help\n");
        sb.append(" ? [cmd]       show help for specific command\n");
        sb.append(" ?V            show version information\n");
        return sb.toString();
    }
}
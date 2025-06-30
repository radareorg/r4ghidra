package ghidrar2web.repl.handlers;

import ghidra.program.model.address.Address;
import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;

/**
 * Handler for the 's' (seek) command
 */
public class R2SeekCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's an 's' command
        if (!command.hasPrefix("s")) {
            throw new R2CommandException("Not a seek command");
        }

        // Handle the various forms of seek command
        String subcommand = command.getSubcommand();
        
        // Simple 's' with no subcommand - just print current address
        if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
            return context.formatAddress(context.getCurrentAddress()) + "\n";
        }
        
        // 's' with an address argument - set current address
        if (subcommand.isEmpty() && command.getArgumentCount() > 0) {
            try {
                String addrStr = command.getFirstArgument("");
                Address newAddr = context.parseAddress(addrStr);
                context.setCurrentAddress(newAddr);
                return context.formatAddress(newAddr) + "\n";
            } catch (Exception e) {
                throw new R2CommandException("Invalid address: " + command.getFirstArgument(""));
            }
        }
        
        // Handle seek subcommands
        switch (subcommand) {
            // 'sb' - seek backward
            case "b": {
                try {
                    String offsetStr = command.getFirstArgument("1");
                    long offset = parseNumericValue(offsetStr, 1);
                    Address newAddr = context.getCurrentAddress().subtract(offset);
                    context.setCurrentAddress(newAddr);
                    return context.formatAddress(newAddr) + "\n";
                } catch (Exception e) {
                    throw new R2CommandException("Invalid offset for 'sb' command");
                }
            }
            
            // 'sf' - seek forward
            case "f": {
                try {
                    String offsetStr = command.getFirstArgument("1");
                    long offset = parseNumericValue(offsetStr, 1);
                    Address newAddr = context.getCurrentAddress().add(offset);
                    context.setCurrentAddress(newAddr);
                    return context.formatAddress(newAddr) + "\n";
                } catch (Exception e) {
                    throw new R2CommandException("Invalid offset for 'sf' command");
                }
            }
            
            // 's-' - seek to previous location
            case "-":
                // Not implemented yet - would need history
                throw new R2CommandException("Command 's-' not implemented yet");
                
            // 's+' - seek to next location
            case "+":
                // Not implemented yet - would need history
                throw new R2CommandException("Command 's+' not implemented yet");
                
            // Other subcommands are not supported
            default:
                throw new R2CommandException("Unknown seek subcommand: s" + subcommand);
        }
    }
    
    /**
     * Parse a numeric value, which could be decimal, hexadecimal, or octal
     */
    private long parseNumericValue(String str, long defaultValue) {
        if (str == null || str.isEmpty()) {
            return defaultValue;
        }
        
        try {
            // Handle hex (0x)
            if (str.toLowerCase().startsWith("0x")) {
                return Long.parseLong(str.substring(2), 16);
            }
            
            // Handle octal (0)
            if (str.startsWith("0") && str.length() > 1) {
                return Long.parseLong(str.substring(1), 8);
            }
            
            // Decimal
            return Long.parseLong(str);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    @Override
    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage: s[bfpm] [addr]\n");
        sb.append(" s              show current address\n");
        sb.append(" s [addr]       seek to address\n");
        sb.append(" sb [delta]     seek backward delta bytes\n");
        sb.append(" sf [delta]     seek forward delta bytes\n");
        sb.append(" s- / s+        seek to previous/next location\n");
        return sb.toString();
    }
}
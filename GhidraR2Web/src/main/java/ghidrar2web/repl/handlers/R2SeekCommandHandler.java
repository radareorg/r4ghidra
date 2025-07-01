package ghidrar2web.repl.handlers;

import ghidra.program.model.address.Address;
import ghidrar2web.repl.R2Command;
import ghidrar2web.repl.R2CommandException;
import ghidrar2web.repl.R2CommandHandler;
import ghidrar2web.repl.R2Context;
import ghidrar2web.repl.num.R2NumException;
import ghidrar2web.repl.num.R2NumUtil;
import org.json.JSONObject;

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
        String subcommand = command.getSubcommandWithoutSuffix();
        
        // Simple 's' with no subcommand - just print current address
        if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
            Address currentAddr = context.getCurrentAddress();
            return formatResult(currentAddr, context, command);
        }
        
        // 's' with an address argument - set current address
        if (subcommand.isEmpty() && command.getArgumentCount() > 0) {
            try {
                String addrStr = command.getFirstArgument("");
                // Use RNum API to evaluate address expressions
                long addrValue = R2NumUtil.evaluateExpression(context, addrStr);
                Address newAddr = context.getAPI().toAddr(addrValue);
                context.setCurrentAddress(newAddr);
                return formatResult(newAddr, context, command);
            } catch (R2NumException e) {
                throw new R2CommandException("Invalid address expression: " + e.getMessage());
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
                    // Use RNum API to evaluate offset expressions
                    long offset = R2NumUtil.evaluateExpression(context, offsetStr);
                    if (offset <= 0) {
                        offset = 1; // Default to 1 for non-positive values
                    }
                    Address newAddr = context.getCurrentAddress().subtract(offset);
                    context.setCurrentAddress(newAddr);
                    return formatResult(newAddr, context, command);
                } catch (R2NumException e) {
                    throw new R2CommandException("Invalid offset expression: " + e.getMessage());
                } catch (Exception e) {
                    throw new R2CommandException("Invalid offset for 'sb' command: " + e.getMessage());
                }
            }
            
            // 'sf' - seek forward
            case "f": {
                try {
                    String offsetStr = command.getFirstArgument("1");
                    // Use RNum API to evaluate offset expressions
                    long offset = R2NumUtil.evaluateExpression(context, offsetStr);
                    if (offset <= 0) {
                        offset = 1; // Default to 1 for non-positive values
                    }
                    Address newAddr = context.getCurrentAddress().add(offset);
                    context.setCurrentAddress(newAddr);
                    return formatResult(newAddr, context, command);
                } catch (R2NumException e) {
                    throw new R2CommandException("Invalid offset expression: " + e.getMessage());
                } catch (Exception e) {
                    throw new R2CommandException("Invalid offset for 'sf' command: " + e.getMessage());
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
     * Format the result according to the command suffix
     */
    private String formatResult(Address address, R2Context context, R2Command command) {
        if (command.hasSuffix('j')) {
            // JSON output
            JSONObject json = new JSONObject();
            json.put("offset", address.getOffset());
            json.put("address", context.formatAddress(address));
            return json.toString() + "\n";
        } else if (command.hasSuffix('q')) {
            // Quiet output - just the address with no newline
            return context.formatAddress(address);
        } else {
            // Default output
            return context.formatAddress(address) + "\n";
        }
    }
    
    // parseNumericValue method removed as we now use R2NumUtil.evaluateExpression

    @Override
    public String getHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage: s[bfpm][j,q] [addr]\n");
        sb.append(" s              show current address\n");
        sb.append(" s [addr]       seek to address\n");
        sb.append(" sb [delta]     seek backward delta bytes\n");
        sb.append(" sf [delta]     seek forward delta bytes\n");
        sb.append(" s- / s+        seek to previous/next location\n");
        sb.append(" sj             show current address as JSON\n");
        sb.append(" sq             show current address (quiet mode)\n");
        return sb.toString();
    }
}
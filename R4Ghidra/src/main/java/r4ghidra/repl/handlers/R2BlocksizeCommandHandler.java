package r4ghidra.repl.handlers;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.num.R2NumException;
import r4ghidra.repl.num.R2NumUtil;

/**
 * Handler for the 'b' (blocksize) command
 * 
 * This command gets and sets the blocksize, which is the default number of bytes
 * used by commands that operate on memory when no size is explicitly specified.
 */
public class R2BlocksizeCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's a 'b' command
        if (!command.hasPrefix("b")) {
            throw new R2CommandException("Not a blocksize command");
        }
        
        // Get the subcommand
        String subcommand = command.getSubcommand();
        
        // If no arguments provided, just return the current blocksize
        if (subcommand.isEmpty() && command.getArguments().isEmpty()) {
            return Integer.toString(context.getBlockSize()) + "\n";
        }
        
        // Check for b+N or b-N syntax
        Pattern increasePattern = Pattern.compile("^\\+(.+)$");
        Pattern decreasePattern = Pattern.compile("^-(.+)$");
        
        Matcher increaseMatcher = increasePattern.matcher(subcommand);
        Matcher decreaseMatcher = decreasePattern.matcher(subcommand);
        
        try {
            int newBlockSize;
            
            if (increaseMatcher.matches()) {
                // Increase blocksize by N
                String valueStr = increaseMatcher.group(1);
                long value = R2NumUtil.evaluateExpression(context, valueStr);
                newBlockSize = context.getBlockSize() + (int) value;
            } else if (decreaseMatcher.matches()) {
                // Decrease blocksize by N
                String valueStr = decreaseMatcher.group(1);
                long value = R2NumUtil.evaluateExpression(context, valueStr);
                newBlockSize = context.getBlockSize() - (int) value;
            } else {
                // Handle direct blocksize setting
                String sizeArg = command.getFirstArgument(subcommand);
                
                if (sizeArg.isEmpty()) {
                    // Return current blocksize if no argument provided
                    return Integer.toString(context.getBlockSize()) + "\n";
                }
                
                // Parse the new blocksize
                long value = R2NumUtil.evaluateExpression(context, sizeArg);
                newBlockSize = (int) value;
            }
            
            // Ensure blocksize is at least 1
            if (newBlockSize < 1) {
                newBlockSize = 1;
            }
            
            // Set the new blocksize
            context.setBlockSize(newBlockSize);
            
            // Return the new blocksize
            return Integer.toString(newBlockSize) + "\n";
            
        } catch (R2NumException e) {
            throw new R2CommandException("Invalid blocksize value: " + e.getMessage());
        }
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: b[+-]<num>\n");
        help.append(" b           display current block size\n");
        help.append(" b <num>     change block size to <num> bytes\n");
        help.append(" b+<num>     increase blocksize by <num> bytes\n");
        help.append(" b-<num>     decrease blocksize by <num> bytes\n");
        help.append("\nExamples:\n");
        help.append(" b           show current block size\n");
        help.append(" b 16        set block size to 16\n");
        help.append(" b 0x100     set block size to 256\n");
        help.append(" b+32        increase block size by 32\n");
        help.append(" b-16        decrease block size by 16\n");
        return help.toString();
    }
}
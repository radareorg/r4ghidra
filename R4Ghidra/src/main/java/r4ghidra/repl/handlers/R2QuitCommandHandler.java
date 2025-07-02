package r4ghidra.repl.handlers;

import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.num.R2NumUtil;
import r4ghidra.repl.num.R2NumException;

/**
 * Handler for the 'q' (quit) command
 * 
 * This command allows quitting the application with an optional exit code.
 */
public class R2QuitCommandHandler implements R2CommandHandler {

    @Override
    public String execute(R2Command command, R2Context context) throws R2CommandException {
        // Check if it's a 'q' command
        if (!command.hasPrefix("q")) {
            throw new R2CommandException("Not a quit command");
        }

        // Special handling for q!! syntax
        if (command.getSubcommand().equals("!!")) {
            // Exit immediately with code 0
            System.exit(0);
            return ""; // This won't be reached
        }
        
        // Check if there is an argument to use as exit code
        if (command.getArgumentCount() > 0) {
            try {
                // Use R2NumUtil to evaluate the exit code expression
                String exitCodeExpr = command.getFirstArgument("0");
                int exitCode = (int)R2NumUtil.evaluateExpression(context, exitCodeExpr);
                System.exit(exitCode);
                return ""; // This won't be reached
            } catch (R2NumException e) {
                throw new R2CommandException("Invalid exit code: " + e.getMessage());
            }
        }
        
        // Default behavior is to show warning message
        return "Use q!! to force quit";
    }

    @Override
    public String getHelp() {
        StringBuilder help = new StringBuilder();
        help.append("Usage: q[!!] [exit_code] - Quit the application\n\n");
        help.append("q       Display quit message\n");
        help.append("q!!     Quit immediately with exit code 0\n");
        help.append("q [n]   Quit with specified exit code\n");
        help.append("\nExamples:\n");
        help.append("q       Show the quit message\n");
        help.append("q!!     Force quit with exit code 0\n");
        help.append("q 1     Exit with code 1\n");
        help.append("q 0x20  Exit with code 32\n");
        return help.toString();
    }
}
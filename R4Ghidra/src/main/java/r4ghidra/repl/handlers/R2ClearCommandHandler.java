package r4ghidra.repl.handlers;

import r4ghidra.R4CommandShellProvider;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/**
 * Handler for the 'clear' command
 *
 * <p>This command clears the output textarea in the R4Ghidra console shell.
 */
/**
 * Handler for the 'clear' command
 * <p>
 * This command clears the output textarea in the R4Ghidra console shell.
 * It provides a way for users to clean the interface during debugging sessions.
 */
public class R2ClearCommandHandler implements R2CommandHandler {

@Override
public String execute(R2Command command, R2Context context) throws R2CommandException {
	// Check if it's a 'clear' command (prefix would be 'c')
	if (!command.getPrefix().equals("c") || !command.getSubcommand().equals("lear")) {
	throw new R2CommandException("Not a clear command");
	}

	// Get the shell provider from the context
	R4CommandShellProvider shellProvider = context.getShellProvider();
	if (shellProvider == null) {
	return "Error: Shell provider not available";
	}

	// Clear the output area
	shellProvider.clearOutputArea();

	// Return an empty string since the output will be cleared anyway
	return "";
}

@Override
public String getHelp() {
	StringBuilder help = new StringBuilder();
	help.append("Usage: clear - Clear the console output\n\n");
	help.append("clear    Clear the console output area\n");
	help.append("\nExamples:\n");
	help.append("clear    Clear all text from the console\n");
	return help.toString();
}
}

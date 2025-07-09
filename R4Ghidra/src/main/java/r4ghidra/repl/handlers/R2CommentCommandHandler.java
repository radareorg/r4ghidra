package r4ghidra.repl.handlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import java.util.Base64;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/** Handler for the 'CC' (comment) command family */
public class R2CommentCommandHandler implements R2CommandHandler {

@Override
public String execute(R2Command command, R2Context context) throws R2CommandException {
	// Check if it's a CC command
	if (!command.hasPrefix("C")) {
	throw new R2CommandException("Not a comment command");
	}

	// Get the subcommand without suffix
	String subcommand = command.getSubcommandWithoutSuffix();

	// Handle different subcommands
	switch (subcommand) {
	case "Cu":
		return executeCCuCommand(command, context);
	default:
		throw new R2CommandException("Unknown comment subcommand: C" + subcommand);
	}
}

/**
* Execute the CCu command to set a unique comment at the current address Format: CCu [comment] @
* addr Special format: CCu base64:[encoded] @ addr - decodes base64 content first
*/
private String executeCCuCommand(R2Command command, R2Context context) throws R2CommandException {
	// Get the current address (or temporary address if specified)
	Address address =
		command.hasTemporaryAddress() ? command.getTemporaryAddress() : context.getCurrentAddress();

	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	// Check if we have a comment text
	if (command.getArgumentCount() < 1) {
	throw new R2CommandException("No comment text provided. Usage: CCu [comment] @ addr");
	}

	// Get the comment text (combine all arguments)
	StringBuilder commentText = new StringBuilder();
	for (int i = 0; i < command.getArgumentCount(); i++) {
	if (i > 0) {
		commentText.append(" ");
	}
	commentText.append(command.getArgument(i, ""));
	}

	String comment = commentText.toString();

	// Check for base64: prefix
	if (comment.startsWith("base64:")) {
	try {
		String base64Content = comment.substring("base64:".length());
		byte[] decodedBytes = Base64.getDecoder().decode(base64Content);
		comment = new String(decodedBytes);
	} catch (IllegalArgumentException e) {
		throw new R2CommandException("Invalid base64 content: " + e.getMessage());
	}
	}

	try {
	// Get the current program
	Program program = context.getAPI().getCurrentProgram();
	if (program == null) {
		throw new R2CommandException("No program is open");
	}

	// Get the listing and start a transaction
	Listing listing = program.getListing();
	int transactionID = program.startTransaction("Set Comment");

	try {
		// Set the EOL (End of Line) comment at the specified address
		// Unique comment means removing any existing comments first
		listing.setComment(address, CommentType.EOL, null); // Clear existing comment
		listing.setComment(address, CommentType.EOL, comment);

		return "Comment set at " + context.formatAddress(address);
	} finally {
		// Always end the transaction
		program.endTransaction(transactionID, true);
	}
	} catch (Exception e) {
	throw new R2CommandException("Error setting comment: " + e.getMessage());
	}
}

@Override
public String getHelp() {
	StringBuilder help = new StringBuilder();
	help.append("Usage: C[command][j]\n");
	help.append(" CCu [comment] @ addr     add a unique comment at given address\n");
	help.append(" CCu base64:AA== @ addr   add comment in base64\n");
	help.append("\nExamples:\n");
	help.append(" CCu function starts here @ 0x1000\n");
	help.append(" CCu base64:aGVsbG8gd29ybGQ= @ 0x2000\n");
	help.append(" CCu important address @ $$ (at current address)\n");
	return help.toString();
}
}

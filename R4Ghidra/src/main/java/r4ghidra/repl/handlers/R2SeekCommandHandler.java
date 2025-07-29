package r4ghidra.repl.handlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import org.json.JSONObject;
import r4ghidra.R4GhidraState;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.num.R2NumException;
import r4ghidra.repl.num.R2NumUtil;

/** Handler for the 's' (seek) command */
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
		seekTo(context, newAddr);
		return formatResult(newAddr, context, command);
	} catch (R2NumException e) {
		throw new R2CommandException("Invalid address expression: " + e.getMessage());
	} catch (Exception e) {
		throw new R2CommandException("Invalid address: " + command.getFirstArgument(""));
	}
	}

	// Handle seek subcommands
	switch (subcommand) {
		// 's..' - seek by replacing lower nibbles
	case ".":
		if (subcommand.startsWith(".") && subcommand.length() > 1) {
		return executeSeekNibblesCommand(command, context);
		}

		// 'sb' - seek backward
	case "b":
		{
		try {
			String offsetStr = command.getFirstArgument("1");
			// Use RNum API to evaluate offset expressions
			long offset = R2NumUtil.evaluateExpression(context, offsetStr);
			if (offset <= 0) {
			offset = 1; // Default to 1 for non-positive values
			}
			Address newAddr = context.getCurrentAddress().subtract(offset);
			seekTo(context, newAddr);
			return formatResult(newAddr, context, command);
		} catch (R2NumException e) {
			throw new R2CommandException("Invalid offset expression: " + e.getMessage());
		} catch (Exception e) {
			throw new R2CommandException("Invalid offset for 'sb' command: " + e.getMessage());
		}
		}

		// 'sf' - seek to start of function at current offset (no arguments), or forward by bytes if
		// arg supplied
	case "f":
		{
		// If no argument, seek to function start
		if (command.getArgumentCount() == 0) {
			Address current = context.getCurrentAddress();
			if (current == null) {
			throw new R2CommandException("Current address is not set");
			}
			Function func = context.getAPI().getFunctionContaining(current);
			if (func == null) {
			throw new R2CommandException("No function found at current address");
			}
			Address entry = func.getEntryPoint();
			seekTo(context, entry);
			return formatResult(entry, context, command);
		}
		// Fallback: seek forward by delta bytes
		try {
			String offsetStr = command.getFirstArgument("1");
			long offset = R2NumUtil.evaluateExpression(context, offsetStr);
			if (offset <= 0) {
			offset = 1;
			}
			Address newAddr = context.getCurrentAddress().add(offset);
			seekTo(context, newAddr);
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
		// Check if this is s.. command
		if (subcommand.startsWith(".")) {
		return executeSeekNibblesCommand(command, context);
		}
		throw new R2CommandException("Unknown seek subcommand: s" + subcommand);
	}
}

private void seekTo(R2Context context, Address a){
	context.setCurrentAddress(a);
	R4GhidraState.codeViewer.goTo(new ProgramLocation(R4GhidraState.api.getCurrentProgram(),a),false);
}

/** Format the result according to the command suffix */
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

/**
* Execute the 's..' command to seek to an address by replacing the lower nibbles This implements
* functionality similar to r_num_tail in radare2
*
* @param command The command object
* @param context The execution context
* @return Formatted result showing the new address
*/
private String executeSeekNibblesCommand(R2Command command, R2Context context)
	throws R2CommandException {
	// Get the current subcommand (which will start with at least one dot)
	String subcommand = command.getSubcommandWithoutSuffix();

	// Skip any leading dots and spaces
	int startIndex = 0;
	while (startIndex < subcommand.length()
		&& (subcommand.charAt(startIndex) == '.' || subcommand.charAt(startIndex) == ' ')) {
	startIndex++;
	}

	// Extract the hex part
	String hexPart = subcommand.substring(startIndex);

	// If there are arguments, use those instead of the subcommand
	if (command.getArgumentCount() > 0) {
	hexPart = command.getFirstArgument("");
	}

	// Validate we have hex digits
	if (hexPart.isEmpty()) {
	throw new R2CommandException("Missing hex digits for s.. command");
	}

	// Check if the first character is a valid hex digit
	if (!isHexDigit(hexPart.charAt(0))) {
	throw new R2CommandException("Invalid hex digits for s.. command");
	}

	try {
	// Get the current address
	Address currentAddr = context.getCurrentAddress();
	if (currentAddr == null) {
		throw new R2CommandException("Current address is not set");
	}

	long currentValue = currentAddr.getOffset();

	// Calculate new address using tail nibbles
	long newAddr = replaceNibbles(currentValue, hexPart);

	// Update current address
	Address newAddress = context.getAPI().toAddr(newAddr);
	seekTo(context, newAddress);

	// Return formatted result
	return formatResult(newAddress, context, command);
	} catch (Exception e) {
	throw new R2CommandException("Error in s.. command: " + e.getMessage());
	}
}

/** Check if a character is a valid hex digit */
private boolean isHexDigit(char c) {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
* Replace lower nibbles of an address with the specified hex digits
*
* @param addr The original address
* @param hex The hex string to use for replacement
* @return The new address value
*/
private long replaceNibbles(long addr, String hex) {
	// Calculate the number of nibbles (4 bits each) to replace
	int nibbleCount = hex.length();

	// Create a mask where the upper bits are preserved and lower bits are replaced
	long mask = ~0L << (nibbleCount * 4); // equivalent to UT64_MAX << i in C

	// Parse the hex value
	long hexValue = Long.parseLong(hex, 16);

	// Combine the preserved upper bits and the new lower bits
	return (addr & mask) | hexValue;
}

@Override
public String getHelp() {
	StringBuilder sb = new StringBuilder();
	sb.append("Usage: s[bfpm][j,q] [addr]\n");
	sb.append(" s              show current address\n");
	sb.append(" s [addr]       seek to address\n");
	sb.append(" s..32a8        seek to same address but replacing the lower nibbles\n");
	sb.append(" sb [delta]     seek backward delta bytes\n");
	sb.append(" sf            seek to start of current function\n");
	sb.append(" sf [delta]     seek forward delta bytes\n");
	sb.append(" s- / s+        seek to previous/next location\n");
	sb.append(" sj             show current address as JSON\n");
	sb.append(" sq             show current address (quiet mode)\n");
	return sb.toString();
}
}

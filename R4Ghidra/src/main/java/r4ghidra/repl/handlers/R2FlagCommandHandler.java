package r4ghidra.repl.handlers;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/**
 * Handler for the 'f' (flag) command
 *
 * <p>This command allows users to manage flags (bookmarks) in the code. Flags are a way to name
 * addresses in radare2.
 */
public class R2FlagCommandHandler implements R2CommandHandler {

// Pattern for flag set with address (f name=0x123)
private static final Pattern FLAG_SET_ADDR_PATTERN = Pattern.compile("([a-zA-Z0-9._-]+)=(.+)");

// Pattern for flag definition with size and address (f name size addr)
private static final Pattern FLAG_DEF_PATTERN =
	Pattern.compile("([a-zA-Z0-9._-]+)\\s+(\\d+)\\s+(.+)");

// Pattern for flag delete (f-name)
private static final Pattern FLAG_DELETE_PATTERN = Pattern.compile("-(.+)");

@Override
public String execute(R2Command command, R2Context context) throws R2CommandException {
	// Check if this is an 'f' command
	if (!command.hasPrefix("f")) {
	throw new R2CommandException("Not a flag command");
	}

	String subcommand = command.getSubcommandWithoutSuffix().trim();

	// Handle flagspace commands (fs)
	if (command.hasPrefix("fs")) {
	return handleFlagspace(command, context);
	}

	// List all flags when no subcommand is provided
	if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
	return listFlags(context, command);
	}

	// Flag deletion (f-name)
	Matcher deleteMatcher = FLAG_DELETE_PATTERN.matcher(subcommand);
	if (deleteMatcher.matches()) {
	String flagName = deleteMatcher.group(1);
	boolean success = context.deleteFlag(flagName);
	if (!success) {
		throw new R2CommandException("Flag '" + flagName + "' not found");
	}
	return ""; // Silent success
	}

	// Check for flag definition with size and address (f name size addr)
	// This needs to come before the name=addr pattern to correctly handle the size syntax
	if (command.getArgumentCount() >= 2) {
	String flagName = command.getFirstArgument("");
	String sizeStr = command.getArgument(1, "");
	String addrStr = command.getArgument(2, "");

	if (!flagName.isEmpty() && !sizeStr.isEmpty() && !addrStr.isEmpty()) {
		try {
		int size = Integer.parseInt(sizeStr);
		long addr = context.parseAddress(addrStr).getOffset();
		boolean success = context.setFlag(flagName, addr, size);
		if (!success) {
			throw new R2CommandException("Failed to set flag '" + flagName + "'");
		}
		return ""; // Silent success
		} catch (NumberFormatException e) {
		throw new R2CommandException("Invalid flag size: " + sizeStr);
		} catch (Exception e) {
		throw new R2CommandException("Invalid address: " + addrStr);
		}
	}
	}

	// Flag creation with specific address (f name=0x123)
	Matcher addrMatcher = FLAG_SET_ADDR_PATTERN.matcher(subcommand);
	if (addrMatcher.matches()) {
	String flagName = addrMatcher.group(1);
	String addrStr = addrMatcher.group(2);

	try {
		// Parse the address using the context's expression evaluator
		long addr = context.parseAddress(addrStr).getOffset();
		boolean success = context.setFlag(flagName, addr);
		if (!success) {
		throw new R2CommandException("Failed to set flag '" + flagName + "'");
		}
		return ""; // Silent success
	} catch (Exception e) {
		throw new R2CommandException("Invalid address: " + addrStr);
	}
	}

	// Check for flag definition with size and address (f name size addr)
	Matcher defMatcher = FLAG_DEF_PATTERN.matcher(subcommand);
	if (defMatcher.matches()) {
	String flagName = defMatcher.group(1);
	int size;
	try {
		size = Integer.parseInt(defMatcher.group(2));
	} catch (NumberFormatException e) {
		throw new R2CommandException("Invalid flag size: " + defMatcher.group(2));
	}

	String addrStr = defMatcher.group(3);
	try {
		// Parse the address using the context's expression evaluator
		long addr = context.parseAddress(addrStr).getOffset();
		boolean success = context.setFlag(flagName, addr, size);
		if (!success) {
		throw new R2CommandException("Failed to set flag '" + flagName + "'");
		}
		return ""; // Silent success
	} catch (Exception e) {
		throw new R2CommandException("Invalid address: " + addrStr);
	}
	}

	// Flag creation at current address (f name)
	if (!subcommand.isEmpty()) {
	boolean success = context.setFlag(subcommand);
	if (!success) {
		throw new R2CommandException("Failed to set flag '" + subcommand + "'");
	}
	return ""; // Silent success
	}

	// If we get here, it's an unknown subcommand
	throw new R2CommandException("Unknown flag command");
}

/** Handle flagspace commands (fs) */
private String handleFlagspace(R2Command command, R2Context context) throws R2CommandException {
	String subcommand = command.getSubcommandWithoutSuffix().trim();

	// List all flagspaces (fs)
	if (subcommand.isEmpty() && command.getArgumentCount() == 0) {
	return listFlagspaces(context, command);
	}

	// Reset flagspace (fs *)
	if (subcommand.equals("*")
		|| (command.getArgumentCount() > 0 && command.getFirstArgument("").equals("*"))) {
	context.setFlagspace("*");
	return ""; // Silent success
	}

	// Set flagspace (fs name)
	String flagspace = subcommand.isEmpty() ? command.getFirstArgument("") : subcommand;
	context.setFlagspace(flagspace);
	return ""; // Silent success
}

/** List all flags */
private String listFlags(R2Context context, R2Command command) {
	Map<String, Long> flags = context.getFlags();

	// JSON output
	if (command.hasSuffix('j')) {
	JSONArray jsonFlags = new JSONArray();
	for (Map.Entry<String, Long> entry : flags.entrySet()) {
		JSONObject flag = new JSONObject();
		flag.put("name", entry.getKey());
		flag.put("offset", entry.getValue());
		flag.put("address", context.formatAddress(entry.getValue()));
		flag.put("size", context.getFlagSize(entry.getKey())); // Include flag size
		jsonFlags.put(flag);
	}
	return jsonFlags.toString() + "\n";
	}
	// R2 commands output
	else if (command.hasSuffix('*')) {
	StringBuilder sb = new StringBuilder();
	for (Map.Entry<String, Long> entry : flags.entrySet()) {
		String flagName = entry.getKey();
		sb.append("f ")
			.append(flagName)
			.append(" ")
			.append(context.getFlagSize(flagName))
			.append(" ")
			.append(context.formatAddress(entry.getValue()))
			.append("\n");
	}
	return sb.toString();
	}
	// Standard output
	else {
	if (flags.isEmpty()) {
		return "No flags defined\n";
	}

	StringBuilder sb = new StringBuilder();
	int maxNameLength = 0;

	// Find the longest name for nice alignment
	for (String name : flags.keySet()) {
		maxNameLength = Math.max(maxNameLength, name.length());
	}

	// Format the output
	for (Map.Entry<String, Long> entry : flags.entrySet()) {
		String flagName = entry.getKey();
		sb.append(context.formatAddress(entry.getValue()));
		sb.append(" ");
		sb.append(String.format("%3d", context.getFlagSize(flagName))); // Display size
		sb.append(" ");
		sb.append(flagName);
		sb.append("\n");
	}

	return sb.toString();
	}
}

/** List all flagspaces */
private String listFlagspaces(R2Context context, R2Command command) {
	String[] flagspaces = context.getFlagspaces();
	String currentFlagspace = context.getCurrentFlagspace();

	// JSON output
	if (command.hasSuffix('j')) {
	JSONObject json = new JSONObject();
	json.put("selected", currentFlagspace);

	JSONArray spaces = new JSONArray();
	for (String fs : flagspaces) {
		spaces.put(fs);
	}
	json.put("spaces", spaces);
	return json.toString() + "\n";
	}
	// R2 commands output
	else if (command.hasSuffix('*')) {
	StringBuilder sb = new StringBuilder();
	sb.append("fs ").append(currentFlagspace).append("\n");
	return sb.toString();
	}
	// Standard output
	else {
	StringBuilder sb = new StringBuilder();
	for (String fs : flagspaces) {
		if (fs.equals(currentFlagspace)) {
		sb.append("* ");
		} else {
		sb.append("  ");
		}
		sb.append(fs).append("\n");
	}
	return sb.toString();
	}
}

@Override
public String getHelp() {
	StringBuilder sb = new StringBuilder();
	sb.append("Usage: f[*j] [name] [@ addr]\n");
	sb.append(" f                list flags in current flagspace\n");
	sb.append(" f name           set flag at current address\n");
	sb.append(" f name=addr      set flag at address\n");
	sb.append(" f name size addr set flag with size at address\n");
	sb.append(" f-name           remove flag\n");
	sb.append(" f*               list flags in r2 commands\n");
	sb.append(" fj               list flags in JSON format\n");
	sb.append("\n");
	sb.append("Flagspace management:\n");
	sb.append(" fs               list all flagspaces\n");
	sb.append(" fs *             select all flagspaces\n");
	sb.append(" fs name          select flagspace\n");
	return sb.toString();
}
}

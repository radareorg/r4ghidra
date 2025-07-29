package r4ghidra.repl.handlers;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.IdentityNameTransformer;
import java.util.ArrayList;
import java.util.Base64;
import org.json.JSONArray;
import org.json.JSONObject;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;

/**
 * Handler for the 'pdd' command - Decompile function at current address
 * <p>
 * This command uses Ghidra's decompiler to generate C-like pseudocode for the function at the current
 * address. The output can be formatted in several ways: standard (with addresses), as radare2 commands,
 * as JSON, or in a quiet format (without addresses).
 * <p>
 * The command supports the following formats:
 * - pdd: standard output with addresses
 * - pdd*: output as radare2 commands
 * - pddj: output as JSON
 * - pddq: quiet output (no addresses)
 */
public class R2DecompileCommandHandler implements R2CommandHandler {

@Override
public String execute(R2Command command, R2Context context) throws R2CommandException {
	// Check if this is a 'p' command
	if (!command.hasPrefix("p")) {
	throw new R2CommandException("Not a print command");
	}

	// Check if it's the 'pdd' subcommand using the base subcommand without suffix
	String subcommand = command.getSubcommandWithoutSuffix();
	if (!subcommand.equals("dd")) {
	throw new R2CommandException("Not a decompile command");
	}

	try {
	// Get function at current address
	Function function = context.getAPI().getFunctionContaining(context.getCurrentAddress());
	if (function == null) {
		throw new R2CommandException(
			"No function at address " + context.formatAddress(context.getCurrentAddress()));
	}

	// Decompile the function
	ArrayList<DecompiledLine> lines = decompileFunction(function, context);
	// Format the output according to the command suffix
	Character suffix = command.getCommandSuffix();
	switch (suffix) {
		case '*':
		return formatAsRadare2Commands(lines);
		case 'j':
		return formatAsJson(lines, function);
		case 'q':
		return formatQuiet(lines);
		default:
		return formatStandard(lines);
	}
	} catch (MemoryAccessException mae) {
	throw new R2CommandException(
		"No function at address " + context.formatAddress(context.getCurrentAddress()));
	} catch (R2CommandException e) {
	throw e;
	} catch (Exception e) {
	throw new R2CommandException("Decompilation error: " + e.getMessage());
	}
}

/** Represents a line of decompiled code with its associated address */
private static class DecompiledLine {

	public long minAddress;
	public long maxAddress;
	public String codeLine;

	public DecompiledLine(long minAddress, long maxAddress, String codeLine) {
	this.minAddress = minAddress;
	this.maxAddress = maxAddress;
	this.codeLine = codeLine;
	}

	public boolean hasAddress() {
	return maxAddress > 0;
	}
}

/** Decompile a function and return the lines with address information */
private ArrayList<DecompiledLine> decompileFunction(Function function, R2Context context)
	throws Exception {
	ArrayList<DecompiledLine> result = new ArrayList<>();

	DecompInterface decompInterface = new DecompInterface();

	// Initialize the decompiler
	decompInterface.openProgram(function.getProgram());

	// Decompile with a 5-seconds timeout
	DecompileResults decompileResults = decompInterface.decompileFunction(function, 5, null);

	if (!decompileResults.decompileCompleted()) {
	throw new R2CommandException("Decompilation did not complete successfully");
	}

	// Format and extract the decompiled code with addresses
	PrettyPrinter prettyPrinter =
		new PrettyPrinter(
			function, decompileResults.getCCodeMarkup(), new IdentityNameTransformer());
	ArrayList<ClangLine> codeLines = new ArrayList<>(prettyPrinter.getLines());

	for (ClangLine line : codeLines) {
	long minAddress = Long.MAX_VALUE;
	long maxAddress = 0;

	// Find the min and max addresses for this line
	for (int i = 0; i < line.getNumTokens(); i++) {
		if (line.getToken(i).getMinAddress() == null) {
		continue;
		}
		long addr = line.getToken(i).getMinAddress().getOffset();
		minAddress = addr < minAddress ? addr : minAddress;
		maxAddress = addr > maxAddress ? addr : maxAddress;
	}

	// Format the code line
	String codeLine = line.toString();
	int colon = codeLine.indexOf(':');
	if (colon != -1) {
		codeLine = codeLine.substring(colon + 1);
		codeLine = line.getIndentString() + codeLine;
	}

	// If no address was found, use maximum value as flag
	if (minAddress == Long.MAX_VALUE) {
		minAddress = 0;
	}

	result.add(new DecompiledLine(minAddress, maxAddress, codeLine));
	}

	return result;
}

/** Format decompiled lines as radare2 commands */
private String formatAsRadare2Commands(ArrayList<DecompiledLine> lines) {
	StringBuilder result = new StringBuilder();

	for (DecompiledLine line : lines) {
	// Only output lines that have an address associated with them
	if (line.hasAddress()) {
		// Base64 encode for radare2 comments
		String b64comment = Base64.getEncoder().encodeToString(line.codeLine.getBytes());
		result.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, line.minAddress));
	}
	}

	return result.toString();
}

/** Format decompiled lines as JSON */
private String formatAsJson(ArrayList<DecompiledLine> lines, Function function) {
	JSONObject json = new JSONObject();
	JSONArray linesArray = new JSONArray();

	// Add function information
	json.put("name", function.getName());
	json.put("address", "0x" + Long.toHexString(function.getEntryPoint().getOffset()));
	json.put("size", function.getBody().getNumAddresses());

	// Add decompiled lines
	for (DecompiledLine line : lines) {
	JSONObject lineObj = new JSONObject();
	lineObj.put("code", line.codeLine);

	if (line.hasAddress()) {
		lineObj.put("address", "0x" + Long.toHexString(line.minAddress));
	}

	linesArray.put(lineObj);
	}

	json.put("lines", linesArray);
	return json.toString() + "\n";
}

/** Format decompiled lines in standard format with addresses */
private String formatStandard(ArrayList<DecompiledLine> lines) {
	StringBuilder result = new StringBuilder();

	for (DecompiledLine line : lines) {
	if (line.hasAddress()) {
		// Address associated with this line
		result.append(String.format("0x%08x %s\n", line.minAddress, line.codeLine));
	} else {
		// No address associated with this line
		result.append(String.format("           %s\n", line.codeLine));
	}
	}

	return result.toString();
}

/** Format decompiled lines in quiet mode (no addresses) */
private String formatQuiet(ArrayList<DecompiledLine> lines) {
	StringBuilder result = new StringBuilder();

	for (DecompiledLine line : lines) {
	result.append(line.codeLine).append("\n");
	}

	return result.toString();
}

@Override
public String getHelp() {
	StringBuilder help = new StringBuilder();
	help.append("Usage: pdd[*jq]\n");
	help.append(" pdd            decompile current function\n");
	help.append(" pdd*           decompile as radare2 comments\n");
	help.append(" pddj           decompile with JSON output\n");
	help.append(" pddq           decompile with quiet output (no addresses)\n");
	return help.toString();
}
}

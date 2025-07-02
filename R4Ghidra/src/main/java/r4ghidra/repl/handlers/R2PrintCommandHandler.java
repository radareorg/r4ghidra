package r4ghidra.repl.handlers;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import r4ghidra.repl.R2Command;
import r4ghidra.repl.R2CommandException;
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.R2Context;
import r4ghidra.repl.num.R2NumException;
import r4ghidra.repl.num.R2NumUtil;

/** Handler for the 'p' (print) command family */
public class R2PrintCommandHandler implements R2CommandHandler {

@Override
public String execute(R2Command command, R2Context context) throws R2CommandException {
	// Check if it's a 'p' command
	if (!command.hasPrefix("p")) {
	throw new R2CommandException("Not a print command");
	}

	// Get the subcommand without suffix
	String subcommand = command.getSubcommandWithoutSuffix();

	// Handle different subcommands
	switch (subcommand) {
	case "8":
		return executeP8Command(command, context);
	case "d":
		return executePdCommand(command, context);
	case "x":
		return executePxCommand(command, context);
	case "8f":
		return executeP8fCommand(command, context);
	case "xf":
		return executePxfCommand(command, context);
	case "df":
		return executePdfCommand(command, context);
	case "dg":
		return executePdgCommand(command, context);
	default:
		throw new R2CommandException("Unknown print subcommand: p" + subcommand);
	}
}

/** Execute the p8 command to print hexadecimal bytes */
private String executeP8Command(R2Command command, R2Context context) throws R2CommandException {
	// Parse the count argument using RNum
	int count;
	try {
	String countArg = command.getFirstArgument("16"); // Default to 16 bytes
	long numValue = R2NumUtil.evaluateExpression(context, countArg);
	count = (int) numValue;
	if (count <= 0) {
		throw new R2CommandException("Invalid byte count: " + count);
	}
	} catch (R2NumException e) {
	throw new R2CommandException("Invalid count expression: " + e.getMessage());
	}

	// Get the current address
	Address address = context.getCurrentAddress();
	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	try {
	// Read bytes from memory
	byte[] bytes = context.getAPI().getBytes(address, count);

	// Format output based on suffix
	if (command.hasSuffix('j')) {
		return formatP8Json(bytes);
	} else {
		return formatP8Text(bytes);
	}
	} catch (Exception e) {
	throw new R2CommandException("Error reading memory: " + e.getMessage());
	}
}

/** Format bytes as a hexadecimal string */
private String formatP8Text(byte[] bytes) {
	StringBuilder sb = new StringBuilder();
	for (byte b : bytes) {
	sb.append(String.format("%02x", b & 0xFF));
	}
	return sb.toString() + "\n";
}

/** Format bytes as a JSON array */
private String formatP8Json(byte[] bytes) {
	JSONArray array = new JSONArray();
	for (byte b : bytes) {
	array.put(b & 0xFF);
	}
	return array.toString() + "\n";
}

/** Execute the p8f command to print hexadecimal bytes using function size */
private String executeP8fCommand(R2Command command, R2Context context) throws R2CommandException {
	// Get the current address
	Address address = context.getCurrentAddress();
	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	try {
	// Get the function at the current address
	Function function = context.getAPI().getFunctionContaining(address);
	if (function == null) {
		throw new R2CommandException("No function at the current address");
	}

	// Get the function size
	int functionSize = (int) function.getBody().getNumAddresses();

	// Read bytes from memory using function size
	byte[] bytes = context.getAPI().getBytes(address, functionSize);

	// Format output based on suffix
	if (command.hasSuffix('j')) {
		return formatP8Json(bytes);
	} else {
		return formatP8Text(bytes);
	}
	} catch (Exception e) {
	throw new R2CommandException("Error reading function bytes: " + e.getMessage());
	}
}

/** Execute the pd command to print disassembly */
private String executePdCommand(R2Command command, R2Context context) throws R2CommandException {
	// Parse the count argument using RNum
	int count;
	try {
	String countArg = command.getFirstArgument("10"); // Default to 10 instructions
	long numValue = R2NumUtil.evaluateExpression(context, countArg);
	count = (int) numValue;
	if (count <= 0) {
		throw new R2CommandException("Invalid instruction count: " + count);
	}
	} catch (R2NumException e) {
	throw new R2CommandException("Invalid count expression: " + e.getMessage());
	}

	// Get the current address
	Address address = context.getCurrentAddress();
	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	// Number of bytes to display per instruction (0 to disable bytes)
	int asmBytes = context.getEvalConfig().getInt("asm.bytes");

	try {
	// Get the listing
	Listing listing = context.getAPI().getCurrentProgram().getListing();
	SymbolTable symbolTable = context.getAPI().getCurrentProgram().getSymbolTable();

	// Get instructions starting from the current address
	List<DisassembledInstruction> instructions = new ArrayList<>();
	Address currentAddr = address;

	for (int i = 0; i < count && currentAddr != null; i++) {
		Instruction instr = listing.getInstructionAt(currentAddr);
		if (instr == null) {
		// No more instructions
		break;
		}

		// Get symbol at this address
		Symbol[] symbols = symbolTable.getSymbols(currentAddr);
		String label = null;
		if (symbols.length > 0) {
		for (Symbol sym : symbols) {
			// Prefer function symbols
			if (sym.getSymbolType() == SymbolType.FUNCTION) {
			label = sym.getName();
			break;
			}
		}
		if (label == null) {
			// If no function symbol, use the first one
			label = symbols[0].getName();
		}
		}

		// Get instruction bytes
		byte[] bytes = instr.getBytes();

		// Get instruction text
		String disasm = instr.toString();

		// Apply case formatting based on asm.ucase setting
		boolean useUppercase = context.getEvalConfig().getBoolean("asm.ucase");
		if (!useUppercase) {
		disasm = disasm.toLowerCase();
		}

		// Create disassembled instruction
		DisassembledInstruction disasmInstr = new DisassembledInstruction();
		disasmInstr.address = currentAddr.getOffset();
		disasmInstr.size = instr.getLength();
		disasmInstr.bytes = bytes;
		disasmInstr.disasm = disasm;
		disasmInstr.label = label;
		// Capture end-of-line comment if present
		disasmInstr.comment = instr.getComment(CodeUnit.EOL_COMMENT);

		instructions.add(disasmInstr);

		// Move to next instruction
		currentAddr = instr.getMaxAddress().next();
	}

	// Format output based on suffix
	if (command.hasSuffix('j')) {
		return formatPdJson(instructions);
	} else {
		return formatPdText(instructions, asmBytes);
	}
	} catch (Exception e) {
	throw new R2CommandException("Error disassembling: " + e.getMessage());
	}
}

/** Format disassembled instructions as text */
private String formatPdText(List<DisassembledInstruction> instructions, int asmBytes) {
	StringBuilder sb = new StringBuilder();
	int bytesFieldWidth = asmBytes > 0 ? (asmBytes * 3 - 1) : 0;

	for (DisassembledInstruction instr : instructions) {
	// Add label if present
	if (instr.label != null) {
		sb.append(instr.label).append(":\n");
	}
	// Format address
	sb.append(String.format("0x%08x  ", instr.address));
	// Add bytes if requested
	if (asmBytes > 0) {
		byte[] bytes = instr.bytes;
		int count = Math.min(bytes.length, asmBytes);
		StringBuilder byteSb = new StringBuilder();
		for (int i = 0; i < count; i++) {
		byteSb.append(String.format("%02x", bytes[i] & 0xFF));
		if (i < count - 1) {
			byteSb.append(" ");
		}
		}
		int padLength = bytesFieldWidth - byteSb.length();
		for (int i = 0; i < padLength; i++) {
		byteSb.append(" ");
		}
		sb.append(byteSb.toString());
		sb.append("  ");
	}
	// Add disassembly
	sb.append(instr.disasm);
	// Add comment if present
	if (instr.comment != null && !instr.comment.isEmpty()) {
		sb.append(" ; ").append(instr.comment);
	}
	sb.append("\n");
	}
	return sb.toString();
}

/** Format disassembled instructions as JSON */
private String formatPdJson(List<DisassembledInstruction> instructions) {
	JSONArray array = new JSONArray();

	for (DisassembledInstruction instr : instructions) {
	JSONObject obj = new JSONObject();
	obj.put("addr", instr.address);
	obj.put("size", instr.size);
	obj.put("disasm", instr.disasm);
	obj.put("bytes", bytesToHex(instr.bytes));
	if (instr.label != null) {
		obj.put("label", instr.label);
	}
	array.put(obj);
	}

	return array.toString() + "\n";
}

/** Convert bytes to a hex string */
private String bytesToHex(byte[] bytes) {
	StringBuilder sb = new StringBuilder();
	for (byte b : bytes) {
	sb.append(String.format("%02x", b & 0xFF));
	}
	return sb.toString();
}

/** Execute the px command to display a classic hexdump */
private String executePxCommand(R2Command command, R2Context context) throws R2CommandException {
	// Parse the count argument using RNum (default to blockSize)
	int count;
	try {
	String countArg = command.getFirstArgument(Integer.toString(context.getBlockSize()));
	long numValue = R2NumUtil.evaluateExpression(context, countArg);
	count = (int) numValue;
	if (count <= 0) {
		throw new R2CommandException("Invalid byte count: " + count);
	}
	} catch (R2NumException e) {
	throw new R2CommandException("Invalid count expression: " + e.getMessage());
	}
	// Get the base address
	Address baseAddr = context.getCurrentAddress();
	if (baseAddr == null) {
	throw new R2CommandException("Current address is not set");
	}
	try {
	byte[] bytes = context.getAPI().getBytes(baseAddr, count);
	if (command.hasSuffix('j')) {
		return formatPxJson(bytes, baseAddr, context);
	}
	return formatPxText(bytes, baseAddr, context);
	} catch (Exception e) {
	throw new R2CommandException("Error reading memory: " + e.getMessage());
	}
}

/** Execute the pxf command to display a hexdump using function size */
private String executePxfCommand(R2Command command, R2Context context) throws R2CommandException {
	// Get the current address
	Address baseAddr = context.getCurrentAddress();
	if (baseAddr == null) {
	throw new R2CommandException("Current address is not set");
	}

	try {
	// Get the function at the current address
	Function function = context.getAPI().getFunctionContaining(baseAddr);
	if (function == null) {
		throw new R2CommandException("No function at the current address");
	}

	// Get the function size
	int functionSize = (int) function.getBody().getNumAddresses();

	// Read bytes from memory using function size
	byte[] bytes = context.getAPI().getBytes(baseAddr, functionSize);

	if (command.hasSuffix('j')) {
		return formatPxJson(bytes, baseAddr, context);
	}
	return formatPxText(bytes, baseAddr, context);
	} catch (Exception e) {
	throw new R2CommandException("Error reading function memory: " + e.getMessage());
	}
}

/** Format hexdump as text with address, hex bytes, and ASCII */
private String formatPxText(byte[] bytes, Address baseAddr, R2Context context) {
	StringBuilder sb = new StringBuilder();
	int lineSize = 16;
	for (int offset = 0; offset < bytes.length; offset += lineSize) {
	long addrOffset = baseAddr.getOffset() + offset;
	sb.append(String.format("0x%08x  ", addrOffset));
	int end = Math.min(offset + lineSize, bytes.length);
	// Hex bytes
	for (int i = offset; i < offset + lineSize; i++) {
		if (i < end) {
		sb.append(String.format("%02x ", bytes[i] & 0xFF));
		} else {
		sb.append("   ");
		}
	}
	sb.append(" ");
	// ASCII representation
	sb.append("|");
	for (int i = offset; i < offset + lineSize; i++) {
		if (i < end) {
		int b = bytes[i] & 0xFF;
		char c = (b >= 32 && b < 127) ? (char) b : '.';
		sb.append(c);
		} else {
		sb.append(' ');
		}
	}
	sb.append("|");
	sb.append("\n");
	}
	return sb.toString();
}

/** Execute the pdg command to disassemble using function size */
private String executePdgCommand(R2Command command, R2Context context) throws R2CommandException {
	// Get the current address
	Address address = context.getCurrentAddress();
	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	try {
	// Get the function at the current address
	Function function = context.getAPI().getFunctionContaining(address);
	if (function == null) {
		throw new R2CommandException("No function at the current address");
	}

	// Check if command has a radare2 command suffix
	char rad = command.hasSuffix('*') ? '*' : ' ';

	// Decompile the function
	return decompileFunction(function, rad);
	} catch (Exception e) {
	throw new R2CommandException("Error decompiling function: " + e.getMessage());
	}
}

/** Execute the pdf command to disassemble using function size */
private String executePdfCommand(R2Command command, R2Context context) throws R2CommandException {
	// Get the current address
	Address address = context.getCurrentAddress();
	if (address == null) {
	throw new R2CommandException("Current address is not set");
	}

	try {
	// Get the function at the current address
	Function function = context.getAPI().getFunctionContaining(address);
	if (function == null) {
		throw new R2CommandException("No function at the current address");
	}

	// Get the listing
	Listing listing = context.getAPI().getCurrentProgram().getListing();
	SymbolTable symbolTable = context.getAPI().getCurrentProgram().getSymbolTable();

	// Get instructions in the function
	List<DisassembledInstruction> instructions = new ArrayList<>();
	Address currentAddr = function.getEntryPoint();
	Address maxFunctionAddr = function.getBody().getMaxAddress();

	// Number of bytes to display per instruction (0 to disable bytes)
	int asmBytes = context.getEvalConfig().getInt("asm.bytes");

	while (currentAddr != null && currentAddr.compareTo(maxFunctionAddr) <= 0) {
		Instruction instr = listing.getInstructionAt(currentAddr);
		if (instr == null) {
		// No more instructions
		break;
		}

		// Get symbol at this address
		Symbol[] symbols = symbolTable.getSymbols(currentAddr);
		String label = null;
		if (symbols.length > 0) {
		for (Symbol sym : symbols) {
			// Prefer function symbols
			if (sym.getSymbolType() == SymbolType.FUNCTION) {
			label = sym.getName();
			break;
			}
		}
		if (label == null) {
			// If no function symbol, use the first one
			label = symbols[0].getName();
		}
		}

		// Get instruction bytes
		byte[] bytes = instr.getBytes();

		// Get instruction text
		String disasm = instr.toString();

		// Apply case formatting based on asm.ucase setting
		boolean useUppercase = context.getEvalConfig().getBoolean("asm.ucase");
		if (!useUppercase) {
		disasm = disasm.toLowerCase();
		}

		// Create disassembled instruction
		DisassembledInstruction disasmInstr = new DisassembledInstruction();
		disasmInstr.address = currentAddr.getOffset();
		disasmInstr.size = instr.getLength();
		disasmInstr.bytes = bytes;
		disasmInstr.disasm = disasm;
		disasmInstr.label = label;
		// Capture end-of-line comment if present
		disasmInstr.comment = instr.getComment(CodeUnit.EOL_COMMENT);

		instructions.add(disasmInstr);

		// Move to next instruction
		currentAddr = instr.getMaxAddress().next();
	}

	// Format output based on suffix
	if (command.hasSuffix('j')) {
		return formatPdJson(instructions);
	} else {
		return formatPdText(instructions, asmBytes);
	}
	} catch (Exception e) {
	throw new R2CommandException("Error disassembling function: " + e.getMessage());
	}
}

/** Format hexdump as JSON array of objects with address, bytes, and ascii */
private String formatPxJson(byte[] bytes, Address baseAddr, R2Context context) {
	JSONArray array = new JSONArray();
	int lineSize = 16;
	for (int offset = 0; offset < bytes.length; offset += lineSize) {
	long addrOffset = baseAddr.getOffset() + offset;
	JSONObject obj = new JSONObject();
	obj.put("addr", addrOffset);
	JSONArray data = new JSONArray();
	int end = Math.min(offset + lineSize, bytes.length);
	StringBuilder ascii = new StringBuilder();
	for (int i = offset; i < end; i++) {
		data.put(bytes[i] & 0xFF);
		int b = bytes[i] & 0xFF;
		char c = (b >= 32 && b < 127) ? (char) b : '.';
		ascii.append(c);
	}
	obj.put("bytes", data);
	obj.put("ascii", ascii.toString());
	array.put(obj);
	}
	return array.toString() + "\n";
}

/** Class to hold disassembled instruction data */
private static class DisassembledInstruction {
	long address;
	int size;
	byte[] bytes;
	String disasm;
	String label;
	String comment;
}

/** Decompile a function and format the output */
private String decompileFunction(Function function, char rad) throws Exception {
	StringBuffer sb = new StringBuffer();

	// Create decompiler interface
	DecompInterface di = new DecompInterface();
	di.openProgram(function.getProgram());

	// Decompile with a 5-seconds timeout
	DecompileResults dr = di.decompileFunction(function, 5, null);

	if (!dr.decompileCompleted()) {
	throw new Exception("Decompilation failed: " + dr.getErrorMessage());
	}

	// Format the decompiled code
	PrettyPrinter pp =
		new PrettyPrinter(function, dr.getCCodeMarkup(), new IdentityNameTransformer());
	ArrayList<ClangLine> lines = new ArrayList<>(pp.getLines());

	// Process each line
	for (ClangLine line : lines) {
	long minAddress = Long.MAX_VALUE;
	long maxAddress = 0;

	// Find min and max addresses in this line
	for (int i = 0; i < line.getNumTokens(); i++) {
		if (line.getToken(i).getMinAddress() == null) {
		continue;
		}
		long addr = line.getToken(i).getMinAddress().getOffset();
		minAddress = addr < minAddress ? addr : minAddress;
		maxAddress = addr > maxAddress ? addr : maxAddress;
	}

	// Process the code line
	String codeline = line.toString();
	int colon = codeline.indexOf(':');
	if (colon != -1) {
		codeline = codeline.substring(colon + 1);
		codeline = line.getIndentString() + codeline;
	}

	// Format output based on command type
	if (rad == '*') {
		String b64comment = Base64.getEncoder().encodeToString(codeline.getBytes());
		sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
	} else {
		if (maxAddress == 0) {
		String msg = String.format("           %s\n", codeline);
		sb.append(msg);
		} else {
		String msg = String.format("0x%08x %s\n", minAddress, codeline);
		sb.append(msg);
		}
	}
	}

	return sb.toString();
}

@Override
public String getHelp() {
	StringBuilder help = new StringBuilder();
	help.append("Usage: p[8|d|x][f|j] [count]\n");
	help.append(" p8 [len]     print hexadecimal bytes\n");
	help.append(" p8j [len]    print hexadecimal bytes as json array\n");
	help.append(" p8f          print hexadecimal bytes for current function\n");
	help.append(" p8fj         print hexadecimal bytes for current function as json\n");
	help.append(" px [len]     print hexdump (addr bytes ascii)\n");
	help.append(" pxj [len]    print hexdump as json array\n");
	help.append(" pxf          print hexdump of current function\n");
	help.append(" pxfj         print hexdump of current function as json\n");
	help.append(" pd [n]       print disassembly with n instructions\n");
	help.append(" pdj [n]      print disassembly as json\n");
	help.append(" pdf          print disassembly of current function\n");
	help.append(" pdfj         print disassembly of current function as json\n");
	help.append(" pdg          print decompiled C-like code of current function\n");
	help.append(" pdg*         print decompiled code for importing comments in radare2\n");
	help.append("\nExamples:\n");
	help.append(" p8 16        print 16 bytes in hex\n");
	help.append(" p8 0x10      print 16 bytes in hex (using hex number)\n");
	help.append(" p8j 4        print 4 bytes as json array\n");
	help.append(" px           print hexdump using default block size\n");
	help.append(" px 32        print 32 bytes hexdump\n");
	help.append(" pxj 16       print 16 bytes hexdump as json\n");
	help.append(" pd           print 10 disassembled instructions\n");
	help.append(" pd 20        print 20 disassembled instructions\n");
	help.append(" pdj 5        print 5 disassembled instructions as json\n");
	help.append(" pdf          print disassembly of current function\n");
	return help.toString();
}
}

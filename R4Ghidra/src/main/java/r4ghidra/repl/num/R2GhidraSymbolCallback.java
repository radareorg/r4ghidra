package r4ghidra.repl.num;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.List;
import r4ghidra.repl.R2Context;

/**
 * Ghidra implementation of R2NumCallback interface for symbol resolution.
 *
 * <p>This class uses the Ghidra API to resolve symbol names to their addresses for use in R2Num
 * expressions.
 */
public class R2GhidraSymbolCallback implements R2NumCallback {
private R2Context context;

/**
* Create a new Ghidra symbol resolver with the specified context
*
* @param context The R2Context to use for symbol resolution
*/
public R2GhidraSymbolCallback(R2Context context) {
	this.context = context;
}

/** Resolve a symbol name to its address value using Ghidra API */
@Override
public Long resolveSymbol(String name) {
	if (context.getAPI() == null) {
	return null;
	}

	// Check if the name is a variable defined in the R2Context
	if (context.hasVariable(name)) {
	String value = context.getVariable(name);
	try {
		// Try to parse the variable as a number
		if (value.toLowerCase().startsWith("0x")) {
		return Long.parseLong(value.substring(2), 16);
		} else {
		return Long.parseLong(value);
		}
	} catch (NumberFormatException e) {
		// Not a number, try to resolve as a symbol recursively
		return resolveSymbol(value);
	}
	}

	try {
	// Try to resolve as a function name
	List<Function> functions = context.getAPI().getGlobalFunctions(name);
	if (!functions.isEmpty()) {
		return functions.get(0).getEntryPoint().getUnsignedOffset();
	}

	// Try to resolve as a symbol
	SymbolTable symbolTable = context.getAPI().getCurrentProgram().getSymbolTable();
	java.util.ArrayList<Symbol> symbols = new java.util.ArrayList<>();

	// Convert SymbolIterator to List<Symbol>
	symbolTable.getSymbols(name).forEach(symbols::add);

	if (!symbols.isEmpty()) {
		// Return the first matching symbol's address
		Address symbolAddr = symbols.get(0).getAddress();
		return symbolAddr.getUnsignedOffset();
	}

	// If it starts with 0x, try to parse as a hex number
	if (name.toLowerCase().startsWith("0x")) {
		return Long.parseLong(name.substring(2), 16);
	}

	// Not found
	return null;

	} catch (Exception e) {
	// Error during resolution
	return null;
	}
}
}

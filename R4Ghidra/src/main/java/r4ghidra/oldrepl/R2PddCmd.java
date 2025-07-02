package r4ghidra;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
// import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.IdentityNameTransformer;
import java.util.ArrayList;
import java.util.Base64;

public class R2PddCmd extends R2CmdHandler {

public R2PddCmd(int i) {
	cmdPos = i;
}

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'd') return true;
	return false;
}

private String decompile(Function f, char rad) throws Exception {
	StringBuffer sb = new StringBuffer();

	// Stop after this headless script
	// setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);

	DecompInterface di = new DecompInterface();

	// TODO implement println
	// println("Simplification style: " + di.getSimplificationStyle()); // DEBUG
	// println("Debug enables: " + di.debugEnabled());

	// println(String.format("Decompiling %s() at 0x%s", f.getName(),
	// f.getEntryPoint().toString()));

	// println("Program: " + di.openProgram(f.getProgram())); // DEBUG
	di.openProgram(f.getProgram());
	// Decompile with a 5-seconds timeout
	DecompileResults dr = di.decompileFunction(f, 5, null);
	// println("Decompilation completed: " + dr.decompileCompleted()); // DEBUG

	// DecompiledFunction df = dr.getDecompiledFunction();
	// println(df.getC());

	// Print lines prepend with addresses
	PrettyPrinter pp = new PrettyPrinter(f, dr.getCCodeMarkup(), new IdentityNameTransformer());
	ArrayList<ClangLine> lines = new ArrayList<ClangLine>(pp.getLines());

	for (ClangLine line : lines) {
	long minAddress = Long.MAX_VALUE;
	long maxAddress = 0;
	for (int i = 0; i < line.getNumTokens(); i++) {
		if (line.getToken(i).getMinAddress() == null) {
		continue;
		}
		long addr = line.getToken(i).getMinAddress().getOffset();
		minAddress = addr < minAddress ? addr : minAddress;
		maxAddress = addr > maxAddress ? addr : maxAddress;
	}
	String codeline = line.toString();
	int colon = codeline.indexOf(':');
	if (colon != -1) {
		codeline = codeline.substring(colon + 1);
		codeline = line.getIndentString() + codeline;
	}
	if (rad == '*') {
		String b64comment = Base64.getEncoder().encodeToString(codeline.getBytes());
		sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, minAddress));
	} else {
		if (maxAddress == 0) {
		String msg = String.format("           %s\n", codeline);
		sb.append(msg);
		} else {
		String msg = hexAddress(minAddress) + " " + codeline + "\n";
		sb.append(msg);
		}
	}
	}
	return sb.toString();
}

@Override
public String handle(String cmd) {
	char rad = (cmd.indexOf("*") != -1) ? '*' : ' '; // TODO check r2 syntax

	try {
	Function f = R4GhidraState.api.getFunctionContaining(R4GhidraState.r2Seek);
	return decompile(f, rad);
	} catch (MemoryAccessException mae) {
	return "No function at address";
	} catch (Exception e) {
	return e.toString() + "\n";
	}
}
}

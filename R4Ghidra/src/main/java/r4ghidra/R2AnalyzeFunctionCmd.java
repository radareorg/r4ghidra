package r4ghidra;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;

public class R2AnalyzeFunctionCmd extends R2CmdHandler {
	List<R2CmdHandler> handlers;

	public R2AnalyzeFunctionCmd() {
		this(0);
	}

	public R2AnalyzeFunctionCmd(int pos) {
		cmdPos = pos;
		handlers = Arrays.asList(
				new R2AnalyzeFunctionDummyCmd(cmdPos + 1), 
				new R2AnalyzeFunctionList(cmdPos + 1)
			);
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == 'f')
			return true;
		return false;
	}

	private String cmdAf(String arg) {
		char rad = (arg.indexOf("*") != -1) ? '*' : ' ';
		// Function f = ghidra.getFunctionAt(ghidra.currentAddress);
		FlatProgramAPI ghidra = R4GhidraState.api;
		Address currentAddress = R4GhidraState.r2Seek;
		Function f = ghidra.getFunctionContaining(currentAddress);
		if (f == null) {
			return "Cannot find function at " + currentAddress + "\n";
		}
		try {
			Variable[] vars = f.getAllVariables();
			String comment = f.getComment();
			StringBuffer sb = new StringBuffer();
			Address addr = f.getEntryPoint();
			if (comment != null) {
				String b64comment = Base64.getEncoder().encodeToString(comment.getBytes());
				sb.append(String.format("CCu base64:%s @ 0x%x\n", b64comment, addr));
			}
			sb.append("?e Done\n");
			return sb.toString();
		} catch (Exception e) {
			return e.toString() + "\n";
		}
	}

	@Override
	public String handle(String cmd) {
		// TODO Auto-generated method stub
		if (cmd.length() == 2) {
			Address addr = R4GhidraState.r2Seek;
			R4GhidraState.api.disassemble(addr);
			R4GhidraState.api.createFunction(addr, "ghidra." + addr.toString());
			return cmdAf(cmd);

		}
		for (R2CmdHandler h : handlers) {
			if (h.canHandle(cmd)) {
				return h.handle(cmd);
			}
		}
		return "Analyze Function command not found!";
	}

}

package r4ghidra;

import ghidra.program.model.address.Address;

public class R2StringSearchCmd extends R2CmdHandler {

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == '/') return true;
	return false;
}

@Override
public String handle(String cmd) {
	if (cmd.length() > 1) {
	switch (cmd.charAt(1)) {
		case ' ':
		// TODO decode \xNN
		Address[] res = R4GhidraState.api.findBytes(R4GhidraState.r2Seek, cmd.substring(2), 9999);
		StringBuilder out = new StringBuilder("");
		for (Address a : res) {
			out.append(a.toString() + "\n");
		}
		return out.toString();
		case 'x':
		return "Usage: / \\xAA\\xBB instead";
	}
	}
	return "Usage: '/ string' or '/x [hex]'";
}
}

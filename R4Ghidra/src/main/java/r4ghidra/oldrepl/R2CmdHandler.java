package r4ghidra.oldrepl;

import ghidra.program.model.address.Address;
import r4ghidra.R4GhidraState;

public abstract class R2CmdHandler {
protected int cmdPos = 0;

public abstract boolean canHandle(char cmdChar);

public abstract String handle(String cmd);

public boolean canHandle(String cmd) {
	return canHandle(cmd.charAt(cmdPos));
}

protected static String hexAddress(Address addr) {
	return "0x" + String.format("%1$08x", addr.getUnsignedOffset());
}

protected static String hexAddress(Long addr) {
	return "0x" + String.format("%1$08x", addr);
}

public static Address atAddress(String cmd) {
	String[] parts = cmd.split("@");
	if (parts.length < 2) return R4GhidraState.r2Seek;
	String addrString = parts[1].trim();
	R4GhidraState.r2Seek = R4GhidraState.api.toAddr(addrString);
	return R4GhidraState.r2Seek;
}
}

package r4ghidra;

public class R2SeekCmd extends R2CmdHandler {

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 's') return true;
	return false;
}

@Override
public String handle(String cmd) {

	String[] parts = cmd.split(" ");
	if (parts.length > 1) {
	R4GhidraState.r2Seek = R4GhidraState.api.toAddr(parts[1]);
	}

	return hexAddress(R4GhidraState.r2Seek) + "\n";
}
}

package r4ghidra;

public class R2FlagCmd extends R2CmdHandler {

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'f') return true;
	return false;
}

@Override
public String handle(String cmd) {
	String[] parts = cmd.split(" ");
	if (parts.length > 1) {
	try {
		R4GhidraState.api.start(); // Start transaction
		R4GhidraState.api.createLabel(R4GhidraState.r2Seek, parts[1], false);
		R4GhidraState.api.end(true); // Commit transaction
	} catch (Exception e) {
		R4GhidraState.api.end(false);
		return e.getMessage();
	}
	}

	return "";
}
}

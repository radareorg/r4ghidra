package r4ghidra;

public class R2CreateDwordCmd extends R2CmdHandler {
public R2CreateDwordCmd() {
	this(0);
}

public R2CreateDwordCmd(int pos) {
	cmdPos = pos;
}

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'd') return true;
	return false;
}

@Override
public String handle(String cmd) {
	try {
	R4GhidraState.api.start();
	R4GhidraState.api.createWord(R4GhidraState.r2Seek);
	R4GhidraState.api.end(true);
	return "";
	} catch (Exception e) {
	R4GhidraState.api.end(false);
	return e.getMessage();
	}
}
}

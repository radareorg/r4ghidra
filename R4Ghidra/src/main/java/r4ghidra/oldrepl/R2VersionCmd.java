package r4ghidra;

import ghidra.framework.Application;

public class R2VersionCmd extends R2CmdHandler {

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'V') return true;
	return false;
}

@Override
public String handle(String cmd) {
	return Application.getApplicationVersion();
}
}

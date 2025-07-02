package r4ghidra;

import java.util.Arrays;
import java.util.List;

public class R2AnalyzeCmd extends R2CmdHandler {
List<R2CmdHandler> handlers;

// We can't inherit constructors and handlers must be initialized after cmdPos is set!
public R2AnalyzeCmd() {
	this(0);
}

public R2AnalyzeCmd(int pos) {
	cmdPos = pos;
	handlers = Arrays.asList(new R2AnalyzeAllCmd(cmdPos + 1), new R2AnalyzeFunctionCmd(cmdPos + 1));
}

@Override
public boolean canHandle(char cmdChar) {
	if (cmdChar == 'a') return true;
	return false;
}

@Override
public String handle(String cmd) {
	for (R2CmdHandler h : handlers) {
	if (h.canHandle(cmd)) {
		return h.handle(cmd);
	}
	}
	return "";
}
}
